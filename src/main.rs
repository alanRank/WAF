mod api;
mod core;
mod runtime;

use crate::api::admin::{ensure_default_admin_user, run_admin_api, AdminApiState};
use crate::core::{
    analyzer::Analyzer,
    config::{load_shared_state, resolve_app_files},
    db::Database,
    logger::AttackLogger,
    models::{AccessListType, AnalysisRequest, NewIpAccessEntry},
};
use crate::runtime::proxy::run_interceptor;
use anyhow::{Context, Result};
use rustls::crypto::ring::default_provider;
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    install_rustls_crypto_provider()?;

    let files = resolve_app_files()?;
    ensure_runtime_directories_exist(&files)?;

    info!(
        config_dir = %files.config_dir.display(),
        db_dir = %files.db_dir.display(),
        "resolved runtime directories"
    );

    let database = Database::connect(&files.db_path).await?;
    database.initialize().await?;
    let attack_logger = AttackLogger::start(database.clone());

    let state = load_shared_state(&files)?;
    ensure_default_admin_user(&database).await?;
    seed_demo_ip_data(&database).await?;

    let analyzer = Analyzer::new(database.clone(), state.clone());
    let config = state.config.read().await.clone();
    let rules = state.rules.read().await.clone();
    let security_policies = state.security_policies.read().await.clone();

    info!(
        mode = ?config.mode,
        enabled = config.is_enabled,
        target = %config.target_url,
        admin_port = config.admin_port,
        interceptor_port = config.interceptor_port,
        "configuration loaded"
    );

    info!(
        rules_count = rules.len(),
        endpoint_policies = security_policies.endpoints.len(),
        db_path = %files.db_path.display(),
        "WAF bootstrap completed"
    );

    let sample_decision = analyzer
        .analyze(&AnalysisRequest {
            source_ip: "203.0.113.10".to_string(),
            method: "GET".to_string(),
            path: "/rest/products/search".to_string(),
            query: Some("q=' union select password from users".to_string()),
            headers: BTreeMap::from([
                ("User-Agent".to_string(), "curl/8.0".to_string()),
                ("Authorization".to_string(), "Bearer demo".to_string()),
                ("Content-Type".to_string(), "application/json".to_string()),
            ]),
            body: None,
        })
        .await?;

    info!(
        action = ?sample_decision.action,
        reason = ?sample_decision.reason,
        matched_rule_id = ?sample_decision.matched_rule_id,
        message = %sample_decision.message,
        "sample analyzer execution completed"
    );

    let interceptor_config = Arc::new(config.clone());
    let admin_state = AdminApiState {
        db: database.clone(),
        shared_state: state.clone(),
        files: files.clone(),
        jwt_secret: Arc::new("dev-secret-change-me".to_string()),
    };

    let interceptor = run_interceptor(interceptor_config, state.clone(), analyzer, attack_logger);
    let admin_api = run_admin_api(admin_state);

    tokio::try_join!(interceptor, admin_api)?;

    Ok(())
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn ensure_runtime_directories_exist(files: &crate::core::config::AppFiles) -> Result<()> {
    std::fs::create_dir_all(&files.config_dir).with_context(|| {
        format!(
            "failed to create or access config directory '{}'",
            files.config_dir.display()
        )
    })?;

    std::fs::create_dir_all(&files.db_dir).with_context(|| {
        format!(
            "failed to create or access database directory '{}'",
            files.db_dir.display()
        )
    })?;

    Ok(())
}

async fn seed_demo_ip_data(database: &Database) -> Result<()> {
    database
        .upsert_ip_access_entry(&NewIpAccessEntry {
            ip_address: "198.51.100.10".to_string(),
            list_type: AccessListType::Black,
            comment: Some("demo blacklisted IP for analyzer verification".to_string()),
            expires_at: None,
        })
        .await?;

    Ok(())
}

fn install_rustls_crypto_provider() -> Result<()> {
    default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install Rustls crypto provider"))?;

    Ok(())
}
