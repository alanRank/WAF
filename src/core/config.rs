use crate::core::models::{Config, Rule, SecurityPolicies};
use anyhow::{Context, Result};
use regex::Regex;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;
use url::Url;

#[derive(Debug, Clone)]
pub struct SharedState {
    pub config: Arc<RwLock<Config>>,
    pub rules: Arc<RwLock<Vec<Rule>>>,
    pub security_policies: Arc<RwLock<SecurityPolicies>>,
}

#[derive(Debug, Clone)]
pub struct AppFiles {
    pub data_dir: PathBuf,
    pub config_path: PathBuf,
    pub rules_path: PathBuf,
    pub security_policies_path: PathBuf,
    pub db_path: PathBuf,
}

impl AppFiles {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();

        Self {
            config_path: data_dir.join("config.json"),
            rules_path: data_dir.join("rules.json"),
            security_policies_path: data_dir.join("sec_policies.json"),
            db_path: data_dir.join("waf.db"),
            data_dir,
        }
    }
}

pub fn load_shared_state(files: &AppFiles) -> Result<SharedState> {
    let config = load_config(&files.config_path)?;
    let rules = load_rules(&files.rules_path)?;
    let security_policies = load_security_policies(&files.security_policies_path)?;

    Ok(SharedState {
        config: Arc::new(RwLock::new(config)),
        rules: Arc::new(RwLock::new(rules)),
        security_policies: Arc::new(RwLock::new(security_policies)),
    })
}

pub fn save_config(path: &Path, config: &Config) -> Result<()> {
    let serialized =
        serde_json::to_string_pretty(config).context("failed to serialize config to JSON")?;
    fs::write(path, serialized)
        .with_context(|| format!("failed to write config file '{}'", path.display()))
}

pub fn save_rules(path: &Path, rules: &[Rule]) -> Result<()> {
    validate_rules(rules)?;
    let serialized =
        serde_json::to_string_pretty(rules).context("failed to serialize rules to JSON")?;
    fs::write(path, serialized)
        .with_context(|| format!("failed to write rules file '{}'", path.display()))
}

pub fn save_security_policies(path: &Path, policies: &SecurityPolicies) -> Result<()> {
    let serialized = serde_json::to_string_pretty(policies)
        .context("failed to serialize security policies to JSON")?;
    fs::write(path, serialized)
        .with_context(|| format!("failed to write security policies file '{}'", path.display()))
}

pub fn load_config(path: &Path) -> Result<Config> {
    let config: Config = read_json_file(path)?;
    validate_config_structure(&config)?;
    Ok(config)
}

pub fn load_rules(path: &Path) -> Result<Vec<Rule>> {
    let rules: Vec<Rule> = read_json_file(path)?;
    validate_rules(&rules)?;
    Ok(rules)
}

pub fn load_security_policies(path: &Path) -> Result<SecurityPolicies> {
    read_json_file(path)
}

fn read_json_file<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read JSON file '{}'", path.display()))?;

    serde_json::from_str(&raw)
        .with_context(|| format!("failed to deserialize JSON file '{}'", path.display()))
}

pub fn load_config_from_value(config: &Config) -> Result<()> {
    validate_config_structure(config)
}

pub fn load_rules_from_value(rules: &[Rule]) -> Result<()> {
    validate_rules(rules)
}

pub fn load_security_policies_from_value(_policies: &SecurityPolicies) -> Result<()> {
    Ok(())
}

fn validate_config_structure(config: &Config) -> Result<()> {
    Url::parse(&config.target_url)
        .with_context(|| format!("target_url '{}' is not a valid URL", config.target_url))?;

    if config.admin_port == config.interceptor_port {
        anyhow::bail!("admin_port and interceptor_port must be different");
    }

    if config.interceptor_host.trim().is_empty() {
        anyhow::bail!("interceptor_host must not be empty");
    }

    if config.tls_cert_path.trim().is_empty() {
        anyhow::bail!("tls_cert_path must not be empty");
    }

    if config.tls_key_path.trim().is_empty() {
        anyhow::bail!("tls_key_path must not be empty");
    }

    Ok(())
}

fn validate_rules(rules: &[Rule]) -> Result<()> {
    if rules.is_empty() {
        anyhow::bail!("rules list must contain at least one rule");
    }

    for rule in rules {
        Regex::new(&rule.regex)
            .with_context(|| format!("invalid regex for rule '{}'", rule.id))?;
    }

    Ok(())
}
