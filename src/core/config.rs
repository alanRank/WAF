use crate::core::models::{Config, Rule, SecurityPolicies};
use anyhow::{Context, Result};
use regex::Regex;
use std::{
    env,
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
    pub config_path: PathBuf,
    pub rules_path: PathBuf,
    pub security_policies_path: PathBuf,
    pub db_path: PathBuf,
    pub config_dir: PathBuf,
    pub db_dir: PathBuf,
}

pub fn load_shared_state(files: &AppFiles) -> Result<SharedState> {
    let mut config = load_config(&files.config_path)?;
    apply_runtime_env_overrides(&mut config)?;
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

pub fn apply_runtime_env_overrides(config: &mut Config) -> Result<()> {
    if let Some(mode) = get_env_value(&["WAF_MODE"])? {
        config.mode = parse_waf_mode(&mode)?;
    }

    if let Some(target_url) = get_env_value(&["TARGET_URL"])? {
        config.target_url = normalize_target_url(&target_url);
    }

    if let Some(admin_port) = get_env_value(&["ADMIN_PORT"])? {
        config.admin_port = parse_port(&admin_port, "ADMIN_PORT")?;
    }

    if let Some(tls_private) = get_env_value(&["TLS_PRIVATE"])? {
        config.tls_key_path = tls_private;
    }

    if let Some(tls_public) = get_env_value(&["TLS_PUBLIC"])? {
        config.tls_cert_path = tls_public;
    }

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

pub fn resolve_app_files() -> Result<AppFiles> {
    if let Some(files) = resolve_explicit_app_files()? {
        return Ok(files);
    }

    let container_config_dir = PathBuf::from("/app/config");
    if has_required_config_files(&container_config_dir) {
        return Ok(AppFiles {
            config_path: container_config_dir.join("config.json"),
            rules_path: container_config_dir.join("rules.json"),
            security_policies_path: container_config_dir.join("sec_policies.json"),
            db_path: PathBuf::from("/var/lib/rust-waf/waf.db"),
            config_dir: container_config_dir,
            db_dir: PathBuf::from("/var/lib/rust-waf"),
        });
    }

    let manifest_candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data");
    if has_required_config_files(&manifest_candidate) {
        return Ok(AppFiles {
            config_path: manifest_candidate.join("config.json"),
            rules_path: manifest_candidate.join("rules.json"),
            security_policies_path: manifest_candidate.join("sec_policies.json"),
            db_path: manifest_candidate.join("waf.db"),
            config_dir: manifest_candidate.clone(),
            db_dir: manifest_candidate,
        });
    }

    let cwd_candidate = PathBuf::from("data");
    if has_required_config_files(&cwd_candidate) {
        let absolute = cwd_candidate
            .canonicalize()
            .with_context(|| format!("failed to canonicalize '{}'", cwd_candidate.display()))?;

        return Ok(AppFiles {
            config_path: absolute.join("config.json"),
            rules_path: absolute.join("rules.json"),
            security_policies_path: absolute.join("sec_policies.json"),
            db_path: absolute.join("waf.db"),
            config_dir: absolute.clone(),
            db_dir: absolute,
        });
    }

    anyhow::bail!(
        "runtime files were not found in explicit env paths, '/app/config', '{}' or '{}'",
        manifest_candidate.display(),
        cwd_candidate.display()
    );
}

fn resolve_explicit_app_files() -> Result<Option<AppFiles>> {
    let config_path = get_env_value(&["WAF_CONFIG_PATH"])?.map(PathBuf::from);
    let rules_path = get_env_value(&["WAF_RULES_PATH"])?.map(PathBuf::from);
    let security_policies_path = get_env_value(&["WAF_SEC_POLICIES_PATH"])?.map(PathBuf::from);
    let db_path = get_env_value(&["WAF_DB_PATH"])?.map(PathBuf::from);

    if config_path.is_none() && rules_path.is_none() && security_policies_path.is_none() && db_path.is_none() {
        return Ok(None);
    }

    let config_path = config_path.unwrap_or_else(|| PathBuf::from("/app/config/config.json"));
    let rules_path = rules_path.unwrap_or_else(|| PathBuf::from("/app/config/rules.json"));
    let security_policies_path =
        security_policies_path.unwrap_or_else(|| PathBuf::from("/app/config/sec_policies.json"));
    let db_path = db_path.unwrap_or_else(|| PathBuf::from("/var/lib/rust-waf/waf.db"));

    Ok(Some(AppFiles {
        config_dir: config_path
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".")),
        db_dir: db_path
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".")),
        config_path,
        rules_path,
        security_policies_path,
        db_path,
    }))
}

fn has_required_config_files(dir: &Path) -> bool {
    dir.join("config.json").is_file()
        && dir.join("rules.json").is_file()
        && dir.join("sec_policies.json").is_file()
}

fn get_env_value(keys: &[&str]) -> Result<Option<String>> {
    for key in keys {
        match env::var(key) {
            Ok(value) if !value.trim().is_empty() => return Ok(Some(value)),
            Ok(_) => return Ok(None),
            Err(env::VarError::NotPresent) => continue,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(anyhow::anyhow!("environment variable '{}' is not valid Unicode", key));
            }
        }
    }

    Ok(None)
}

fn parse_waf_mode(value: &str) -> Result<crate::core::models::WafMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "active" => Ok(crate::core::models::WafMode::Active),
        "passive" => Ok(crate::core::models::WafMode::Passive),
        _ => anyhow::bail!("WAF_MODE must be either 'active' or 'passive'"),
    }
}

fn parse_port(value: &str, env_name: &str) -> Result<u16> {
    value
        .trim()
        .parse::<u16>()
        .with_context(|| format!("environment variable '{}' must be a valid TCP port", env_name))
}

fn normalize_target_url(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    }
}
