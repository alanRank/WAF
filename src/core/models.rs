use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    Active,
    Passive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub mode: WafMode,
    pub is_enabled: bool,
    pub target_url: String,
    pub admin_port: u16,
    pub interceptor_port: u16,
    pub interceptor_host: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: i64,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub regex: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicies {
    pub global_defaults: GlobalDefaults,
    pub endpoints: HashMap<String, EndpointPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalDefaults {
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub max_body_size_kb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EndpointPolicy {
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_headers: Vec<String>,
    #[serde(default)]
    pub mandatory_headers: Vec<String>,
    pub max_body_size_kb: Option<u64>,
    pub max_params: Option<u32>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessListType {
    White,
    Black,
}

impl AccessListType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::White => "white",
            Self::Black => "black",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IpAccessEntry {
    pub id: i64,
    pub ip_address: String,
    pub list_type: String,
    pub comment: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
} 
//уже в БД

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewIpAccessEntry {
    pub ip_address: String,
    pub list_type: AccessListType,
    pub comment: Option<String>,
    pub expires_at: Option<String>,
} 
// для добавления через фронт

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateIpAccessEntry {
    pub list_type: AccessListType,
    pub comment: Option<String>,
    pub expires_at: Option<String>,
} 
// для обновлениея через фронт

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AttackLog {
    pub id: i64,
    pub timestamp: String,
    pub source_ip: String,
    pub request_method: Option<String>,
    pub request_url: Option<String>,
    pub matched_rule_id: Option<String>,
    pub attack_type: Option<String>,
    pub payload: Option<String>,
    pub action_taken: String,
} 

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAttackLog {
    pub source_ip: String,
    pub request_method: Option<String>,
    pub request_url: Option<String>,
    pub matched_rule_id: Option<String>,
    pub attack_type: Option<String>,
    pub payload: Option<String>,
    pub action_taken: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    Analyst,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Analyst => "analyst",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSummary {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub source_ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    Allow,
    Block,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReason {
    IpBlacklist,
    IpWhitelist,
    MethodNotAllowed,
    MissingMandatoryHeader,
    HeaderNotAllowed,
    BodyTooLarge,
    TooManyParams,
    SignatureMatch,
    WafDisabled,
    Passed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisDecision {
    pub action: DecisionAction,
    pub reason: DecisionReason,
    pub matched_rule_id: Option<String>,
    pub message: String,
}
