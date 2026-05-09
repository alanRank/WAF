use crate::{
    core::{
        config::SharedState,
        db::Database,
        models::{
            AnalysisDecision, AnalysisRequest, CompiledRule, DecisionAction, DecisionReason,
            EndpointPolicy, NormalizedRequest, SecurityPolicies, WafMode,
        },
    },
};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone)]
pub struct Analyzer {
    db: Database,
    state: SharedState,
}

impl Analyzer {
    pub fn new(db: Database, state: SharedState) -> Self {
        Self { db, state }
    }

    pub async fn analyze(&self, request: &AnalysisRequest) -> Result<AnalysisDecision> {
        let config = self.state.config.read().await.clone();
        if !config.is_enabled {
            return Ok(AnalysisDecision {
                action: DecisionAction::Allow,
                reason: DecisionReason::WafDisabled,
                matched_rule_id: None,
                message: "WAF is disabled; request allowed".to_string(),
            });
        }

        if let Some(ip_decision) = self.check_ip_access(request).await? {
            return Ok(ip_decision);
        }

        if let Some(policy_decision) = self.check_security_policies(request).await? {
            return Ok(self.apply_mode(policy_decision, &config.mode));
        }

        if let Some(signature_decision) = self.check_signatures(request).await? {
            return Ok(self.apply_mode(signature_decision, &config.mode));
        }

        Ok(AnalysisDecision {
            action: DecisionAction::Allow,
            reason: DecisionReason::Passed,
            matched_rule_id: None,
            message: "request passed all analyzer stages".to_string(),
        })
    }

    async fn check_ip_access(&self, request: &AnalysisRequest) -> Result<Option<AnalysisDecision>> {
        if let Some(entry) = self.db.get_ip_access_entry(&request.source_ip).await? {
            match entry.list_type.as_str() {
                "black" => {
                    return Ok(Some(AnalysisDecision {
                        action: DecisionAction::Block,
                        reason: DecisionReason::IpBlacklist,
                        matched_rule_id: None,
                        message: format!("source IP '{}' is blacklisted", request.source_ip),
                    }));
                }
                "white" => {
                    return Ok(Some(AnalysisDecision {
                        action: DecisionAction::Allow,
                        reason: DecisionReason::IpWhitelist,
                        matched_rule_id: None,
                        message: format!("source IP '{}' is explicitly whitelisted", request.source_ip),
                    }));
                }
                _ => {}
            }
        }

        Ok(None)
    }

    async fn check_security_policies(
        &self,
        request: &AnalysisRequest,
    ) -> Result<Option<AnalysisDecision>> {
        let policies = self.state.security_policies.read().await.clone();
        let normalized_method = normalize_method(&request.method);
        let normalized_headers = normalize_headers(&request.headers);
        let endpoint_policy = match find_endpoint_policy(&policies, &request.path) {
            Some(policy) => policy,
            None => return Ok(None),
        };

        let effective_methods = if endpoint_policy.allowed_methods.is_empty() {
            policies.global_defaults.allowed_methods.clone()
        } else {
            endpoint_policy.allowed_methods.clone()
        };

        let mut effective_allowed_headers = policies.global_defaults.allowed_headers.clone();
        effective_allowed_headers.extend(endpoint_policy.allowed_headers.clone());

        let effective_max_body_size_kb = endpoint_policy
            .max_body_size_kb
            .unwrap_or(policies.global_defaults.max_body_size_kb);

        if !effective_methods
            .iter()
            .map(|method| normalize_method(method))
            .any(|method| method == normalized_method)
        {
            return Ok(Some(AnalysisDecision {
                action: DecisionAction::Block,
                reason: DecisionReason::MethodNotAllowed,
                matched_rule_id: None,
                message: format!(
                    "HTTP method '{}' is not allowed for path '{}'",
                    normalized_method, request.path
                ),
            }));
        }

        let allowed_headers: HashSet<String> = effective_allowed_headers
            .iter()
            .map(|header| normalize_header_name(header))
            .collect();

        for mandatory in &endpoint_policy.mandatory_headers {
            let mandatory = normalize_header_name(mandatory);
            if !normalized_headers.contains_key(&mandatory) {
                return Ok(Some(AnalysisDecision {
                    action: DecisionAction::Block,
                    reason: DecisionReason::MissingMandatoryHeader,
                    matched_rule_id: None,
                    message: format!(
                        "mandatory header '{}' is missing for path '{}'",
                        mandatory, request.path
                    ),
                }));
            }
        }

        for header_name in normalized_headers.keys() {
            if is_implicit_allowed_header(header_name) {
                continue;
            }

            if !allowed_headers.contains(header_name) {
                return Ok(Some(AnalysisDecision {
                    action: DecisionAction::Block,
                    reason: DecisionReason::HeaderNotAllowed,
                    matched_rule_id: None,
                    message: format!(
                        "header '{}' is not allowed for path '{}'",
                        header_name, request.path
                    ),
                }));
            }
        }

        let body_size_bytes = request.body.as_ref().map_or(0, |body| body.as_bytes().len());
        if body_size_bytes > (effective_max_body_size_kb as usize * 1024) {
            return Ok(Some(AnalysisDecision {
                action: DecisionAction::Block,
                reason: DecisionReason::BodyTooLarge,
                matched_rule_id: None,
                message: format!(
                    "request body size '{}' exceeds '{}' KB for path '{}'",
                    body_size_bytes, effective_max_body_size_kb, request.path
                ),
            }));
        }

        if let Some(max_params) = endpoint_policy.max_params {
            let params_count = count_query_params(request.query.as_deref());
            if params_count > max_params as usize {
                return Ok(Some(AnalysisDecision {
                    action: DecisionAction::Block,
                    reason: DecisionReason::TooManyParams,
                    matched_rule_id: None,
                    message: format!(
                        "query parameter count '{}' exceeds '{}' for path '{}'",
                        params_count, max_params, request.path
                    ),
                }));
            }
        }

        Ok(None)
    }

    async fn check_signatures(&self, request: &AnalysisRequest) -> Result<Option<AnalysisDecision>> {
        let rules = self.state.compiled_rules.read().await.clone();
        let normalized_request = normalize_request(request);

        for rule in rules {
            if let Some(component) = match_rule_against_request(&rule, &normalized_request) {
                return Ok(Some(AnalysisDecision {
                    action: DecisionAction::Block,
                    reason: DecisionReason::SignatureMatch,
                    matched_rule_id: Some(rule.id.clone()),
                    message: format!(
                        "request matched signature '{}: {}' in {}",
                        rule.id, rule.name, component
                    ),
                }));
            }
        }

        Ok(None)
    }

    fn apply_mode(&self, decision: AnalysisDecision, mode: &WafMode) -> AnalysisDecision {
        if decision.action != DecisionAction::Block {
            return decision;
        }

        match mode {
            WafMode::Active => decision,
            WafMode::Passive => AnalysisDecision {
                action: DecisionAction::Log,
                reason: decision.reason,
                matched_rule_id: decision.matched_rule_id,
                message: format!("passive mode: {}", decision.message),
            },
        }
    }
}

fn match_rule_against_request<'a>(
    rule: &'a CompiledRule,
    request: &'a NormalizedRequest,
) -> Option<&'static str> {
    let _severity = &rule.severity;

    if rule.regex.is_match(&request.path) {
        return Some("path");
    }

    if request
        .query
        .as_deref()
        .is_some_and(|query| rule.regex.is_match(query))
    {
        return Some("query");
    }

    for (header_name, header_values) in &request.headers {
        if !should_inspect_header_for_signatures(header_name) {
            continue;
        }

        if rule.regex.is_match(header_name) {
            return Some("header-name");
        }

        if header_values.iter().any(|value| rule.regex.is_match(value)) {
            return Some("header-value");
        }
    }

    if request.body.iter().any(|body| rule.regex.is_match(body)) {
        return Some("body");
    }

    None
}

fn normalize_request(request: &AnalysisRequest) -> NormalizedRequest {
    NormalizedRequest {
        path: normalize_path_or_query(&request.path),
        query: request.query.as_deref().map(normalize_path_or_query),
        headers: normalize_signature_headers(&request.headers),
        body: request
            .body
            .as_deref()
            .map(normalize_body)
            .unwrap_or_default(),
    }
}

fn normalize_path_or_query(input: &str) -> String {
    recursive_url_decode(input, 3).to_ascii_lowercase()
}

fn normalize_signature_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, Vec<String>> {
    headers
        .iter()
        .map(|(name, value)| {
            let normalized_name = normalize_header_name(name);
            let normalized_values = normalize_header_value(&normalized_name, value);
            (normalized_name, normalized_values)
        })
        .collect()
}

fn normalize_header_value(name: &str, value: &str) -> Vec<String> {
    let mut variants = vec![normalize_header_text(value)];

    if should_attempt_base64_decode(name) {
        for candidate in extract_base64_candidates(value) {
            if let Some(decoded) = decode_base64_text(&candidate) {
                variants.push(normalize_header_text(&decoded));
            }
        }
    }

    dedup_non_empty(variants)
}

fn normalize_body(input: &str) -> Vec<String> {
    let url_decoded = recursive_url_decode(input, 3);
    let mut variants = vec![normalize_body_text(&url_decoded)];

    if let Some(decoded) = decode_base64_text(url_decoded.trim()) {
        variants.push(normalize_body_text(&decoded));
    }

    dedup_non_empty(variants)
}

fn normalize_body_text(input: &str) -> String {
    let html_decoded = decode_html_entities(input);
    normalize_text(&html_decoded)
}

fn normalize_header_text(input: &str) -> String {
    normalize_text(input)
}

fn normalize_text(input: &str) -> String {
    collapse_whitespace(&input.to_ascii_lowercase())
}

fn recursive_url_decode(input: &str, max_passes: usize) -> String {
    let mut current = input.to_string();

    for _ in 0..max_passes {
        let decoded = url_decode_once(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }

    current
}

fn url_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (
                    hex_value(bytes[index + 1]),
                    hex_value(bytes[index + 2]),
                ) {
                    output.push((high << 4) | low);
                    index += 3;
                    continue;
                }
                output.push(bytes[index]);
                index += 1;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&output).to_string()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_html_entities(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut index = 0;

    while index < chars.len() {
        if chars[index] == '&' {
            let relative_end = chars[index + 1..].iter().position(|ch| *ch == ';');
            if let Some(relative_end) = relative_end {
                let end = index + 1 + relative_end;
                let entity: String = chars[index + 1..end].iter().collect();
                if let Some(decoded) = decode_single_html_entity(&entity) {
                    output.push(decoded);
                    index = end + 1;
                    continue;
                }
            }
        }

        output.push(chars[index]);
        index += 1;
    }

    output
}

fn decode_single_html_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ if entity.starts_with("#x") || entity.starts_with("#X") => {
            u32::from_str_radix(&entity[2..], 16)
                .ok()
                .and_then(char::from_u32)
        }
        _ if entity.starts_with('#') => entity[1..].parse::<u32>().ok().and_then(char::from_u32),
        _ => None,
    }
}

fn should_attempt_base64_decode(header_name: &str) -> bool {
    matches!(header_name, "authorization")
        || header_name.contains("token")
        || header_name.contains("auth")
        || header_name.contains("secret")
}

fn should_inspect_header_for_signatures(header_name: &str) -> bool {
    matches!(
        header_name,
        "authorization" | "origin" | "referer" | "x-requested-with"
    ) || header_name.starts_with("x-")
}

fn extract_base64_candidates(input: &str) -> Vec<String> {
    let trimmed = input.trim();
    let mut candidates = vec![trimmed.to_string()];

    if let Some(last_token) = trimmed.split_whitespace().last() {
        if last_token != trimmed {
            candidates.push(last_token.to_string());
        }
    }

    dedup_non_empty(candidates)
}

fn decode_base64_text(input: &str) -> Option<String> {
    let candidate = input.trim();
    if !looks_like_base64(candidate) {
        return None;
    }

    let decoded = STANDARD.decode(candidate).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    if text.trim().is_empty() {
        return None;
    }

    Some(text)
}

fn looks_like_base64(input: &str) -> bool {
    let candidate = input.trim();
    candidate.len() >= 8
        && candidate.len() % 4 == 0
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

fn collapse_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn dedup_non_empty(items: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();

    for item in items {
        if item.trim().is_empty() {
            continue;
        }
        if !unique.contains(&item) {
            unique.push(item);
        }
    }

    unique
}

fn find_endpoint_policy<'a>(
    policies: &'a SecurityPolicies,
    path: &str,
) -> Option<&'a EndpointPolicy> {
    policies.endpoints.get(path)
}

fn normalize_method(method: &str) -> String {
    method.trim().to_ascii_uppercase()
}

fn normalize_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(name, value)| (normalize_header_name(name), value.trim().to_string()))
        .collect()
}

fn normalize_header_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn is_implicit_allowed_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "connection"
            | "content-length"
            | "upgrade"
            | "priority"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-extensions"
    )
}

fn count_query_params(query: Option<&str>) -> usize {
    query.map_or(0, |value| {
        value
            .split('&')
            .filter(|pair| !pair.trim().is_empty())
            .count()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        config::{compile_rules, SharedState},
        models::{
            AccessListType, Config, GlobalDefaults, NewIpAccessEntry, Rule, Severity,
        },
    };
    use anyhow::Result;
    use std::{
        collections::HashMap,
        path::PathBuf,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::sync::RwLock;

    fn test_config(mode: WafMode, is_enabled: bool) -> Config {
        Config {
            mode,
            is_enabled,
            target_url: "http://localhost:3000".to_string(),
            admin_port: 8081,
            interceptor_port: 443,
            interceptor_host: "0.0.0.0".to_string(),
            tls_cert_path: "data/certs/test.pem".to_string(),
            tls_key_path: "data/certs/test-key.pem".to_string(),
        }
    }

    fn test_rules() -> Vec<Rule> {
        vec![
            Rule {
                id: "942100".to_string(),
                name: "SQL Injection Attack".to_string(),
                regex: "(?i)(union\\s+select|or\\s+1=1|select)".to_string(),
                severity: Severity::High,
            },
            Rule {
                id: "941220".to_string(),
                name: "XSS Attack".to_string(),
                regex: "(?i)<script|onerror\\s*=".to_string(),
                severity: Severity::High,
            },
        ]
    }

    fn test_policies() -> SecurityPolicies {
        let mut endpoints = HashMap::new();
        endpoints.insert(
            "/strict".to_string(),
            EndpointPolicy {
                allowed_methods: vec!["POST".to_string()],
                allowed_headers: vec!["X-Trace-Id".to_string()],
                mandatory_headers: vec!["Content-Type".to_string()],
                max_body_size_kb: Some(1),
                max_params: Some(2),
                description: Some("strict policy".to_string()),
            },
        );
        endpoints.insert(
            "/defaults".to_string(),
            EndpointPolicy {
                allowed_methods: Vec::new(),
                allowed_headers: vec!["X-Custom".to_string()],
                mandatory_headers: Vec::new(),
                max_body_size_kb: None,
                max_params: None,
                description: Some("uses global defaults".to_string()),
            },
        );

        SecurityPolicies {
            global_defaults: GlobalDefaults {
                allowed_methods: vec!["GET".to_string(), "POST".to_string()],
                allowed_headers: vec![
                    "User-Agent".to_string(),
                    "Content-Type".to_string(),
                    "Accept".to_string(),
                ],
                max_body_size_kb: 8,
            },
            endpoints,
        }
    }

    fn build_request(path: &str) -> AnalysisRequest {
        AnalysisRequest {
            source_ip: "203.0.113.10".to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            query: None,
            headers: BTreeMap::from([
                ("User-Agent".to_string(), "curl/8.0".to_string()),
                ("Accept".to_string(), "application/json".to_string()),
            ]),
            body: None,
        }
    }

    async fn build_analyzer(mode: WafMode, is_enabled: bool) -> Result<(Analyzer, PathBuf)> {
        let db_path = unique_test_db_path();
        let db = Database::connect(&db_path).await?;
        db.initialize().await?;
        let rules = test_rules();
        let compiled_rules = compile_rules(&rules)?;

        let state = SharedState {
            config: Arc::new(RwLock::new(test_config(mode, is_enabled))),
            rules: Arc::new(RwLock::new(rules)),
            compiled_rules: Arc::new(RwLock::new(compiled_rules)),
            security_policies: Arc::new(RwLock::new(test_policies())),
        };

        Ok((Analyzer::new(db, state), db_path))
    }

    fn unique_test_db_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rust-waf-analyzer-test-{}-{}.db",
            std::process::id(),
            nanos
        ))
    }

    fn cleanup_db(path: PathBuf) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn normalize_method_uppercases_and_trims() {
        assert_eq!(normalize_method(" post "), "POST");
    }

    #[test]
    fn normalize_headers_lowercases_names_and_trims_values() {
        let headers = BTreeMap::from([
            (" Content-Type ".to_string(), " application/json ".to_string()),
            ("X-Test".to_string(), " value ".to_string()),
        ]);

        let normalized = normalize_headers(&headers);

        assert_eq!(
            normalized.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(normalized.get("x-test").map(String::as_str), Some("value"));
    }

    #[test]
    fn implicit_allowed_headers_include_transport_headers() {
        assert!(is_implicit_allowed_header("host"));
        assert!(is_implicit_allowed_header("content-length"));
        assert!(!is_implicit_allowed_header("x-custom"));
    }

    #[test]
    fn count_query_params_ignores_empty_segments() {
        assert_eq!(count_query_params(Some("a=1&&b=2&")), 2);
        assert_eq!(count_query_params(None), 0);
    }

    #[test]
    fn recursive_url_decode_unwraps_multiple_layers() {
        assert_eq!(recursive_url_decode("%2527", 3), "'");
    }

    #[test]
    fn decode_html_entities_supports_named_and_numeric_values() {
        assert_eq!(decode_html_entities("S&#69;L&#x45;CT &lt;x&gt;"), "SELECT <x>");
    }

    #[test]
    fn normalize_body_decodes_base64_payloads() {
        let normalized = normalize_body("U0VMRUNU");
        assert!(normalized.iter().any(|value| value.contains("select")));
    }

    #[test]
    fn normalize_request_keeps_components_separate() {
        let request = AnalysisRequest {
            source_ip: "127.0.0.1".to_string(),
            method: "POST".to_string(),
            path: "/REST/%2550roducts".to_string(),
            query: Some("q=%2527%2520UNION%2520SELECT".to_string()),
            headers: BTreeMap::from([("X-Token".to_string(), "U0VMRUNU".to_string())]),
            body: Some("S&#69;L&#x45;CT".to_string()),
        };

        let normalized = normalize_request(&request);

        assert_eq!(normalized.path, "/rest/products");
        assert_eq!(normalized.query.as_deref(), Some("q=' union select"));
        assert!(normalized
            .headers
            .get("x-token")
            .is_some_and(|values| values.iter().any(|value| value.contains("select"))));
        assert!(normalized.body.iter().any(|value| value.contains("select")));
    }

    #[test]
    fn generic_browser_headers_are_not_signature_targets() {
        assert!(!should_inspect_header_for_signatures("user-agent"));
        assert!(!should_inspect_header_for_signatures("accept"));
        assert!(!should_inspect_header_for_signatures("sec-fetch-dest"));
        assert!(!should_inspect_header_for_signatures("cookie"));
        assert!(should_inspect_header_for_signatures("authorization"));
        assert!(should_inspect_header_for_signatures("x-auth-token"));
    }

    #[tokio::test]
    async fn apply_mode_keeps_block_in_active_mode() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let decision = AnalysisDecision {
            action: DecisionAction::Block,
            reason: DecisionReason::SignatureMatch,
            matched_rule_id: Some("942100".to_string()),
            message: "blocked".to_string(),
        };

        let applied = analyzer.apply_mode(decision, &WafMode::Active);

        assert_eq!(applied.action, DecisionAction::Block);
        assert_eq!(applied.reason, DecisionReason::SignatureMatch);
        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn apply_mode_converts_block_to_log_in_passive_mode() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Passive, true).await?;
        let decision = AnalysisDecision {
            action: DecisionAction::Block,
            reason: DecisionReason::SignatureMatch,
            matched_rule_id: Some("942100".to_string()),
            message: "blocked".to_string(),
        };

        let applied = analyzer.apply_mode(decision, &WafMode::Passive);

        assert_eq!(applied.action, DecisionAction::Log);
        assert_eq!(applied.reason, DecisionReason::SignatureMatch);
        assert_eq!(applied.matched_rule_id.as_deref(), Some("942100"));
        assert!(applied.message.starts_with("passive mode:"));
        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_allows_when_waf_is_disabled() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, false).await?;
        let request = build_request("/strict");

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, DecisionReason::WafDisabled);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_blocks_blacklisted_ip() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        analyzer
            .db
            .upsert_ip_access_entry(&NewIpAccessEntry {
                ip_address: "203.0.113.10".to_string(),
                list_type: AccessListType::Black,
                comment: Some("blocked in test".to_string()),
                expires_at: None,
            })
            .await?;

        let request = build_request("/strict");
        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.reason, DecisionReason::IpBlacklist);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_allows_whitelisted_ip_before_other_checks() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        analyzer
            .db
            .upsert_ip_access_entry(&NewIpAccessEntry {
                ip_address: "203.0.113.10".to_string(),
                list_type: AccessListType::White,
                comment: Some("allowed in test".to_string()),
                expires_at: None,
            })
            .await?;

        let mut request = build_request("/strict");
        request.method = "DELETE".to_string();
        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, DecisionReason::IpWhitelist);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_blocks_disallowed_method() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let request = build_request("/strict");

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.reason, DecisionReason::MethodNotAllowed);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_blocks_when_mandatory_header_is_missing() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let mut request = build_request("/strict");
        request.method = "POST".to_string();

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.reason, DecisionReason::MissingMandatoryHeader);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_blocks_unapproved_header() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let mut request = build_request("/strict");
        request.method = "POST".to_string();
        request
            .headers
            .insert("Content-Type".to_string(), "application/json".to_string());
        request
            .headers
            .insert("X-Blocked".to_string(), "1".to_string());

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.reason, DecisionReason::HeaderNotAllowed);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_allows_endpoint_header_extension_over_global_defaults() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let mut request = build_request("/defaults");
        request
            .headers
            .insert("X-Custom".to_string(), "ok".to_string());

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, DecisionReason::Passed);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_blocks_oversized_body() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let mut request = build_request("/strict");
        request.method = "POST".to_string();
        request
            .headers
            .insert("Content-Type".to_string(), "application/json".to_string());
        request
            .headers
            .insert("X-Trace-Id".to_string(), "trace-1".to_string());
        request.body = Some("A".repeat(2048));

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.reason, DecisionReason::BodyTooLarge);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_blocks_when_query_param_limit_is_exceeded() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let mut request = build_request("/strict");
        request.method = "POST".to_string();
        request
            .headers
            .insert("Content-Type".to_string(), "application/json".to_string());
        request
            .headers
            .insert("X-Trace-Id".to_string(), "trace-2".to_string());
        request.query = Some("a=1&b=2&c=3".to_string());

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.reason, DecisionReason::TooManyParams);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_blocks_on_signature_match_in_active_mode() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let mut request = build_request("/no-policy");
        request.query = Some("q=%2527%2520UNION%2520SELECT".to_string());

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.reason, DecisionReason::SignatureMatch);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("942100"));

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_detects_html_entity_obfuscated_payload_in_body() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let mut request = build_request("/no-policy");
        request.body = Some("S&#69;L&#x45;CT".to_string());

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.reason, DecisionReason::SignatureMatch);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("942100"));

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_detects_base64_payload_in_header() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let mut request = build_request("/no-policy");
        request
            .headers
            .insert("X-Auth-Token".to_string(), "U0VMRUNU".to_string());

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Block);
        assert_eq!(decision.reason, DecisionReason::SignatureMatch);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("942100"));

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_converts_signature_block_to_log_in_passive_mode() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Passive, true).await?;
        let mut request = build_request("/no-policy");
        request.body = Some("<script>alert(1)</script>".to_string());

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Log);
        assert_eq!(decision.reason, DecisionReason::SignatureMatch);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("941220"));

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_allows_clean_request() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let request = build_request("/no-policy");

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, DecisionReason::Passed);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_allows_typical_browser_asset_request() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let request = AnalysisRequest {
            source_ip: "172.19.0.1".to_string(),
            method: "GET".to_string(),
            path: "/favicon.ico".to_string(),
            query: None,
            headers: BTreeMap::from([
                ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
                ("Accept".to_string(), "image/avif,image/webp,image/*,*/*;q=0.8".to_string()),
                (
                    "Cookie".to_string(),
                    "continueCode=O3VMEvaDgyX8LvJ4qo7EwW6m29xP0pOGzRkZKY1bB3MNjOVprl5QenrK4a2x"
                        .to_string(),
                ),
                ("Sec-Fetch-Site".to_string(), "same-origin".to_string()),
                ("Sec-Fetch-Mode".to_string(), "no-cors".to_string()),
                ("Sec-Fetch-Dest".to_string(), "image".to_string()),
                ("Upgrade-Insecure-Requests".to_string(), "1".to_string()),
            ]),
            body: None,
        };

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, DecisionReason::Passed);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }

    #[tokio::test]
    async fn analyze_does_not_treat_cookie_key_names_as_xss_event_handlers() -> Result<()> {
        let (analyzer, db_path) = build_analyzer(WafMode::Active, true).await?;
        let request = AnalysisRequest {
            source_ip: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/favicon.ico".to_string(),
            query: None,
            headers: BTreeMap::from([(
                "Cookie".to_string(),
                "continueCode=O3VMEvaDgyX8LvJ4qo7EwW6m29xP0pOGzRkZKY1bB3MNjOVprl5QenrK4a2x"
                    .to_string(),
            )]),
            body: None,
        };

        let decision = analyzer.analyze(&request).await?;

        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.reason, DecisionReason::Passed);

        drop(analyzer);
        cleanup_db(db_path);
        Ok(())
    }
}
