use crate::{
    core::{
        config::SharedState,
        db::Database,
        models::{
            AnalysisDecision, AnalysisRequest, DecisionAction, DecisionReason, EndpointPolicy,
            SecurityPolicies, WafMode,
        },
    },
};
use anyhow::{Context, Result};
use regex::Regex;
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
        let rules = self.state.rules.read().await.clone();
        let inspect_target = build_inspection_target(request);

        for rule in rules {
            let regex = Regex::new(&rule.regex)
                .with_context(|| format!("failed to compile regex for rule '{}'", rule.id))?;

            if regex.is_match(&inspect_target) {
                return Ok(Some(AnalysisDecision {
                    action: DecisionAction::Block,
                    reason: DecisionReason::SignatureMatch,
                    matched_rule_id: Some(rule.id.clone()),
                    message: format!("request matched signature '{}: {}'", rule.id, rule.name),
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

fn build_inspection_target(request: &AnalysisRequest) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        request.method,
        request.path,
        request.query.as_deref().unwrap_or_default(),
        request.body.as_deref().unwrap_or_default()
    )
}
