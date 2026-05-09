use crate::{
    core::{
        analyzer::Analyzer,
        config::SharedState,
        logger::AttackLogger,
        models::{AnalysisRequest, Config, DecisionAction, NewAttackLog},
    },
};
use anyhow::{Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Request, State},
    http::{
        header::{
            HeaderName, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_SECURITY_POLICY, HOST, SET_COOKIE,
            STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
        },
        HeaderMap, HeaderValue, Response, StatusCode, Uri,
    },
    response::IntoResponse,
    routing::any,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use reqwest::Client;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tracing::{error, info};
use url::Url;

#[derive(Clone)]
pub struct ProxyState {
    client: Client,
    shared_state: SharedState,
    analyzer: Analyzer,
    attack_logger: AttackLogger,
}

impl ProxyState {
    pub fn new(
        _config: &Config,
        shared_state: SharedState,
        analyzer: Analyzer,
        attack_logger: AttackLogger,
    ) -> Result<Self> {
        let client = Client::builder()
            .http2_adaptive_window(true)
            .build()
            .context("failed to build reqwest client for proxy")?;

        Ok(Self {
            client,
            shared_state,
            analyzer,
            attack_logger,
        })
    }
}

pub async fn run_interceptor(
    config: Arc<Config>,
    shared_state: SharedState,
    analyzer: Analyzer,
    attack_logger: AttackLogger,
) -> Result<()> {
    let proxy_state = ProxyState::new(&config, shared_state, analyzer, attack_logger)?;
    let router = Router::new()
        .route("/", any(proxy_handler))
        .route("/*path", any(proxy_handler))
        .with_state(proxy_state);

    let address: SocketAddr = format!("{}:{}", config.interceptor_host, config.interceptor_port)
        .parse()
        .with_context(|| {
            format!(
                "failed to parse interceptor address '{}:{}'",
                config.interceptor_host, config.interceptor_port
            )
        })?;

    let cert_path = resolve_runtime_path(&config.tls_cert_path);
    let key_path = resolve_runtime_path(&config.tls_key_path);

    let tls_config = RustlsConfig::from_pem_file(cert_path.clone(), key_path.clone())
    .await
    .with_context(|| {
        format!(
            "failed to load TLS certificate '{}' and key '{}'",
            cert_path.display(),
            key_path.display()
        )
    })?;

    info!(
        bind = %address,
        target = %config.target_url,
        cert = %cert_path.display(),
        "starting HTTPS interceptor"
    );

    axum_server::bind_rustls(address, tls_config)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("interceptor server terminated unexpectedly")
}

async fn proxy_handler(
    State(state): State<ProxyState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> impl IntoResponse {
    match handle_request(state, remote_addr, request).await {
        Ok(response) => response,
        Err(error) => {
            error!(error = %error, "proxy request failed");
            (
                StatusCode::BAD_GATEWAY,
                "upstream proxy error".to_string(),
            )
                .into_response()
        }
    }
}

async fn handle_request(
    state: ProxyState,
    remote_addr: SocketAddr,
    request: Request,
) -> Result<Response<Body>> {
    let (parts, body) = request.into_parts();
    let method = parts.method.clone();
    let uri = parts.uri.clone();
    let body_bytes = to_bytes(body, usize::MAX)
        .await
        .context("failed to read incoming request body")?;
    // Сборка запроса на анализ
    let analysis_request = build_analysis_request(&parts.headers, &method, &uri, &body_bytes, remote_addr);
    let decision = state.analyzer.analyze(&analysis_request).await?;

    //Передача логгеру атак в случае Block илм Log
    if matches!(decision.action, DecisionAction::Block | DecisionAction::Log) {
        state
            .attack_logger
            .enqueue(NewAttackLog {
                source_ip: analysis_request.source_ip.clone(),
                request_method: Some(analysis_request.method.clone()),
                request_url: Some(build_request_url(&analysis_request.path, analysis_request.query.as_deref())),
                matched_rule_id: decision.matched_rule_id.clone(),
                attack_type: Some(format!("{:?}", decision.reason)),
                payload: Some(build_attack_payload(&analysis_request, &decision.message)?),
                action_taken: format!("{:?}", decision.action).to_ascii_lowercase(),
            })
            .await;
    }
    // Блокировка в случае Block
    if decision.action == DecisionAction::Block {
        let request_preview = build_blocked_request_preview(&analysis_request)?;

        info!(
            source_ip = %analysis_request.source_ip,
            path = %analysis_request.path,
            reason = ?decision.reason,
            matched_rule_id = ?decision.matched_rule_id,
            message = %decision.message,
            request = %request_preview,
            "request blocked by analyzer"
        );

        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                "{{\"error\":\"request blocked\",\"reason\":\"{}\"}}",
                decision.message.replace('"', "\\\"")
            )))
            .context("failed to build blocked response");
    }

    forward_request(state, uri, method, &parts.headers, body_bytes, &analysis_request.source_ip).await
}

async fn forward_request(
    state: ProxyState,
    uri: Uri,
    method: axum::http::Method,
    headers: &HeaderMap,
    body_bytes: axum::body::Bytes,
    source_ip: &str,
) -> Result<Response<Body>> {
    let target_base_url = {
        let config = state.shared_state.config.read().await.clone();
        Url::parse(&config.target_url)
            .with_context(|| format!("failed to parse target URL '{}'", config.target_url))?
    };
    let upstream_url = build_upstream_url(&target_base_url, &uri)?;
    let forwarded_headers = build_forward_headers(headers, &uri, source_ip)?;
    //ответ от целевого сервера
    let upstream_response = state
        .client
        .request(method, upstream_url)
        .headers(forwarded_headers)
        .body(body_bytes)
        .send()
        .await
        .context("failed to send request to upstream")?;
    //разбор ответа по частям
    let status = upstream_response.status();
    let mut response_headers = filter_response_headers(upstream_response.headers());
    inject_security_headers(&mut response_headers)?;
    let response_body = upstream_response
        .bytes()
        .await
        .context("failed to read upstream response body")?;
    //пересборка и отпрака клиенту
    let mut response_builder = Response::builder().status(status);
    for (name, value) in &response_headers {
        response_builder = response_builder.header(name, value);
    }

    response_builder
        .body(Body::from(response_body))
        .context("failed to build proxied response")
}

fn build_upstream_url(target_base_url: &Url, uri: &Uri) -> Result<Url> {
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    target_base_url
        .join(path_and_query.trim_start_matches('/'))
        .with_context(|| format!("failed to build upstream URL for '{}'", path_and_query))
}

fn build_forward_headers(
    headers: &HeaderMap,
    uri: &Uri,
    source_ip: &str,
) -> Result<reqwest::header::HeaderMap> {
    let mut forwarded = reqwest::header::HeaderMap::new();

    for (name, value) in headers {
        if is_hop_by_hop_header(name) || name == HOST {
            continue;
        }

        forwarded.insert(name.clone(), value.clone());
    }

    forwarded.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );

    forwarded.insert(
        HeaderName::from_static("x-forwarded-host"),
        HeaderValue::from_str(
            uri.authority()
                .map(|authority| authority.as_str())
                .unwrap_or("waf.local"),
        )
        .context("failed to set x-forwarded-host header")?,
    );

    append_forwarded_for(&mut forwarded, source_ip)?;

    Ok(forwarded)
}

fn append_forwarded_for(
    headers: &mut reqwest::header::HeaderMap,
    source_ip: &str,
) -> Result<()> {
    let name = HeaderName::from_static("x-forwarded-for");
    let updated_value = match headers.get(&name) {
        Some(current) => format!("{}, {}", current.to_str().unwrap_or_default(), source_ip),
        None => source_ip.to_string(),
    };

    headers.insert(
        name,
        HeaderValue::from_str(&updated_value)
            .with_context(|| format!("failed to build x-forwarded-for header '{}'", updated_value))?,
    );

    Ok(())
}
//удаляем hop-by-hop заголовки
fn filter_response_headers(headers: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();

    for (name, value) in headers {
        if !is_hop_by_hop_header(name) {
            filtered.append(name.clone(), value.clone());
        }
    }

    filtered
}

fn inject_security_headers(headers: &mut HeaderMap) -> Result<()> {
    headers.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(
        ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("https://waf.local"),
    );
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
        ),
    );

    harden_set_cookie_headers(headers)?;

    Ok(())
}

fn harden_set_cookie_headers(headers: &mut HeaderMap) -> Result<()> {
    let existing_cookies: Vec<HeaderValue> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    if existing_cookies.is_empty() {
        return Ok(());
    }

    let mut hardened_cookies = Vec::with_capacity(existing_cookies.len());
    for cookie_value in existing_cookies {
        let hardened_cookie = match cookie_value.to_str() {
            Ok(cookie_str) => {
                let mut updated_cookie = cookie_str.to_string();
                let normalized_cookie = cookie_str.to_ascii_lowercase();

                if !normalized_cookie.contains("; secure") && !normalized_cookie.ends_with(" secure")
                {
                    updated_cookie.push_str("; Secure");
                }
                if !normalized_cookie.contains("; samesite=")
                    && !normalized_cookie.ends_with(" samesite")
                {
                    updated_cookie.push_str("; SameSite=Lax");
                }

                HeaderValue::from_str(&updated_cookie).with_context(|| {
                    format!(
                        "failed to build hardened Set-Cookie header '{}'",
                        updated_cookie
                    )
                })?
            }
            Err(_) => cookie_value,
        };

        hardened_cookies.push(hardened_cookie);
    }

    headers.remove(SET_COOKIE);
    for cookie in hardened_cookies {
        headers.append(SET_COOKIE, cookie);
    }

    Ok(())
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn resolve_runtime_path(path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        return candidate;
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(candidate)
}
////?????
fn build_analysis_request(
    headers: &HeaderMap,
    method: &axum::http::Method,
    uri: &Uri,
    body_bytes: &[u8],
    remote_addr: SocketAddr,
) -> AnalysisRequest {
    AnalysisRequest {
        source_ip: remote_addr.ip().to_string(),
        method: method.as_str().to_string(),
        path: uri.path().to_string(),
        query: uri.query().map(|value| value.to_string()),
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect(),
        body: if body_bytes.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(body_bytes).to_string())
        },
    }
}

fn build_request_url(path: &str, query: Option<&str>) -> String {
    match query {
        Some(query) if !query.is_empty() => format!("{path}?{query}"),
        _ => path.to_string(),
    }
}

fn build_attack_payload(request: &AnalysisRequest, message: &str) -> Result<String> {
    serde_json::to_string(&serde_json::json!({
        "message": message,
        "headers": request.headers,
        "query": request.query,
        "body": request.body,
    }))
    .context("failed to serialize attack payload")
}

fn build_blocked_request_preview(request: &AnalysisRequest) -> Result<String> {
    let headers = request
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), truncate_preview(value, 256)))
        .collect::<Vec<_>>();

    serde_json::to_string(&serde_json::json!({
        "method": request.method,
        "path": request.path,
        "query": request.query,
        "headers": headers,
        "body": request.body.as_ref().map(|body| truncate_preview(body, 1024)),
    }))
    .context("failed to serialize blocked request preview")
}

fn truncate_preview(value: &str, max_len: usize) -> String {
    let mut truncated = String::new();
    let mut chars = value.chars();

    for _ in 0..max_len {
        match chars.next() {
            Some(ch) => truncated.push(ch),
            None => return truncated,
        }
    }

    if chars.next().is_some() {
        truncated.push_str("...");
    }

    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_response_headers_preserves_multiple_set_cookie_headers() {
        let mut upstream_headers = reqwest::header::HeaderMap::new();
        upstream_headers.append(
            SET_COOKIE,
            HeaderValue::from_static("session=abc; Path=/; HttpOnly"),
        );
        upstream_headers.append(SET_COOKIE, HeaderValue::from_static("theme=dark; Path=/"));

        let filtered = filter_response_headers(&upstream_headers);
        let cookies: Vec<_> = filtered.get_all(SET_COOKIE).iter().collect();

        assert_eq!(cookies.len(), 2);
    }

    #[test]
    fn inject_security_headers_adds_gateway_headers() {
        let mut headers = HeaderMap::new();

        inject_security_headers(&mut headers).expect("security header injection should succeed");

        assert_eq!(
            headers.get(STRICT_TRANSPORT_SECURITY).and_then(|v| v.to_str().ok()),
            Some("max-age=31536000; includeSubDomains")
        );
        assert_eq!(
            headers.get(X_FRAME_OPTIONS).and_then(|v| v.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            headers
                .get(X_CONTENT_TYPE_OPTIONS)
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("https://waf.local")
        );
        assert_eq!(
            headers
                .get(CONTENT_SECURITY_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some(
                "default-src 'self'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
            )
        );
    }

    #[test]
    fn harden_set_cookie_headers_appends_missing_attributes() {
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("session=abc; Path=/; HttpOnly"),
        );
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("prefs=1; Path=/; Secure; SameSite=Strict"),
        );

        harden_set_cookie_headers(&mut headers).expect("cookie hardening should succeed");

        let cookies: Vec<String> = headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect();

        assert_eq!(cookies.len(), 2);
        assert!(cookies[0].contains("; Secure"));
        assert!(cookies[0].contains("; SameSite=Lax"));
        assert!(cookies[1].contains("; Secure"));
        assert!(cookies[1].contains("SameSite=Strict"));
    }

    #[test]
    fn blocked_request_preview_includes_request_parts_and_truncates_body() {
        let request = AnalysisRequest {
            source_ip: "127.0.0.1".to_string(),
            method: "POST".to_string(),
            path: "/login".to_string(),
            query: Some("return=/admin".to_string()),
            headers: [
                ("content-type".to_string(), "application/json".to_string()),
                ("x-auth-token".to_string(), "abc123".to_string()),
            ]
            .into_iter()
            .collect(),
            body: Some("x".repeat(1100)),
        };

        let preview = build_blocked_request_preview(&request)
            .expect("request preview serialization should succeed");

        assert!(preview.contains("\"method\":\"POST\""));
        assert!(preview.contains("\"path\":\"/login\""));
        assert!(preview.contains("\"query\":\"return=/admin\""));
        assert!(preview.contains("\"content-type\",\"application/json\""));
        assert!(preview.contains("\"x-auth-token\",\"abc123\""));
        assert!(preview.contains("..."));
    }
}
