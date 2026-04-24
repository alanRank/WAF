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
        header::{HeaderName, HOST},
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

    let analysis_request = build_analysis_request(&parts.headers, &method, &uri, &body_bytes, remote_addr);
    let decision = state.analyzer.analyze(&analysis_request).await?;

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

    if decision.action == DecisionAction::Block {
        info!(
            source_ip = %analysis_request.source_ip,
            path = %analysis_request.path,
            reason = ?decision.reason,
            matched_rule_id = ?decision.matched_rule_id,
            message = %decision.message,
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

    let upstream_response = state
        .client
        .request(method, upstream_url)
        .headers(forwarded_headers)
        .body(body_bytes)
        .send()
        .await
        .context("failed to send request to upstream")?;

    let status = upstream_response.status();
    let response_headers = filter_response_headers(upstream_response.headers());
    let response_body = upstream_response
        .bytes()
        .await
        .context("failed to read upstream response body")?;

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

fn filter_response_headers(headers: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();

    for (name, value) in headers {
        if !is_hop_by_hop_header(name) {
            filtered.insert(name.clone(), value.clone());
        }
    }

    filtered
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
