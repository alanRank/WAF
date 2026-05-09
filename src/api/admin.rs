use crate::{
    core::{
        config::{
            apply_runtime_env_overrides, compile_rules, load_rules_from_value,
            load_security_policies_from_value, save_config, save_rules, save_security_policies,
            AppFiles, SharedState,
        },
        db::Database,
        models::{
            Config, IpAccessEntry, JwtClaims, LoginRequest, LoginResponse, NewIpAccessEntry,
            NewUser, Rule, SecurityPolicies, UpdateIpAccessEntry, User, UserRole, UserSummary,
        },
    },
};
use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{
        header::{
            HeaderValue, AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY,
            CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
        },
        StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use chrono::{DateTime, Duration, NaiveDateTime, Timelike, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;
use tracing::info;

#[derive(Clone)]
pub struct AdminApiState {
    pub db: Database,
    pub shared_state: SharedState,
    pub files: AppFiles,
    pub jwt_secret: Arc<String>,
}

pub async fn run_admin_api(state: AdminApiState) -> Result<()> {
    let config = state.shared_state.config.read().await.clone();
    let address: SocketAddr = format!("0.0.0.0:{}", config.admin_port)
        .parse()
        .with_context(|| format!("failed to parse admin bind port '{}'", config.admin_port))?;

    let protected = Router::new()
        .route("/config", get(get_config).put(update_config))
        .route("/rules", get(get_rules).put(update_rules))
        .route("/security-policies", get(get_security_policies).put(update_security_policies))
        .route("/logs", get(list_attack_logs))
        .route("/logs/clear", post(clear_attack_logs))
        .route("/reports/daily.pdf", get(download_daily_report_pdf))
        .route("/reports/daily.json", get(download_daily_report_json))
        .route("/logs/:id", get(get_attack_log))
        .route("/logs/:id", delete(delete_attack_log))
        .route("/ip-lists", get(list_ip_entries).post(upsert_ip_entry))
        .route("/ip-lists/:ip", patch(update_ip_entry).delete(delete_ip_entry))
        .route("/users", get(list_users).post(create_user))
        .route("/users/:username", patch(update_user).delete(delete_user))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_authentication,
        ));

    let static_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("public/admin");

    let router = Router::new()
        .route("/api/admin/login", post(login))
        .nest("/api/admin", protected)
        .nest_service("/admin", ServeDir::new(static_dir))
        .layer(middleware::from_fn(set_security_headers))
        .with_state(state);

    info!(bind = %address, "starting admin API");

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .context("failed to bind admin API listener")?;

    axum::serve(listener, router)
        .await
        .context("admin API terminated unexpectedly")
}

async fn login(
    State(state): State<AdminApiState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let user = state
        .db
        .get_user_by_username(&payload.username)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::unauthorized("invalid credentials"))?;

    if user.password_hash != hash_password(&payload.password) {
        return Err(ApiError::unauthorized("invalid credentials"));
    }

    let expires_at = (Utc::now() + Duration::hours(8)).timestamp();
    let claims = JwtClaims {
        sub: user.username,
        role: user.role.clone(),
        exp: expires_at as usize,
    };

    let access_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(ApiError::internal)?;

    Ok(Json(LoginResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_at,
        role: user.role,
    }))
}

async fn get_config(State(state): State<AdminApiState>) -> Result<Json<Config>, ApiError> {
    Ok(Json(state.shared_state.config.read().await.clone()))
}

async fn update_config(
    State(state): State<AdminApiState>,
    Json(new_config): Json<Config>,
) -> Result<Json<Config>, ApiError> {
    crate::core::config::load_config_from_value(&new_config).map_err(ApiError::bad_request)?;
    save_config(&state.files.config_path, &new_config).map_err(ApiError::internal)?;
    let mut effective_config = new_config.clone();
    apply_runtime_env_overrides(&mut effective_config).map_err(ApiError::bad_request)?;
    *state.shared_state.config.write().await = effective_config.clone();
    Ok(Json(effective_config))
}

async fn get_rules(State(state): State<AdminApiState>) -> Result<Json<Vec<Rule>>, ApiError> {
    Ok(Json(state.shared_state.rules.read().await.clone()))
}

async fn update_rules(
    State(state): State<AdminApiState>,
    Json(new_rules): Json<Vec<Rule>>,
) -> Result<Json<Vec<Rule>>, ApiError> {
    load_rules_from_value(&new_rules).map_err(ApiError::bad_request)?;
    let compiled_rules = compile_rules(&new_rules).map_err(ApiError::bad_request)?;
    save_rules(&state.files.rules_path, &new_rules).map_err(ApiError::internal)?;
    *state.shared_state.rules.write().await = new_rules.clone();
    *state.shared_state.compiled_rules.write().await = compiled_rules;
    Ok(Json(new_rules))
}

async fn get_security_policies(
    State(state): State<AdminApiState>,
) -> Result<Json<SecurityPolicies>, ApiError> {
    Ok(Json(state.shared_state.security_policies.read().await.clone()))
}

async fn update_security_policies(
    State(state): State<AdminApiState>,
    Json(new_policies): Json<SecurityPolicies>,
) -> Result<Json<SecurityPolicies>, ApiError> {
    load_security_policies_from_value(&new_policies).map_err(ApiError::bad_request)?;
    save_security_policies(&state.files.security_policies_path, &new_policies)
        .map_err(ApiError::internal)?;
    *state.shared_state.security_policies.write().await = new_policies.clone();
    Ok(Json(new_policies))
}

async fn list_attack_logs(
    State(state): State<AdminApiState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<crate::core::models::AttackLog>>, ApiError> {
    let logs = match params.get("limit").map(String::as_str) {
        Some("all") => state
            .db
            .list_all_attack_logs()
            .await
            .map_err(ApiError::internal)?,
        _ => {
            let limit = params
                .get("limit")
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(100);
            state
                .db
                .list_attack_logs(limit)
                .await
                .map_err(ApiError::internal)?
        }
    };
    Ok(Json(logs))
}

async fn get_attack_log(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Json<crate::core::models::AttackLog>, ApiError> {
    let log = state
        .db
        .get_attack_log(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("log not found"))?;
    Ok(Json(log))
}

async fn delete_attack_log(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let deleted = state
        .db
        .delete_attack_log(id)
        .await
        .map_err(ApiError::internal)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("log not found"))
    }
}

async fn clear_attack_logs(State(state): State<AdminApiState>) -> Result<Json<ClearLogsResponse>, ApiError> {
    let deleted = state
        .db
        .clear_attack_logs()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(ClearLogsResponse { deleted }))
}

async fn download_daily_report_pdf(
    State(state): State<AdminApiState>,
) -> Result<Response, ApiError> {
    let report = build_daily_report(&state).await.map_err(ApiError::internal)?;
    let pdf_bytes = render_daily_report_pdf(&report)?;
    let filename = format!(
        "waf-daily-report-{}.pdf",
        report.window_end.format("%Y-%m-%d")
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/pdf")
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(pdf_bytes))
        .map_err(ApiError::internal)
}

async fn download_daily_report_json(
    State(state): State<AdminApiState>,
) -> Result<Response, ApiError> {
    let report = build_daily_report(&state).await.map_err(ApiError::internal)?;
    let json_bytes = serde_json::to_vec_pretty(&report).map_err(ApiError::internal)?;
    let filename = format!(
        "waf-daily-logs-{}.json",
        report.window_end.format("%Y-%m-%d")
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(json_bytes))
        .map_err(ApiError::internal)
}

async fn list_ip_entries(
    State(state): State<AdminApiState>,
) -> Result<Json<Vec<IpAccessEntry>>, ApiError> {
    let entries = state
        .db
        .list_ip_access_entries()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(entries))
}

async fn upsert_ip_entry(
    State(state): State<AdminApiState>,
    Json(payload): Json<NewIpAccessEntry>,
) -> Result<Json<IpAccessEntry>, ApiError> {
    let entry = state
        .db
        .upsert_ip_access_entry(&payload)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(entry))
}

async fn update_ip_entry(
    State(state): State<AdminApiState>,
    Path(ip): Path<String>,
    Json(payload): Json<UpdateIpAccessEntry>,
) -> Result<Json<IpAccessEntry>, ApiError> {
    let entry = state
        .db
        .update_ip_access_entry(&ip, &payload)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("IP entry not found"))?;
    Ok(Json(entry))
}

async fn delete_ip_entry(
    State(state): State<AdminApiState>,
    Path(ip): Path<String>,
) -> Result<StatusCode, ApiError> {
    let deleted = state
        .db
        .delete_ip_access_entry(&ip)
        .await
        .map_err(ApiError::internal)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("IP entry not found"))
    }
}

async fn list_users(State(state): State<AdminApiState>) -> Result<Json<Vec<UserSummary>>, ApiError> {
    let users = state
        .db
        .list_users()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .map(|user| UserSummary {
            id: user.id,
            username: user.username,
            role: user.role,
            created_at: user.created_at,
        })
        .collect();
    Ok(Json(users))
}

async fn create_user(
    State(state): State<AdminApiState>,
    Json(mut payload): Json<NewUserInput>,
) -> Result<Json<User>, ApiError> {
    let user = NewUser {
        username: std::mem::take(&mut payload.username),
        password_hash: hash_password(&payload.password),
        role: payload.role,
    };
    let created = state.db.create_user(&user).await.map_err(ApiError::internal)?;
    Ok(Json(created))
}

async fn delete_user(
    State(state): State<AdminApiState>,
    Path(username): Path<String>,
) -> Result<StatusCode, ApiError> {
    let deleted = state
        .db
        .delete_user(&username)
        .await
        .map_err(ApiError::internal)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("user not found"))
    }
}

async fn update_user(
    State(state): State<AdminApiState>,
    Path(username): Path<String>,
    Json(payload): Json<UpdateUserInput>,
) -> Result<Json<UserSummary>, ApiError> {
    let password_hash = payload.password.as_deref().map(hash_password);
    let updated = state
        .db
        .update_user(
            &username,
            password_hash.as_deref(),
            payload.role.as_ref().map(UserRole::as_str),
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;

    Ok(Json(UserSummary {
        id: updated.id,
        username: updated.username,
        role: updated.role,
        created_at: updated.created_at,
    }))
}

async fn require_authentication(
    State(state): State<AdminApiState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let header_value = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing authorization header"))?;

    let token = header_value
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::unauthorized("invalid authorization scheme"))?;

    decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| ApiError::unauthorized("invalid or expired token"))?;

    Ok(next.run(request).await)
}

async fn set_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdn.jsdelivr.net/npm/chart.js; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        ),
    );
    response
}

#[derive(Debug, Deserialize)]
struct NewUserInput {
    username: String,
    password: String,
    role: UserRole,
}

#[derive(Debug, Deserialize)]
struct UpdateUserInput {
    password: Option<String>,
    role: Option<UserRole>,
}

#[derive(Debug, Serialize)]
struct ClearLogsResponse {
    deleted: u64,
}

#[derive(Debug, Clone, Serialize)]
struct DailyReport {
    generated_at: String,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    total_attacks: usize,
    distribution: Vec<ReportCount>,
    top_attack_types: Vec<ReportCount>,
    timeline: Vec<TimelineBucket>,
    logs: Vec<crate::core::models::AttackLog>,
}

#[derive(Debug, Clone, Serialize)]
struct ReportCount {
    label: String,
    count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct TimelineBucket {
    label: String,
    count: usize,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn bad_request(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorPayload {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct ErrorPayload {
    error: String,
}

pub async fn ensure_default_admin_user(db: &Database) -> Result<()> {
    if db
        .get_user_by_username("admin")
        .await?
        .is_none()
    {
        db.create_user(&NewUser {
            username: "admin".to_string(),
            password_hash: hash_password("admin123"),
            role: UserRole::Admin,
        })
        .await
        .context("failed to seed default admin user")?;
    }

    Ok(())
}

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

async fn build_daily_report(state: &AdminApiState) -> Result<DailyReport> {
    let all_logs = state.db.list_all_attack_logs().await?;
    let window_end = Utc::now();
    let window_start = window_end - Duration::hours(24);
    let rule_labels = state
        .shared_state
        .rules
        .read()
        .await
        .iter()
        .map(|rule| (rule.id.clone(), format!("{} - {}", rule.id, rule.name)))
        .collect::<HashMap<_, _>>();

    let mut logs = all_logs
        .into_iter()
        .filter_map(|log| {
            let timestamp = parse_attack_log_timestamp(&log.timestamp).ok()?;
            if timestamp >= window_start && timestamp <= window_end {
                Some((timestamp, log))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    logs.sort_by_key(|(timestamp, _)| *timestamp);

    let distribution = build_distribution(&logs, &rule_labels);
    let top_attack_types = distribution.iter().take(3).cloned().collect::<Vec<_>>();
    let timeline = build_timeline(&logs, window_end);
    let logs_only = logs.into_iter().map(|(_, log)| log).collect::<Vec<_>>();

    Ok(DailyReport {
        generated_at: window_end.to_rfc3339(),
        window_start,
        window_end,
        total_attacks: logs_only.len(),
        distribution,
        top_attack_types,
        timeline,
        logs: logs_only,
    })
}

fn build_distribution(
    logs: &[(DateTime<Utc>, crate::core::models::AttackLog)],
    rule_labels: &HashMap<String, String>,
) -> Vec<ReportCount> {
    let mut counts = HashMap::<String, usize>::new();

    for (_, log) in logs {
        let label = report_attack_label(log, rule_labels);
        *counts.entry(label).or_insert(0) += 1;
    }

    let mut items = counts
        .into_iter()
        .map(|(label, count)| ReportCount { label, count })
        .collect::<Vec<_>>();

    items.sort_by(|left, right| right.count.cmp(&left.count).then_with(|| left.label.cmp(&right.label)));
    items
}

fn build_timeline(
    logs: &[(DateTime<Utc>, crate::core::models::AttackLog)],
    window_end: DateTime<Utc>,
) -> Vec<TimelineBucket> {
    let end_hour = window_end
        .with_minute(0)
        .and_then(|time| time.with_second(0))
        .and_then(|time| time.with_nanosecond(0))
        .unwrap_or(window_end);
    let start_hour = end_hour - Duration::hours(23);
    let mut counts = vec![0usize; 24];

    for (timestamp, _) in logs {
        if *timestamp < start_hour || *timestamp > end_hour + Duration::hours(1) {
            continue;
        }

        let offset = timestamp.signed_duration_since(start_hour).num_hours();
        if (0..24).contains(&offset) {
            counts[offset as usize] += 1;
        }
    }

    (0..24)
        .map(|index| {
            let hour = start_hour + Duration::hours(index as i64);
            TimelineBucket {
                label: hour.format("%H:%M").to_string(),
                count: counts[index],
            }
        })
        .collect()
}

fn report_attack_label(
    log: &crate::core::models::AttackLog,
    rule_labels: &HashMap<String, String>,
) -> String {
    if let Some(rule_id) = &log.matched_rule_id {
        return rule_labels
            .get(rule_id)
            .cloned()
            .unwrap_or_else(|| rule_id.clone());
    }

    log.attack_type
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "Other".to_string())
}

fn parse_attack_log_timestamp(value: &str) -> Result<DateTime<Utc>> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Ok(parsed.with_timezone(&Utc));
    }

    let naive = NaiveDateTime::parse_from_str(value.trim(), "%Y-%m-%d %H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(value.trim(), "%Y-%m-%dT%H:%M:%S"))
        .with_context(|| format!("failed to parse attack log timestamp '{value}'"))?;

    Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

fn render_daily_report_pdf(report: &DailyReport) -> Result<Vec<u8>, ApiError> {
    let mut content = String::new();
    let page = PdfPage::new(842.0, 595.0);

    content.push_str(&page.fill_rect(0.0, 0.0, 842.0, 595.0, (0.953, 0.957, 1.0)));
    content.push_str(&page.fill_rect(36.0, 530.0, 770.0, 42.0, (0.365, 0.400, 0.839)));
    content.push_str(&page.text(
        "F2",
        24.0,
        52.0,
        548.0,
        (1.0, 1.0, 1.0),
        "WAF Daily Report",
    ));
    content.push_str(&page.text(
        "F1",
        10.0,
        52.0,
        532.0,
        (1.0, 1.0, 1.0),
        &format!(
            "Window: {} to {}",
            report.window_start.format("%Y-%m-%d %H:%M UTC"),
            report.window_end.format("%Y-%m-%d %H:%M UTC")
        ),
    ));

    draw_summary_card(
        &page,
        &mut content,
        36.0,
        438.0,
        230.0,
        74.0,
        "Total attacks / 24h",
        &report.total_attacks.to_string(),
    );
    draw_summary_card(
        &page,
        &mut content,
        287.0,
        438.0,
        230.0,
        74.0,
        "Most frequent type",
        report
            .top_attack_types
            .first()
            .map(|item| trim_label(&item.label, 30))
            .as_deref()
            .unwrap_or("No attacks"),
    );
    draw_summary_card(
        &page,
        &mut content,
        538.0,
        438.0,
        268.0,
        74.0,
        "Generated at",
        &report.window_end.format("%Y-%m-%d %H:%M UTC").to_string(),
    );

    draw_panel(&page, &mut content, 36.0, 208.0, 470.0, 210.0, "Distribution by attack type");
    draw_distribution_chart(&page, &mut content, report);

    draw_panel(&page, &mut content, 528.0, 208.0, 278.0, 210.0, "Top 3 attack types");
    draw_top_attack_list(&page, &mut content, report);

    draw_panel(&page, &mut content, 36.0, 36.0, 770.0, 152.0, "Timeline for the last 24 hours");
    draw_timeline_chart(&page, &mut content, report);

    build_pdf_document(page, &content).map_err(ApiError::internal)
}

fn draw_summary_card(
    page: &PdfPage,
    content: &mut String,
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    title: &str,
    value: &str,
) {
    content.push_str(&page.fill_rect(x, y, width, height, (1.0, 1.0, 1.0)));
    content.push_str(&page.stroke_rect(x, y, width, height, (0.365, 0.400, 0.839)));
    content.push_str(&page.text("F1", 10.0, x + 16.0, y + height - 20.0, (0.365, 0.400, 0.839), title));
    content.push_str(&page.text("F2", 17.0, x + 16.0, y + 26.0, (0.145, 0.169, 0.361), value));
}

fn draw_panel(
    page: &PdfPage,
    content: &mut String,
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    title: &str,
) {
    content.push_str(&page.fill_rect(x, y, width, height, (1.0, 1.0, 1.0)));
    content.push_str(&page.stroke_rect(x, y, width, height, (0.365, 0.400, 0.839)));
    content.push_str(&page.text("F2", 14.0, x + 18.0, y + height - 24.0, (0.145, 0.169, 0.361), title));
}

fn draw_distribution_chart(page: &PdfPage, content: &mut String, report: &DailyReport) {
    let items = report.distribution.iter().take(5).collect::<Vec<_>>();
    if items.is_empty() {
        content.push_str(&page.text("F1", 11.0, 58.0, 310.0, (0.365, 0.400, 0.839), "No attacks in the last 24 hours"));
        return;
    }

    let max_count = items.iter().map(|item| item.count).max().unwrap_or(1) as f32;
    let chart_left = 58.0;
    let mut y = 356.0;
    let colors = [
        (0.604, 0.639, 1.0),
        (0.435, 0.475, 0.945),
        (0.294, 0.337, 0.796),
        (0.365, 0.400, 0.839),
        (0.145, 0.169, 0.361),
    ];

    for (index, item) in items.iter().enumerate() {
        let bar_width = ((item.count as f32 / max_count) * 220.0).max(6.0);
        content.push_str(&page.text(
            "F1",
            10.0,
            chart_left,
            y + 12.0,
            (0.145, 0.169, 0.361),
            &trim_label(&item.label, 36),
        ));
        content.push_str(&page.fill_rect(
            chart_left + 165.0,
            y,
            bar_width,
            14.0,
            colors[index.min(colors.len() - 1)],
        ));
        content.push_str(&page.text(
            "F2",
            10.0,
            chart_left + 165.0 + bar_width + 8.0,
            y + 4.0,
            (0.145, 0.169, 0.361),
            &item.count.to_string(),
        ));
        y -= 30.0;
    }

    content.push_str(&page.text(
        "F1",
        9.0,
        58.0,
        230.0,
        (0.365, 0.400, 0.839),
        "Top categories for the last 24 hours",
    ));
}

fn draw_top_attack_list(page: &PdfPage, content: &mut String, report: &DailyReport) {
    let top = report.top_attack_types.iter().take(3).collect::<Vec<_>>();
    if top.is_empty() {
        content.push_str(&page.text("F1", 11.0, 550.0, 330.0, (0.365, 0.400, 0.839), "No attacks recorded"));
        return;
    }

    let mut y = 350.0;
    for (index, item) in top.iter().enumerate() {
        content.push_str(&page.fill_rect(550.0, y - 8.0, 236.0, 42.0, (0.925, 0.933, 1.0)));
        content.push_str(&page.text(
            "F2",
            12.0,
            566.0,
            y + 14.0,
            (0.145, 0.169, 0.361),
            &format!("{}. {}", index + 1, trim_label(&item.label, 28)),
        ));
        content.push_str(&page.text(
            "F1",
            10.0,
            566.0,
            y,
            (0.365, 0.400, 0.839),
            &format!("Hits: {}", item.count),
        ));
        y -= 54.0;
    }
}

fn draw_timeline_chart(page: &PdfPage, content: &mut String, report: &DailyReport) {
    let chart_left = 60.0;
    let chart_bottom = 62.0;
    let chart_width = 720.0;
    let chart_height = 86.0;
    let max_count = report.timeline.iter().map(|item| item.count).max().unwrap_or(1).max(1) as f32;
    let bar_width = chart_width / report.timeline.len().max(1) as f32;

    content.push_str(&page.stroke_line(chart_left, chart_bottom, chart_left + chart_width, chart_bottom, (0.365, 0.400, 0.839)));
    content.push_str(&page.stroke_line(chart_left, chart_bottom, chart_left, chart_bottom + chart_height, (0.365, 0.400, 0.839)));

    for (index, bucket) in report.timeline.iter().enumerate() {
        let height = if bucket.count == 0 {
            2.0
        } else {
            (bucket.count as f32 / max_count) * (chart_height - 8.0)
        };
        let x = chart_left + index as f32 * bar_width + 1.5;
        content.push_str(&page.fill_rect(x, chart_bottom, (bar_width - 3.0).max(2.0), height, (0.435, 0.475, 0.945)));

        if index % 3 == 0 {
            content.push_str(&page.text(
                "F1",
                8.0,
                x,
                46.0,
                (0.365, 0.400, 0.839),
                &bucket.label,
            ));
        }
    }

    content.push_str(&page.text(
        "F1",
        9.0,
        62.0,
        154.0,
        (0.365, 0.400, 0.839),
        "Bars show the number of attacks in each hourly bucket",
    ));
}

fn trim_label(value: &str, max_len: usize) -> String {
    let mut trimmed = String::new();
    let mut chars = value.chars();

    for _ in 0..max_len {
        match chars.next() {
            Some(ch) => trimmed.push(ch),
            None => return trimmed,
        }
    }

    if chars.next().is_some() {
        trimmed.push_str("...");
    }

    trimmed
}

fn build_pdf_document(page: PdfPage, content: &str) -> Result<Vec<u8>> {
    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = Vec::new();

    append_pdf_object(&mut pdf, &mut offsets, 1, "<< /Type /Catalog /Pages 2 0 R >>");
    append_pdf_object(&mut pdf, &mut offsets, 2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    append_pdf_object(
        &mut pdf,
        &mut offsets,
        3,
        &format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {:.0} {:.0}] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>",
            page.width, page.height
        ),
    );
    append_pdf_object(
        &mut pdf,
        &mut offsets,
        4,
        &format!(
            "<< /Length {} >>\nstream\n{}\nendstream",
            content.as_bytes().len(),
            content
        ),
    );
    append_pdf_object(&mut pdf, &mut offsets, 5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    append_pdf_object(&mut pdf, &mut offsets, 6, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");

    let xref_offset = pdf.as_bytes().len();
    pdf.push_str(&format!("xref\n0 {}\n", offsets.len() + 1));
    pdf.push_str("0000000000 65535 f \n");
    for offset in &offsets {
        pdf.push_str(&format!("{offset:010} 00000 n \n"));
    }
    pdf.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF",
        offsets.len() + 1,
        xref_offset
    ));

    Ok(pdf.into_bytes())
}

fn append_pdf_object(pdf: &mut String, offsets: &mut Vec<usize>, object_id: usize, body: &str) {
    offsets.push(pdf.as_bytes().len());
    pdf.push_str(&format!("{object_id} 0 obj\n{body}\nendobj\n"));
}

struct PdfPage {
    width: f32,
    height: f32,
}

impl PdfPage {
    fn new(width: f32, height: f32) -> Self {
        Self { width, height }
    }

    fn fill_rect(&self, x: f32, y: f32, width: f32, height: f32, color: (f32, f32, f32)) -> String {
        format!(
            "q\n{:.3} {:.3} {:.3} rg\n{:.2} {:.2} {:.2} {:.2} re f\nQ\n",
            color.0, color.1, color.2, x, y, width, height
        )
    }

    fn stroke_rect(&self, x: f32, y: f32, width: f32, height: f32, color: (f32, f32, f32)) -> String {
        format!(
            "q\n{:.3} {:.3} {:.3} RG\n1 w\n{:.2} {:.2} {:.2} {:.2} re S\nQ\n",
            color.0, color.1, color.2, x, y, width, height
        )
    }

    fn stroke_line(&self, x1: f32, y1: f32, x2: f32, y2: f32, color: (f32, f32, f32)) -> String {
        format!(
            "q\n{:.3} {:.3} {:.3} RG\n1 w\n{:.2} {:.2} m\n{:.2} {:.2} l\nS\nQ\n",
            color.0, color.1, color.2, x1, y1, x2, y2
        )
    }

    fn text(
        &self,
        font: &str,
        size: f32,
        x: f32,
        y: f32,
        color: (f32, f32, f32),
        text: &str,
    ) -> String {
        format!(
            "BT\n/{font} {:.2} Tf\n{:.3} {:.3} {:.3} rg\n1 0 0 1 {:.2} {:.2} Tm\n({}) Tj\nET\n",
            size,
            color.0,
            color.1,
            color.2,
            x,
            y,
            escape_pdf_text(text),
        )
    }
}

fn escape_pdf_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}
