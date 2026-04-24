use crate::{
    core::{
        config::{
            load_rules_from_value, load_security_policies_from_value, save_config, save_rules,
            save_security_policies, AppFiles, SharedState,
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
    extract::{Path, Query, Request, State},
    http::{
        header::{
            HeaderValue, AUTHORIZATION, CONTENT_SECURITY_POLICY, REFERRER_POLICY,
            X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
        },
        StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use chrono::{Duration, Utc};
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
    let address: SocketAddr = format!("127.0.0.1:{}", config.admin_port)
        .parse()
        .with_context(|| format!("failed to parse admin bind port '{}'", config.admin_port))?;

    let protected = Router::new()
        .route("/config", get(get_config).put(update_config))
        .route("/rules", get(get_rules).put(update_rules))
        .route("/security-policies", get(get_security_policies).put(update_security_policies))
        .route("/logs", get(list_attack_logs))
        .route("/logs/clear", post(clear_attack_logs))
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
    *state.shared_state.config.write().await = new_config.clone();
    Ok(Json(new_config))
}

async fn get_rules(State(state): State<AdminApiState>) -> Result<Json<Vec<Rule>>, ApiError> {
    Ok(Json(state.shared_state.rules.read().await.clone()))
}

async fn update_rules(
    State(state): State<AdminApiState>,
    Json(new_rules): Json<Vec<Rule>>,
) -> Result<Json<Vec<Rule>>, ApiError> {
    load_rules_from_value(&new_rules).map_err(ApiError::bad_request)?;
    save_rules(&state.files.rules_path, &new_rules).map_err(ApiError::internal)?;
    *state.shared_state.rules.write().await = new_rules.clone();
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
