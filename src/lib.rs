pub mod config;
pub mod db;
pub mod rate_limit;
pub mod tokens;

use crate::config::Config;
use crate::db::Db;
use crate::rate_limit::LoginRateLimiter;
use crate::tokens::{issue_access, verify_access};
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub cfg: Arc<Config>,
    pub limiter: Arc<LoginRateLimiter>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub ok: bool,
    pub service: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserBody {
    pub id: String,
    pub username: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub user: UserBody,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/settings", get(read_settings).put(write_settings))
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "auth-server".into(),
    })
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    if !state.cfg.allow_register {
        return err(StatusCode::FORBIDDEN, "registration_disabled");
    }

    let username = body.username.trim();
    if username.is_empty() {
        return err(StatusCode::BAD_REQUEST, "bad_request");
    }
    if body.password.len() < 8 {
        return err(StatusCode::BAD_REQUEST, "weak_password");
    }

    let ip = client_ip(&headers);
    let key = format!(
        "reg:{}:{}",
        ip,
        crate::db::normalize_username(username)
    );
    let window = Duration::from_secs(state.cfg.login_rate_window_secs);
    if !state
        .limiter
        .check_and_record(&key, state.cfg.login_rate_limit, window)
    {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }

    let user = match state.db.create_user(username, &body.password) {
        Ok(u) => u,
        Err(crate::db::DbError::UsernameTaken) => {
            return err(StatusCode::CONFLICT, "username_taken");
        }
        Err(crate::db::DbError::Password(msg)) if msg.contains("at least 8") => {
            return err(StatusCode::BAD_REQUEST, "weak_password");
        }
        Err(crate::db::DbError::Password(_)) => {
            return err(StatusCode::BAD_REQUEST, "bad_request");
        }
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };

    issue_pair(&state, &user.id, &user.username, None)
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    let ip = client_ip(&headers);
    let key = format!(
        "login:{}:{}",
        ip,
        crate::db::normalize_username(&body.username)
    );
    let window = Duration::from_secs(state.cfg.login_rate_window_secs);
    if !state
        .limiter
        .check_and_record(&key, state.cfg.login_rate_limit, window)
    {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }

    let user = match state.db.find_user_by_username(&body.username) {
        Ok(Some(u)) => u,
        Ok(None) => return err(StatusCode::UNAUTHORIZED, "invalid_credentials"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };

    match Db::verify_password(&user, &body.password) {
        Ok(true) => {}
        Ok(false) => return err(StatusCode::UNAUTHORIZED, "invalid_credentials"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }

    issue_pair(&state, &user.id, &user.username, None)
}

async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> impl IntoResponse {
    match state.db.rotate_refresh(&body.refresh_token, &state.cfg) {
        Ok((user, new_refresh)) => match issue_access(&state.cfg, &user.id, &user.username) {
            Ok(access) => (
                StatusCode::OK,
                Json(TokenResponse {
                    access_token: access,
                    refresh_token: new_refresh,
                    expires_in: state.cfg.access_ttl_secs,
                    user: UserBody {
                        id: user.id,
                        username: user.username,
                    },
                }),
            )
                .into_response(),
            Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        },
        Err(_) => err(StatusCode::UNAUTHORIZED, "invalid_token"),
    }
}

async fn logout(
    State(state): State<AppState>,
    Json(body): Json<LogoutRequest>,
) -> impl IntoResponse {
    if let Some(token) = body.refresh_token.as_deref() {
        let _ = state.db.revoke_refresh(token);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(token) = bearer_token(&headers) else {
        return err(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let claims = match verify_access(&state.cfg, &token) {
        Ok(c) => c,
        Err(_) => return err(StatusCode::UNAUTHORIZED, "invalid_token"),
    };
    match state.db.find_user_by_id(&claims.sub) {
        Ok(Some(user)) => (
            StatusCode::OK,
            Json(UserBody {
                id: user.id,
                username: user.username,
            }),
        )
            .into_response(),
        Ok(None) => err(StatusCode::UNAUTHORIZED, "invalid_token"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

fn issue_pair(
    state: &AppState,
    user_id: &str,
    username: &str,
    family: Option<String>,
) -> axum::response::Response {
    let refresh = match state.db.issue_refresh(user_id, &state.cfg, family) {
        Ok((raw, _)) => raw,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };
    let access = match issue_access(&state.cfg, user_id, username) {
        Ok(t) => t,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };
    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token: access,
            refresh_token: refresh,
            expires_in: state.cfg.access_ttl_secs,
            user: UserBody {
                id: user_id.to_string(),
                username: username.to_string(),
            },
        }),
    )
        .into_response()
}

const MAX_SETTINGS_BYTES: usize = 512 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutSettingsBody {
    revision: Option<i64>,
    document: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SettingsResponse {
    revision: i64,
    updated_at: i64,
    document: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn read_settings(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(user_id) = authed_user_id(&state, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    match state.db.get_settings(&user_id) {
        Ok(Some(row)) => settings_response(StatusCode::OK, &row, None),
        Ok(None) => err(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

async fn write_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PutSettingsBody>,
) -> impl IntoResponse {
    let Some(user_id) = authed_user_id(&state, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    if body.revision.is_some_and(|revision| revision < 0) || !body.document.is_object() {
        return err(StatusCode::BAD_REQUEST, "bad_request");
    }
    if document_has_secret(&body.document) {
        return err(StatusCode::BAD_REQUEST, "bad_request");
    }
    let Ok(raw) = serde_json::to_string(&body.document) else {
        return err(StatusCode::BAD_REQUEST, "bad_request");
    };
    if raw.len() > MAX_SETTINGS_BYTES {
        return err(StatusCode::BAD_REQUEST, "bad_request");
    }
    match state.db.put_settings(&user_id, body.revision, &raw) {
        Ok(crate::db::SettingsWrite::Saved(row)) => settings_response(StatusCode::OK, &row, None),
        Ok(crate::db::SettingsWrite::Conflict(row)) => {
            settings_response(StatusCode::CONFLICT, &row, Some("conflict"))
        }
        Ok(crate::db::SettingsWrite::Missing) => err(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

fn authed_user_id(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = bearer_token(headers)?;
    let claims = verify_access(&state.cfg, &token).ok()?;
    match state.db.find_user_by_id(&claims.sub) {
        Ok(Some(user)) => Some(user.id),
        _ => None,
    }
}

fn settings_response(
    status: StatusCode,
    row: &crate::db::SettingsRow,
    error: Option<&str>,
) -> axum::response::Response {
    let document = serde_json::from_str(&row.document).unwrap_or(Value::Null);
    (
        status,
        Json(SettingsResponse {
            revision: row.revision,
            updated_at: row.updated_at,
            document,
            error: error.map(str::to_string),
        }),
    )
        .into_response()
}

/// Reject password, token, and API-key fields. The `secrets` array is a list of
/// key names and is allowed.
fn document_has_secret(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, child)| {
            if key == "secrets" {
                return false;
            }
            if is_secret_field(key) {
                return !is_empty_secret_value(child);
            }
            document_has_secret(child)
        }),
        Value::Array(items) => items.iter().any(document_has_secret),
        _ => false,
    }
}

fn is_empty_secret_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) if text.is_empty() => true,
        _ => false,
    }
}

fn is_secret_field(key: &str) -> bool {
    const SECRET_KEYS: &[&str] = &[
        "password",
        "secret",
        "token",
        "apikey",
        "api_key",
        "apptoken",
        "app_token",
        "refreshtoken",
        "refresh_token",
        "accesstoken",
        "access_token",
        "authorization",
        "clientsecret",
        "client_secret",
    ];
    let normalized: String = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .flat_map(|ch| ch.to_lowercase())
        .collect();
    let flat = normalized.replace('_', "");
    SECRET_KEYS
        .iter()
        .any(|item| *item == normalized.as_str() || item.replace('_', "") == flat)
}

fn err(status: StatusCode, code: &str) -> axum::response::Response {
    (status, Json(ErrorBody { error: code.into() })).into_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let rest = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?;
    Some(rest.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_keep_secret_names_and_reject_values() {
        let ok = serde_json::json!({
            "sources": {
                "feed": {
                    "secrets": ["broadcastify.password"],
                    "params": { "feedId": "42", "note": "desk" }
                }
            }
        });
        assert!(!document_has_secret(&ok));
        let leaked = serde_json::json!({
            "boards": [{ "options": { "password": "panel-secret-value" } }]
        });
        assert!(document_has_secret(&leaked));
        let nested = serde_json::json!({
            "sources": { "feed": { "params": { "nested": { "apiKey": "abcd1234efgh" } } } }
        });
        assert!(document_has_secret(&nested));
    }
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}
