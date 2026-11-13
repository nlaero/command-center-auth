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
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "auth-server".into(),
    })
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    let ip = client_ip(&headers);
    let key = format!(
        "{}:{}",
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

fn err(status: StatusCode, code: &str) -> axum::response::Response {
    (status, Json(ErrorBody { error: code.into() })).into_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let rest = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?;
    Some(rest.trim().to_string())
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}
