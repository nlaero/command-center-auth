//! Local GUI for the server admin.
//!
//! The account that signs in here is created during server install. It is not a
//! Command Center board login, and a board token cannot call these routes.

use crate::config::{bind_is_loopback, ServerMode};
use crate::db::Db;
use crate::install;
use crate::platform::StartupMode;
use crate::tokens::{issue_admin, verify_admin, ADMIN_AUDIENCE};
use crate::{bearer_token, AppState, ErrorBody, LoginRequest};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

const PAGE: &str = include_str!("admin.html");

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin", get(page))
        .route("/admin/api/login", post(login))
        .route("/admin/api/settings", get(read_settings).put(write_settings))
        .route("/admin/api/startup", post(change_startup).put(change_startup))
        .route("/admin/api/password", post(change_password))
        .route("/admin/api/users", get(list_users).post(create_user))
        .route("/admin/api/users/{id}", axum::routing::delete(delete_user))
        .route("/admin/api/users/{id}/password", post(reset_password))
        .layer(axum::middleware::from_fn(require_loopback))
}

pub fn allow_register(state: &AppState) -> bool {
    state.db.setting_bool("allow_register", state.cfg.allow_register)
}

pub fn secret_store_enabled(state: &AppState) -> bool {
    state.cfg.mode == ServerMode::Device
        && bind_is_loopback(&state.cfg.bind)
        && state.db.setting_bool("secret_store", state.cfg.secret_store)
}

async fn require_loopback(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if addr.ip().is_loopback() {
        next.run(request).await
    } else {
        err(StatusCode::FORBIDDEN, "admin_local_only")
    }
}

async fn page() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminSession {
    access_token: String,
    token_type: &'static str,
    username: String,
}

async fn login(State(state): State<AppState>, Json(body): Json<LoginRequest>) -> impl IntoResponse {
    let Some(admin) = state.db.server_admin().ok().flatten() else {
        return err(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
        );
    };
    if crate::db::normalize_username(&body.username) != admin.username_norm {
        return err(StatusCode::UNAUTHORIZED, "invalid_credentials");
    }
    match Db::verify_password_hash(&admin.password_hash, &body.password) {
        Ok(true) => {}
        Ok(false) => return err(StatusCode::UNAUTHORIZED, "invalid_credentials"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
    let token = match issue_admin(&state.cfg, &admin.id, &admin.username) {
        Ok(token) => token,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };
    (
        StatusCode::OK,
        Json(AdminSession {
            access_token: token,
            token_type: "server-admin",
            username: admin.username,
        }),
    )
        .into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SettingsBody {
    mode: String,
    bind: String,
    secret_store: bool,
    secret_store_allowed: bool,
    allow_register: bool,
    startup: Option<String>,
    admin_username: Option<String>,
}

async fn read_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(response) = require_admin(&state, &headers) {
        return response;
    }
    let startup = install::read_startup(&state.cfg.db_path);
    let admin_username = state
        .db
        .server_admin()
        .ok()
        .flatten()
        .map(|admin| admin.username);
    (
        StatusCode::OK,
        Json(SettingsBody {
            mode: state.cfg.mode.as_str().into(),
            bind: state.cfg.bind.clone(),
            secret_store: secret_store_enabled(&state),
            secret_store_allowed: state.cfg.mode == ServerMode::Device
                && bind_is_loopback(&state.cfg.bind),
            allow_register: allow_register(&state),
            startup,
            admin_username,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsPut {
    allow_register: Option<bool>,
    secret_store: Option<bool>,
}

async fn write_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SettingsPut>,
) -> impl IntoResponse {
    if let Err(response) = require_admin(&state, &headers) {
        return response;
    }
    if let Some(enabled) = body.secret_store {
        if enabled && (state.cfg.mode != ServerMode::Device || !bind_is_loopback(&state.cfg.bind))
        {
            return err(
                StatusCode::BAD_REQUEST,
                "A server for other devices does not store passwords or API keys.",
            );
        }
        if let Err(error) = state.db.set_setting("secret_store", if enabled { "true" } else { "false" }) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
        let _ = install::set_env_value(&state.cfg.db_path, "AUTH_SECRET_STORE", if enabled { "true" } else { "false" });
    }
    if let Some(enabled) = body.allow_register {
        if let Err(error) = state
            .db
            .set_setting("allow_register", if enabled { "true" } else { "false" })
        {
            return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
        let _ = install::set_env_value(
            &state.cfg.db_path,
            "AUTH_ALLOW_REGISTER",
            if enabled { "true" } else { "false" },
        );
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct StartupPut {
    startup: String,
}

async fn change_startup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<StartupPut>,
) -> impl IntoResponse {
    if let Err(response) = require_admin(&state, &headers) {
        return response;
    }
    let mode = match StartupMode::parse(&body.startup) {
        Ok(mode) => mode,
        Err(message) => return err(StatusCode::BAD_REQUEST, &message),
    };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => return err(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    match install::switch_startup(&state.cfg.db_path, &exe, mode) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(message) => err(StatusCode::BAD_REQUEST, &message),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordPut {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PasswordPut>,
) -> impl IntoResponse {
    let claims = match require_admin(&state, &headers) {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    if body.new_password.len() < 8 {
        return err(StatusCode::BAD_REQUEST, "weak_password");
    }
    let Some(admin) = state.db.server_admin().ok().flatten() else {
        return err(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    if admin.id != claims.sub {
        return err(StatusCode::UNAUTHORIZED, "invalid_token");
    }
    match Db::verify_password_hash(&admin.password_hash, &body.current_password) {
        Ok(true) => {}
        Ok(false) => return err(StatusCode::UNAUTHORIZED, "invalid_credentials"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
    match state.db.set_server_admin(&admin.username, &body.new_password) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserList {
    users: Vec<UserItem>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserItem {
    id: String,
    username: String,
    created_at: i64,
}

async fn list_users(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(response) = require_admin(&state, &headers) {
        return response;
    }
    match state.db.list_users() {
        Ok(users) => (
            StatusCode::OK,
            Json(UserList {
                users: users
                    .into_iter()
                    .map(|user| UserItem {
                        id: user.id,
                        username: user.username,
                        created_at: user.created_at,
                    })
                    .collect(),
            }),
        )
            .into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    if let Err(response) = require_admin(&state, &headers) {
        return response;
    }
    if body.username.trim().is_empty() || body.password.len() < 8 {
        return err(StatusCode::BAD_REQUEST, "weak_password");
    }
    match state.db.create_user(body.username.trim(), &body.password) {
        Ok(user) => (
            StatusCode::OK,
            Json(UserItem {
                id: user.id,
                username: user.username,
                created_at: 0,
            }),
        )
            .into_response(),
        Err(crate::db::DbError::UsernameTaken) => err(StatusCode::CONFLICT, "username_taken"),
        Err(_) => err(StatusCode::BAD_REQUEST, "bad_request"),
    }
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(response) = require_admin(&state, &headers) {
        return response;
    }
    match state.db.delete_user(&id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

#[derive(Deserialize)]
struct ResetBody {
    password: String,
}

async fn reset_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ResetBody>,
) -> impl IntoResponse {
    if let Err(response) = require_admin(&state, &headers) {
        return response;
    }
    if body.password.len() < 8 {
        return err(StatusCode::BAD_REQUEST, "weak_password");
    }
    if let Err(_) = state.db.set_user_password(&id, &body.password) {
        return err(StatusCode::NOT_FOUND, "not_found");
    }
    let _ = state.db.revoke_user_sessions(&id);
    StatusCode::NO_CONTENT.into_response()
}

fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<crate::tokens::AccessClaims, Response> {
    let Some(token) = bearer_token(headers) else {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid_token"));
    };
    match verify_admin(&state.cfg, &token) {
        Ok(claims) if claims.aud == ADMIN_AUDIENCE => Ok(claims),
        _ => Err(err(StatusCode::UNAUTHORIZED, "invalid_token")),
    }
}

fn err(status: StatusCode, code: &str) -> Response {
    (status, Json(ErrorBody { error: code.into() })).into_response()
}
