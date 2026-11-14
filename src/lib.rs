pub mod admin;
pub mod backup;
pub mod config;
pub mod db;
pub mod install;
pub mod platform;
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
use std::collections::BTreeMap;
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
    /// `device` (this computer) or `shared` (other devices can connect).
    pub mode: String,
    /// Source passwords and API keys are accepted only for a device server.
    pub secret_store: bool,
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
        .route("/vault", get(read_vault).put(write_vault))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/settings", get(read_settings).put(write_settings))
        .merge(admin::routes())
        .with_state(state)
}

pub async fn serve(cfg: Config) -> Result<(), String> {
    let db = Db::open(&cfg.db_path).map_err(|err| format!("db error: {err}"))?;
    let state = AppState {
        db: Arc::new(db),
        cfg: Arc::new(cfg.clone()),
        limiter: Arc::new(LoginRateLimiter::default()),
    };
    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .map_err(|err| format!("bind {} failed: {err}", cfg.bind))?;
    tracing::info!(
        bind = %cfg.bind,
        db = %cfg.db_path.display(),
        mode = cfg.mode.as_str(),
        secret_store = cfg.secret_store,
        "auth-server listening"
    );
    let app = router(state)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    axum::serve(listener, app)
        .await
        .map_err(|err| format!("auth-server exited: {err}"))
}

pub async fn serve_from_args(args: &[String]) -> Result<(), String> {
    if let Some(home) = arg_flag(args, "--home") {
        let _ = config::load_dotenv(&std::path::PathBuf::from(home).join("server").join(".env"));
    }
    serve(Config::from_env()?).await
}

pub(crate) fn arg_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "auth-server".into(),
        mode: state.cfg.mode.as_str().into(),
        secret_store: admin::secret_store_enabled(&state),
    })
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    if !admin::allow_register(&state) {
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

const MAX_VAULT_SECRETS: usize = 64;
const MAX_VAULT_NAME: usize = 128;
const MAX_VAULT_VALUE: usize = 8 * 1024;

#[derive(Debug, Deserialize)]
struct VaultPut {
    secrets: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct VaultBody {
    secrets: BTreeMap<String, String>,
}

async fn read_vault(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(response) = vault_disabled(&state) {
        return response;
    }
    let Some(user_id) = authed_user_id(&state, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    match state.db.list_secrets(&user_id) {
        Ok(secrets) => (StatusCode::OK, Json(VaultBody { secrets })).into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

async fn write_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VaultPut>,
) -> impl IntoResponse {
    if let Some(response) = vault_disabled(&state) {
        return response;
    }
    let Some(user_id) = authed_user_id(&state, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    if let Err(code) = validate_vault(&body.secrets) {
        return err(StatusCode::BAD_REQUEST, code);
    }
    match state.db.replace_secrets(&user_id, &body.secrets) {
        Ok(()) => (StatusCode::OK, Json(VaultBody { secrets: body.secrets })).into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

fn vault_disabled(state: &AppState) -> Option<axum::response::Response> {
    if admin::secret_store_enabled(state) {
        None
    } else {
        Some(err(StatusCode::FORBIDDEN, "secret_store_disabled"))
    }
}

/// Session tokens stay in the desktop keyring. The vault is for source passwords and API keys.
pub fn validate_vault(secrets: &BTreeMap<String, String>) -> Result<(), &'static str> {
    if secrets.len() > MAX_VAULT_SECRETS {
        return Err("bad_request");
    }
    for (name, value) in secrets {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_VAULT_NAME || trimmed.chars().any(|ch| ch.is_control()) {
            return Err("bad_request");
        }
        if is_session_secret(trimmed) {
            return Err("bad_request");
        }
        if value.len() > MAX_VAULT_VALUE {
            return Err("bad_request");
        }
    }
    Ok(())
}

pub fn is_session_secret(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "auth.access_token"
            | "auth.refresh_token"
            | "auth.access_expires_at"
            | "auth.user_id"
            | "auth.username"
    )
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

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<String> {
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

    #[test]
    fn vault_rejects_session_tokens() {
        let mut secrets = BTreeMap::new();
        secrets.insert("broadcastify.password".into(), "desk".into());
        assert!(validate_vault(&secrets).is_ok());
        secrets.insert("auth.access_token".into(), "nope".into());
        assert!(validate_vault(&secrets).is_err());
    }

    #[tokio::test]
    async fn device_server_stores_secrets_and_shared_server_does_not() {
        let device = spawn_server(crate::config::ServerMode::Device, true).await.0;
        let shared = spawn_server(crate::config::ServerMode::Shared, false).await.0;

        let device_health = http(&device, "GET", "/health", None, None).await;
        assert!(device_health.contains("\"mode\":\"device\""));
        assert!(device_health.contains("\"secretStore\":true"));

        let token = register(&device, "ada", "correct-password").await;
        let put = http(
            &device,
            "PUT",
            "/vault",
            Some(&token),
            Some(r#"{"secrets":{"broadcastify.password":"feed-secret","socrata.app_token":"tok"}}"#),
        )
        .await;
        assert!(put.starts_with("HTTP/1.1 200"), "{put}");
        let got = http(&device, "GET", "/vault", Some(&token), None).await;
        assert!(got.contains("feed-secret"), "{got}");

        let shared_token = register(&shared, "ada", "correct-password").await;
        let rejected = http(
            &shared,
            "PUT",
            "/vault",
            Some(&shared_token),
            Some(r#"{"secrets":{"broadcastify.password":"nope"}}"#),
        )
        .await;
        assert!(rejected.starts_with("HTTP/1.1 403"), "{rejected}");
        assert!(rejected.contains("secret_store_disabled"));
    }

    #[tokio::test]
    async fn admin_account_is_not_a_board_login() {
        let (addr, db_path) = spawn_server(crate::config::ServerMode::Device, false).await;
        let db = crate::db::Db::open(&db_path).unwrap();
        db.set_server_admin("desk-admin", "server-admin-pass").unwrap();

        let board = register(&addr, "desk-admin", "board-password-1").await;
        let me = http(&addr, "GET", "/auth/me", Some(&board), None).await;
        assert!(me.contains("desk-admin"), "{me}");

        let rejected = http(
            &addr,
            "POST",
            "/admin/api/login",
            None,
            Some(r#"{"username":"desk-admin","password":"board-password-1"}"#),
        )
        .await;
        assert!(rejected.starts_with("HTTP/1.1 401"), "{rejected}");

        let admin_login = http(
            &addr,
            "POST",
            "/admin/api/login",
            None,
            Some(r#"{"username":"desk-admin","password":"server-admin-pass"}"#),
        )
        .await;
        assert!(admin_login.starts_with("HTTP/1.1 200"), "{admin_login}");
        assert!(admin_login.contains("server-admin"), "{admin_login}");
        let json = admin_login.split("\r\n\r\n").nth(1).unwrap_or("");
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let admin_token = value["accessToken"].as_str().unwrap();

        let admin_as_board = http(&addr, "GET", "/auth/me", Some(admin_token), None).await;
        assert!(admin_as_board.starts_with("HTTP/1.1 401"), "{admin_as_board}");
        let board_as_admin = http(&addr, "GET", "/admin/api/users", Some(&board), None).await;
        assert!(board_as_admin.starts_with("HTTP/1.1 401"), "{board_as_admin}");

        let users = http(&addr, "GET", "/admin/api/users", Some(admin_token), None).await;
        assert!(users.contains("desk-admin"), "{users}");
        let page = http(&addr, "GET", "/admin", None, None).await;
        assert!(page.contains("not a Command Center"), "{page}");
    }

    async fn spawn_server(
        mode: crate::config::ServerMode,
        secret_store: bool,
    ) -> (std::net::SocketAddr, std::path::PathBuf) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "auth-http-{}-{}",
            std::process::id(),
            addr.port()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let cfg = crate::config::Config {
            bind: "127.0.0.1:0".into(),
            db_path: dir.join("auth.db"),
            jwt_secret: "0123456789abcdef-lab-secret".into(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 1_209_600,
            jwt_iss: "command-center-auth".into(),
            jwt_aud: "command-center-desktop".into(),
            allow_register: true,
            login_rate_limit: 50,
            login_rate_window_secs: 300,
            mode,
            secret_store,
        };
        let db = crate::db::Db::open(&cfg.db_path).unwrap();
        let db_path = cfg.db_path.clone();
        let state = AppState {
            db: Arc::new(db),
            cfg: Arc::new(cfg),
            limiter: Arc::new(crate::rate_limit::LoginRateLimiter::default()),
        };
        tokio::spawn(async move {
            axum::serve(
                listener,
                router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        (addr, db_path)
    }

    async fn register(addr: &std::net::SocketAddr, username: &str, password: &str) -> String {
        let body = format!(r#"{{"username":"{username}","password":"{password}"}}"#);
        let response = http(addr, "POST", "/auth/register", None, Some(&body)).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let json = response.split("\r\n\r\n").nth(1).unwrap_or("");
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        value["accessToken"].as_str().unwrap().to_string()
    }

    async fn http(
        addr: &std::net::SocketAddr,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<&str>,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let body = body.unwrap_or("");
        let mut headers = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        if body.is_empty() {
            // Content-Length 0 is fine for GET.
        } else {
            headers.push_str("Content-Type: application/json\r\n");
        }
        if let Some(token) = bearer {
            headers.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        headers.push_str("\r\n");
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(headers.as_bytes()).await.unwrap();
        if !body.is_empty() {
            stream.write_all(body.as_bytes()).await.unwrap();
        }
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_to_end(&mut buf))
            .await;
        String::from_utf8_lossy(&buf).to_string()
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
