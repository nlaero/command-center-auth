use std::env;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: String,
    pub db_path: PathBuf,
    pub jwt_secret: String,
    pub access_ttl_secs: i64,
    pub refresh_ttl_secs: i64,
    pub jwt_iss: String,
    pub jwt_aud: String,
    pub allow_register: bool,
    pub login_rate_limit: u32,
    pub login_rate_window_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let jwt_secret = env::var("AUTH_JWT_SECRET").unwrap_or_default();
        if jwt_secret.trim().len() < 16 {
            return Err(
                "AUTH_JWT_SECRET must be set to a string of at least 16 characters".into(),
            );
        }

        Ok(Self {
            bind: env::var("AUTH_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into()),
            db_path: PathBuf::from(
                env::var("AUTH_DB").unwrap_or_else(|_| "./data/auth-server.db".into()),
            ),
            jwt_secret,
            access_ttl_secs: parse_i64("AUTH_ACCESS_TTL_SECS", 900)?,
            refresh_ttl_secs: parse_i64("AUTH_REFRESH_TTL_SECS", 1_209_600)?,
            jwt_iss: env::var("AUTH_JWT_ISS")
                .unwrap_or_else(|_| "command-center-auth".into()),
            jwt_aud: env::var("AUTH_JWT_AUD")
                .unwrap_or_else(|_| "command-center-desktop".into()),
            allow_register: parse_bool("AUTH_ALLOW_REGISTER", false),
            login_rate_limit: parse_u32("AUTH_LOGIN_RATE_LIMIT", 20)?,
            login_rate_window_secs: parse_u64("AUTH_LOGIN_RATE_WINDOW_SECS", 300)?,
        })
    }
}

fn parse_i64(key: &str, default: i64) -> Result<i64, String> {
    match env::var(key) {
        Ok(v) => v
            .parse()
            .map_err(|_| format!("{key} must be an integer")),
        Err(_) => Ok(default),
    }
}

fn parse_u32(key: &str, default: u32) -> Result<u32, String> {
    match env::var(key) {
        Ok(v) => v
            .parse()
            .map_err(|_| format!("{key} must be an unsigned integer")),
        Err(_) => Ok(default),
    }
}

fn parse_u64(key: &str, default: u64) -> Result<u64, String> {
    match env::var(key) {
        Ok(v) => v
            .parse()
            .map_err(|_| format!("{key} must be an unsigned integer")),
        Err(_) => Ok(default),
    }
}

fn parse_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}
