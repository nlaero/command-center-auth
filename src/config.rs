use std::env;
use std::net::IpAddr;
use std::path::PathBuf;

/// `device` listens on this computer only and may store source passwords and API keys.
/// `shared` is a server other Command Center installs can use. It does not store those secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerMode {
    Device,
    Shared,
}

impl ServerMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Shared => "shared",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "shared" => Ok(Self::Shared),
            "device" | "device-only" => Ok(Self::Device),
            other => Err(format!("AUTH_MODE must be device or shared (got {other})")),
        }
    }
}

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
    pub mode: ServerMode,
    /// Source passwords and API keys. Only legal when `mode` is `Device`.
    pub secret_store: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let jwt_secret = env::var("AUTH_JWT_SECRET").unwrap_or_default();
        if jwt_secret.trim().len() < 16 {
            return Err(
                "AUTH_JWT_SECRET must be set to a string of at least 16 characters".into(),
            );
        }

        let mode = ServerMode::parse(&env::var("AUTH_MODE").unwrap_or_default())?;
        let bind = env::var("AUTH_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
        let secret_store = parse_bool("AUTH_SECRET_STORE", false);
        validate_mode(mode, &bind, secret_store)?;

        Ok(Self {
            bind,
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
            // Self-register from Command Center is the product path; false is an emergency lock.
            allow_register: parse_bool("AUTH_ALLOW_REGISTER", true),
            login_rate_limit: parse_u32("AUTH_LOGIN_RATE_LIMIT", 20)?,
            login_rate_window_secs: parse_u64("AUTH_LOGIN_RATE_WINDOW_SECS", 300)?,
            mode,
            secret_store,
        })
    }
}

pub fn validate_mode(mode: ServerMode, bind: &str, secret_store: bool) -> Result<(), String> {
    if secret_store && mode != ServerMode::Device {
        return Err(
            "AUTH_SECRET_STORE is only available when AUTH_MODE=device. A server for other devices does not store passwords or API keys.".into(),
        );
    }
    if mode == ServerMode::Device && !bind_is_loopback(bind) {
        return Err(format!(
            "AUTH_MODE=device only listens on this computer (127.0.0.1 or localhost), not {bind}"
        ));
    }
    Ok(())
}

pub fn bind_host(bind: &str) -> String {
    let bind = bind.trim();
    if let Some(rest) = bind.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host.to_string();
        }
    }
    match bind.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => host.to_string(),
        _ => bind.to_string(),
    }
}

pub fn load_dotenv(path: &std::path::Path) -> std::io::Result<()> {
    let raw = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            if env::var_os(key).is_none() {
                env::set_var(key, value);
            }
        }
    }
    Ok(())
}

pub fn bind_is_loopback(bind: &str) -> bool {
    let host = bind_host(bind);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_mode_stays_on_this_computer() {
        assert!(validate_mode(ServerMode::Device, "127.0.0.1:8080", true).is_ok());
        assert!(validate_mode(ServerMode::Device, "localhost:8080", false).is_ok());
        assert!(validate_mode(ServerMode::Device, "[::1]:8080", false).is_ok());
        assert!(validate_mode(ServerMode::Device, "0.0.0.0:8080", false)
            .unwrap_err()
            .contains("this computer"));
        assert!(validate_mode(ServerMode::Shared, "0.0.0.0:8080", false).is_ok());
        assert!(validate_mode(ServerMode::Shared, "192.168.1.20:8080", true)
            .unwrap_err()
            .contains("AUTH_SECRET_STORE"));
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
