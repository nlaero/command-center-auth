//! Layout for a server installed on this computer (by the desktop app or the Windows setup).
//!
//! Writes `server/.env`, `server/install.json`, and a start script under the Command Center
//! home directory. An existing JWT secret is kept so a second run does not sign everyone out.

use crate::config::{validate_mode, ServerMode};
use crate::db::Db;
use crate::platform::{self, StartupMode};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

pub struct InstallRequest {
    pub home: PathBuf,
    pub role: ServerMode,
    pub secret_store: bool,
    pub port: u16,
    pub autostart: bool,
    pub startup: StartupMode,
    pub exe: PathBuf,
    /// Server settings account. Not a Command Center board login.
    pub admin_username: Option<String>,
    pub admin_password: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Marker {
    role: String,
    secret_store: bool,
    port: u16,
    bind: String,
    base_url: String,
    startup: String,
}

pub fn install(req: &InstallRequest) -> Result<PathBuf, String> {
    if req.port == 0 {
        return Err("port must be between 1 and 65535".into());
    }
    if req.secret_store && req.role != ServerMode::Device {
        return Err(
            "A server for other devices does not store passwords or API keys.".into(),
        );
    }
    let bind = match req.role {
        ServerMode::Device => format!("127.0.0.1:{}", req.port),
        ServerMode::Shared => format!("0.0.0.0:{}", req.port),
    };
    validate_mode(req.role, &bind, req.secret_store)?;

    let server_dir = req.home.join("server");
    let data_dir = server_dir.join("data");
    fs::create_dir_all(&data_dir)
        .map_err(|err| format!("could not create {}: {err}", data_dir.display()))?;

    let env_path = server_dir.join(".env");
    let existing = fs::read_to_string(&env_path).unwrap_or_default();
    let jwt = env_get(&existing, "AUTH_JWT_SECRET").unwrap_or_else(random_secret);
    if jwt.trim().len() < 16 {
        return Err("existing AUTH_JWT_SECRET is too short to keep".into());
    }
    let db_path = env_get(&existing, "AUTH_DB")
        .unwrap_or_else(|| data_dir.join("auth-server.db").display().to_string());
    let body = format!(
        "\
# Written by auth-server --install. The JWT secret stays put across reinstalls.\n\
AUTH_BIND={bind}\n\
AUTH_DB={db_path}\n\
AUTH_JWT_SECRET={jwt}\n\
AUTH_MODE={mode}\n\
AUTH_SECRET_STORE={secrets}\n\
AUTH_ALLOW_REGISTER=true\n\
",
        mode = req.role.as_str(),
        secrets = if req.secret_store { "true" } else { "false" },
    );
    fs::write(&env_path, &body).map_err(|err| format!("could not write {}: {err}", env_path.display()))?;

    let marker = Marker {
        role: req.role.as_str().into(),
        secret_store: req.secret_store,
        port: req.port,
        bind,
        base_url: format!("http://127.0.0.1:{}", req.port),
        startup: req.startup.as_str().into(),
    };
    let marker_path = server_dir.join("install.json");
    fs::write(
        &marker_path,
        serde_json::to_string_pretty(&marker).map_err(|err| err.to_string())?,
    )
    .map_err(|err| format!("could not write {}: {err}", marker_path.display()))?;

    write_launcher(&server_dir, &req.exe, &req.home)?;
    let db = Db::open(Path::new(&db_path)).map_err(|err| format!("could not open the database: {err}"))?;
    db.set_setting("secret_store", if req.secret_store { "true" } else { "false" })
        .map_err(|err| err.to_string())?;
    match (&req.admin_username, &req.admin_password) {
        (Some(username), Some(password)) if !username.trim().is_empty() => {
            db.set_server_admin(username, password)
                .map_err(|err| format!("could not create the server admin: {err}"))?;
        }
        _ => {
            if db.server_admin().map_err(|err| err.to_string())?.is_none() {
                return Err(
                    "Create a server admin during install. This account is for the server and its settings, not a Command Center board login.".into(),
                );
            }
        }
    }
    if req.autostart {
        if let Err(err) = platform::register_startup(req.startup, &req.exe, &req.home, &server_dir) {
            eprintln!("auth-server startup was not registered: {err}");
        }
    }
    Ok(server_dir)
}

pub fn uninstall(home: &Path) -> Result<(), String> {
    platform::unregister_startup()?;
    let _ = home;
    Ok(())
}

pub fn read_startup(db_path: &Path) -> Option<String> {
    let marker = db_path.parent()?.parent()?.join("install.json");
    let raw = fs::read_to_string(marker).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    value.get("startup")?.as_str().map(str::to_string)
}

pub fn switch_startup(db_path: &Path, exe: &Path, startup: StartupMode) -> Result<(), String> {
    let server_dir = db_path
        .parent()
        .and_then(|path| path.parent())
        .ok_or("could not find the server directory")?
        .to_path_buf();
    let marker_path = server_dir.join("install.json");
    let raw = fs::read_to_string(&marker_path)
        .map_err(|_| "This server was not installed with setup, so its startup cannot be changed here.".to_string())?;
    let mut value: serde_json::Value = serde_json::from_str(&raw).map_err(|err| err.to_string())?;
    value["startup"] = serde_json::Value::String(startup.as_str().into());
    fs::write(&marker_path, serde_json::to_string_pretty(&value).map_err(|err| err.to_string())?)
        .map_err(|err| err.to_string())?;
    let home = server_dir
        .parent()
        .ok_or("could not find the Command Center home directory")?;
    platform::register_startup(startup, exe, home, &server_dir)
}

pub fn set_env_value(db_path: &Path, key: &str, value: &str) -> Result<(), String> {
    let Some(server_dir) = db_path.parent().and_then(|path| path.parent()) else {
        return Ok(());
    };
    let env_path = server_dir.join(".env");
    if !env_path.is_file() {
        return Ok(());
    }
    let existing = fs::read_to_string(&env_path).unwrap_or_default();
    let mut lines: Vec<String> = Vec::new();
    let mut found = false;
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.contains('=') {
            lines.push(line.to_string());
            continue;
        }
        let (name, _) = trimmed.split_once('=').unwrap();
        if name.trim() == key {
            lines.push(format!("{key}={value}"));
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !found {
        lines.push(format!("{key}={value}"));
    }
    fs::write(&env_path, lines.join("\n") + "\n").map_err(|err| err.to_string())
}

pub fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    RngCore::fill_bytes(&mut OsRng, &mut bytes);
    hex::encode(bytes)
}

fn env_get(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() == key {
            let value = value.trim().trim_matches('"').to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn write_launcher(server_dir: &Path, exe: &Path, home: &Path) -> Result<(), String> {
    let script = launcher_script(exe, home);
    let path = server_dir.join(launcher_name());
    fs::write(&path, script).map_err(|err| format!("could not write {}: {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path).map_err(|err| err.to_string())?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).map_err(|err| err.to_string())?;
    }
    Ok(())
}

#[cfg(windows)]
fn launcher_name() -> &'static str {
    "start-auth-server.cmd"
}

#[cfg(not(windows))]
fn launcher_name() -> &'static str {
    "start-auth-server.sh"
}

#[cfg(windows)]
fn launcher_script(exe: &Path, home: &Path) -> String {
    format!(
        "@echo off\r\ncd /d \"%~dp0\"\r\n\"{exe}\" --tray --home \"{home}\"\r\n",
        exe = exe.display(),
        home = home.display(),
    )
}

#[cfg(not(windows))]
fn launcher_script(exe: &Path, home: &Path) -> String {
    format!(
        "#!/bin/sh\ncd \"$(dirname \"$0\")\" || exit 1\nexec \"{exe}\" --tray --home \"{home}\"\n",
        exe = exe.display(),
        home = home.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_install_keeps_the_jwt_and_shared_refuses_secrets() {
        let home = std::env::temp_dir().join(format!(
            "auth-install-{}",
            UtcStamp::now()
        ));
        let _ = fs::remove_dir_all(&home);
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("auth-server"));
        let dir = install(&InstallRequest {
            home: home.clone(),
            role: ServerMode::Device,
            secret_store: true,
            port: 8080,
            autostart: false,
            startup: StartupMode::Login,
            exe: exe.clone(),
            admin_username: Some("server-admin".into()),
            admin_password: Some("server-admin-pass".into()),
        })
        .unwrap();
        let db = Db::open(&dir.join("data").join("auth-server.db")).unwrap();
        let admin = db.server_admin().unwrap().unwrap();
        assert_eq!(admin.username, "server-admin");
        assert!(Db::verify_password_hash(&admin.password_hash, "server-admin-pass").unwrap());
        assert!(db.find_user_by_username("server-admin").unwrap().is_none());
        let env = fs::read_to_string(dir.join(".env")).unwrap();
        assert!(env.contains("AUTH_BIND=127.0.0.1:8080"));
        assert!(env.contains("AUTH_MODE=device"));
        assert!(env.contains("AUTH_SECRET_STORE=true"));
        let jwt = env_get(&env, "AUTH_JWT_SECRET").unwrap();
        let again = install(&InstallRequest {
            home: home.clone(),
            role: ServerMode::Device,
            secret_store: false,
            port: 8090,
            autostart: false,
            startup: StartupMode::Service,
            exe,
            admin_username: None,
            admin_password: None,
        })
        .unwrap();
        let env = fs::read_to_string(again.join(".env")).unwrap();
        assert_eq!(env_get(&env, "AUTH_JWT_SECRET").as_deref(), Some(jwt.as_str()));
        assert!(env.contains("AUTH_BIND=127.0.0.1:8090"));
        assert!(env.contains("AUTH_SECRET_STORE=false"));
        let marker: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(again.join("install.json")).unwrap()).unwrap();
        assert_eq!(marker["baseUrl"], "http://127.0.0.1:8090");
        assert_eq!(marker["role"], "device");
        assert_eq!(marker["startup"], "service");
        let kept = Db::open(&again.join("data").join("auth-server.db")).unwrap();
        assert_eq!(kept.server_admin().unwrap().unwrap().username, "server-admin");

        let err = install(&InstallRequest {
            home: home.join("shared"),
            role: ServerMode::Shared,
            secret_store: true,
            port: 8080,
            autostart: false,
            startup: StartupMode::Login,
            exe: PathBuf::from("auth-server"),
            admin_username: Some("server-admin".into()),
            admin_password: Some("server-admin-pass".into()),
        })
        .unwrap_err();
        assert!(err.contains("does not store"));
        let _ = fs::remove_dir_all(home);
    }

    struct UtcStamp;
    impl UtcStamp {
        fn now() -> String {
            format!(
                "{}-{}",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            )
        }
    }
}
