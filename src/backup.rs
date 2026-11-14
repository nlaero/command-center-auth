//! Versioned backup of accounts, sessions, boards, and any device-only secrets.
//!
//! The file is JSON. Password hashes are included so a restore can sign in again.
//! Account passwords are not stored in the clear. Source passwords and API keys are
//! included only when this server was storing them.

use crate::db::{
    Db, Snapshot, SnapshotAdmin, SnapshotRefresh, SnapshotSecret, SnapshotSettings, SnapshotUser,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const FORMAT: &str = "command-center-auth-backup";
pub const VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackupFile {
    pub format: String,
    pub version: u32,
    pub exported_at: i64,
    pub users: Vec<BackupUser>,
    pub refresh_tokens: Vec<BackupRefresh>,
    pub settings: Vec<BackupSettings>,
    pub secrets: Vec<BackupSecret>,
    /// Caption fixes for the local AI. Missing on backups from before that existed.
    #[serde(default)]
    pub ai_memory: Option<Vec<BackupSettings>>,
    /// Missing on older backups. Import then leaves the server admin account alone.
    #[serde(default)]
    pub server_admins: Option<Vec<BackupAdmin>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackupAdmin {
    pub id: String,
    pub username: String,
    pub username_norm: String,
    pub password_hash: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackupUser {
    pub id: String,
    pub username: String,
    pub username_norm: String,
    pub password_hash: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackupRefresh {
    pub id: String,
    pub user_id: String,
    pub family_id: String,
    pub token_hash: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub replaced_by: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackupSettings {
    pub user_id: String,
    pub revision: i64,
    pub document: String,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackupSecret {
    pub user_id: String,
    pub name: String,
    pub value: String,
    pub updated_at: i64,
}

pub fn export_string(db: &Db) -> Result<String, String> {
    let snapshot = db.export_snapshot().map_err(|err| err.to_string())?;
    let file = BackupFile::from_snapshot(snapshot);
    serde_json::to_string_pretty(&file).map_err(|err| err.to_string())
}

pub fn export_path(db: &Db, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
    }
    let body = export_string(db)?;
    fs::write(path, body).map_err(|err| format!("could not write {}: {err}", path.display()))
}

pub fn import_str(db: &Db, raw: &str) -> Result<(), String> {
    let file: BackupFile =
        serde_json::from_str(raw).map_err(|err| format!("backup is not valid JSON: {err}"))?;
    file.validate()?;
    let snapshot = file.into_snapshot();
    db.import_snapshot(&snapshot).map_err(|err| err.to_string())
}

pub fn import_path(db: &Db, path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("could not read {}: {err}", path.display()))?;
    import_str(db, &raw)
}

impl BackupFile {
    fn from_snapshot(snapshot: Snapshot) -> Self {
        Self {
            format: FORMAT.into(),
            version: VERSION,
            exported_at: Utc::now().timestamp(),
            users: snapshot
                .users
                .into_iter()
                .map(|user| BackupUser {
                    id: user.id,
                    username: user.username,
                    username_norm: user.username_norm,
                    password_hash: user.password_hash,
                    created_at: user.created_at,
                })
                .collect(),
            refresh_tokens: snapshot
                .refresh_tokens
                .into_iter()
                .map(|token| BackupRefresh {
                    id: token.id,
                    user_id: token.user_id,
                    family_id: token.family_id,
                    token_hash: token.token_hash,
                    expires_at: token.expires_at,
                    created_at: token.created_at,
                    revoked_at: token.revoked_at,
                    replaced_by: token.replaced_by,
                })
                .collect(),
            settings: snapshot
                .settings
                .into_iter()
                .map(|row| BackupSettings {
                    user_id: row.user_id,
                    revision: row.revision,
                    document: row.document,
                    updated_at: row.updated_at,
                })
                .collect(),
            secrets: snapshot
                .secrets
                .into_iter()
                .map(|secret| BackupSecret {
                    user_id: secret.user_id,
                    name: secret.name,
                    value: secret.value,
                    updated_at: secret.updated_at,
                })
                .collect(),
            ai_memory: Some(
                snapshot
                    .ai_memory
                    .into_iter()
                    .map(|row| BackupSettings {
                        user_id: row.user_id,
                        revision: row.revision,
                        document: row.document,
                        updated_at: row.updated_at,
                    })
                    .collect(),
            ),
            server_admins: snapshot.admins.map(|admins| {
                admins
                    .into_iter()
                    .map(|admin| BackupAdmin {
                        id: admin.id,
                        username: admin.username,
                        username_norm: admin.username_norm,
                        password_hash: admin.password_hash,
                        created_at: admin.created_at,
                    })
                    .collect()
            }),
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.format != FORMAT {
            return Err(format!(
                "not a Command Center auth-server backup ({})",
                self.format
            ));
        }
        if self.version != VERSION {
            return Err(format!(
                "backup version {} is not supported (this server reads version {VERSION})",
                self.version
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for user in &self.users {
            if user.id.is_empty() || user.username_norm.is_empty() || user.password_hash.is_empty()
            {
                return Err("backup user is missing an id, username, or password hash".into());
            }
            if !ids.insert(user.id.clone()) {
                return Err(format!("backup has two users with id {}", user.id));
            }
        }
        if let Some(admins) = &self.server_admins {
            for admin in admins {
                if admin.id.is_empty()
                    || admin.username_norm.is_empty()
                    || admin.password_hash.is_empty()
                {
                    return Err(
                        "backup server admin is missing an id, username, or password hash".into(),
                    );
                }
            }
        }
        Ok(())
    }

    fn into_snapshot(self) -> Snapshot {
        Snapshot {
            users: self
                .users
                .into_iter()
                .map(|user| SnapshotUser {
                    id: user.id,
                    username: user.username,
                    username_norm: user.username_norm,
                    password_hash: user.password_hash,
                    created_at: user.created_at,
                })
                .collect(),
            refresh_tokens: self
                .refresh_tokens
                .into_iter()
                .map(|token| SnapshotRefresh {
                    id: token.id,
                    user_id: token.user_id,
                    family_id: token.family_id,
                    token_hash: token.token_hash,
                    expires_at: token.expires_at,
                    created_at: token.created_at,
                    revoked_at: token.revoked_at,
                    replaced_by: token.replaced_by,
                })
                .collect(),
            settings: self
                .settings
                .into_iter()
                .map(|row| SnapshotSettings {
                    user_id: row.user_id,
                    revision: row.revision,
                    document: row.document,
                    updated_at: row.updated_at,
                })
                .collect(),
            secrets: self
                .secrets
                .into_iter()
                .map(|secret| SnapshotSecret {
                    user_id: secret.user_id,
                    name: secret.name,
                    value: secret.value,
                    updated_at: secret.updated_at,
                })
                .collect(),
            ai_memory: self
                .ai_memory
                .unwrap_or_default()
                .into_iter()
                .map(|row| SnapshotSettings {
                    user_id: row.user_id,
                    revision: row.revision,
                    document: row.document,
                    updated_at: row.updated_at,
                })
                .collect(),
            admins: self.server_admins.map(|admins| {
                admins
                    .into_iter()
                    .map(|admin| SnapshotAdmin {
                        id: admin.id,
                        username: admin.username,
                        username_norm: admin.username_norm,
                        password_hash: admin.password_hash,
                        created_at: admin.created_at,
                    })
                    .collect()
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn temp_db() -> (Db, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "auth-backup-{}-{}.db",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let db = Db::open(&path).unwrap();
        (db, path)
    }

    #[test]
    fn export_import_keeps_login_boards_and_secrets() {
        let (db, path) = temp_db();
        let user = db.create_user("Ada", "correct-password").unwrap();
        db.put_settings(&user.id, None, r#"{"title":"Ops"}"#)
            .unwrap();
        db.put_ai_memory(
            &user.id,
            None,
            r#"{"version":1,"corrections":[{"id":"c1","heard":"engine twelve","says":"Engine 12","count":1}]}"#,
        )
        .unwrap();
        let mut secrets = BTreeMap::new();
        secrets.insert("broadcastify.password".into(), "feed-secret".into());
        secrets.insert("socrata.app_token".into(), "token-1".into());
        db.replace_secrets(&user.id, &secrets).unwrap();
        db.set_server_admin("server-admin", "server-admin-pass")
            .unwrap();

        let raw = export_string(&db).unwrap();
        assert!(raw.contains("command-center-auth-backup"));
        assert!(raw.contains("feed-secret"));
        assert!(raw.contains("serverAdmins"));
        assert!(raw.contains("Engine 12"));
        assert!(!raw.contains("correct-password"));
        assert!(!raw.contains("server-admin-pass"));

        let (other, other_path) = temp_db();
        other.create_user("gone", "other-password").unwrap();
        import_str(&other, &raw).unwrap();

        let restored = other.find_user_by_username("ada").unwrap().unwrap();
        assert!(Db::verify_password(&restored, "correct-password").unwrap());
        assert!(other.find_user_by_username("gone").unwrap().is_none());
        let settings = other.get_settings(&restored.id).unwrap().unwrap();
        assert!(settings.document.contains("Ops"));
        let memory = other.get_ai_memory(&restored.id).unwrap().unwrap();
        assert!(memory.document.contains("Engine 12"));
        assert_eq!(memory.revision, 1);
        assert_eq!(settings.revision, 1);
        let stored = other.list_secrets(&restored.id).unwrap();
        assert_eq!(
            stored.get("broadcastify.password").map(String::as_str),
            Some("feed-secret")
        );
        assert_eq!(
            stored.get("socrata.app_token").map(String::as_str),
            Some("token-1")
        );
        let restored_admin = other.server_admin().unwrap().unwrap();
        assert_eq!(restored_admin.username, "server-admin");
        assert!(
            Db::verify_password_hash(&restored_admin.password_hash, "server-admin-pass").unwrap()
        );
        assert!(other
            .find_user_by_username("server-admin")
            .unwrap()
            .is_none());

        let mut old: serde_json::Value = serde_json::from_str(&raw).unwrap();
        old.as_object_mut().unwrap().remove("serverAdmins");
        old.as_object_mut().unwrap().remove("aiMemory");
        other
            .set_server_admin("keep-me", "keep-me-password")
            .unwrap();
        import_str(&other, &serde_json::to_string(&old).unwrap()).unwrap();
        assert_eq!(other.server_admin().unwrap().unwrap().username, "keep-me");
        assert!(other.get_ai_memory(&restored.id).unwrap().is_none());

        let bad = r#"{"format":"nope","version":1,"exportedAt":0,"users":[],"refreshTokens":[],"settings":[],"secrets":[]}"#;
        assert!(import_str(&other, bad)
            .unwrap_err()
            .contains("not a Command Center"));

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(other_path);
    }
}
