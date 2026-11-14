use crate::config::Config;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::{Duration, Utc};
use rand::rngs::OsRng;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration as StdDuration;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("password hash: {0}")]
    Password(String),
    #[error("username_taken")]
    UsernameTaken,
    #[error("lock poisoned")]
    Lock,
}

#[derive(Clone, Debug)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub username_norm: String,
    pub password_hash: String,
}

/// Server settings login. Not a Command Center board account.
#[derive(Clone, Debug)]
pub struct ServerAdmin {
    pub id: String,
    pub username: String,
    pub username_norm: String,
    pub password_hash: String,
}

#[derive(Clone, Debug)]
pub struct ListedUser {
    pub id: String,
    pub username: String,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct SettingsRow {
    pub revision: i64,
    pub document: String,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub enum SettingsWrite {
    Saved(SettingsRow),
    Conflict(SettingsRow),
    Missing,
}

#[derive(Clone, Debug)]
pub struct RefreshRow {
    pub id: String,
    pub user_id: String,
    pub family_id: String,
    pub token_hash: String,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, DbError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY NOT NULL,
              username TEXT NOT NULL,
              username_norm TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
              id TEXT PRIMARY KEY NOT NULL,
              user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              family_id TEXT NOT NULL,
              token_hash TEXT NOT NULL UNIQUE,
              expires_at INTEGER NOT NULL,
              created_at INTEGER NOT NULL,
              revoked_at INTEGER,
              replaced_by TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
            CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);
            CREATE TABLE IF NOT EXISTS user_settings (
              user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              revision INTEGER NOT NULL,
              document TEXT NOT NULL,
              updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_secrets (
              user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              name TEXT NOT NULL,
              value TEXT NOT NULL,
              updated_at INTEGER NOT NULL,
              PRIMARY KEY (user_id, name)
            );
            CREATE TABLE IF NOT EXISTS server_admin (
              id TEXT PRIMARY KEY NOT NULL,
              username TEXT NOT NULL,
              username_norm TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS server_settings (
              key TEXT PRIMARY KEY NOT NULL,
              value TEXT NOT NULL
            );
            ",
        )?;
        conn.busy_timeout(StdDuration::from_secs(5))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, DbError> {
        self.conn.lock().map_err(|_| DbError::Lock)
    }

    pub fn create_user(&self, username: &str, password: &str) -> Result<UserRow, DbError> {
        let display = username.trim();
        if display.is_empty() {
            return Err(DbError::Password("username required".into()));
        }
        let norm = normalize_username(display);
        let id = Uuid::new_v4().to_string();
        let password_hash = hash_password(password)?;
        let now = Utc::now().timestamp();
        let conn = self.lock()?;
        match conn.execute(
            "INSERT INTO users (id, username, username_norm, password_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, display, norm, password_hash, now],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(info, _))
                if info.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(DbError::UsernameTaken);
            }
            Err(e) => return Err(DbError::Sqlite(e)),
        }
        Ok(UserRow {
            id,
            username: display.to_string(),
            username_norm: norm,
            password_hash,
        })
    }

    pub fn find_user_by_username(&self, username: &str) -> Result<Option<UserRow>, DbError> {
        let norm = normalize_username(username);
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, username, username_norm, password_hash FROM users WHERE username_norm = ?1",
            params![norm],
            |row| {
                Ok(UserRow {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    username_norm: row.get(2)?,
                    password_hash: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(DbError::from)
    }

    pub fn find_user_by_id(&self, id: &str) -> Result<Option<UserRow>, DbError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, username, username_norm, password_hash FROM users WHERE id = ?1",
            params![id],
            |row| {
                Ok(UserRow {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    username_norm: row.get(2)?,
                    password_hash: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(DbError::from)
    }

    pub fn verify_password(user: &UserRow, password: &str) -> Result<bool, DbError> {
        Self::verify_password_hash(&user.password_hash, password)
    }

    pub fn verify_password_hash(hash: &str, password: &str) -> Result<bool, DbError> {
        let parsed = PasswordHash::new(hash).map_err(|e| DbError::Password(e.to_string()))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    /// The server admin can open server settings. It is not a Command Center board login.
    pub fn set_server_admin(&self, username: &str, password: &str) -> Result<ServerAdmin, DbError> {
        let display = username.trim();
        if display.is_empty() {
            return Err(DbError::Password("username required".into()));
        }
        let norm = normalize_username(display);
        let password_hash = hash_password(password)?;
        let now = Utc::now().timestamp();
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let existing: Option<(String, i64)> = tx
            .query_row(
                "SELECT id, created_at FROM server_admin WHERE username_norm = ?1",
                params![norm],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (id, created_at) = existing.unwrap_or_else(|| (Uuid::new_v4().to_string(), now));
        tx.execute("DELETE FROM server_admin", [])?;
        tx.execute(
            "INSERT INTO server_admin (id, username, username_norm, password_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, display, norm, password_hash, created_at],
        )?;
        tx.commit()?;
        Ok(ServerAdmin {
            id,
            username: display.to_string(),
            username_norm: norm,
            password_hash,
        })
    }

    pub fn server_admin(&self) -> Result<Option<ServerAdmin>, DbError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, username, username_norm, password_hash FROM server_admin LIMIT 1",
            [],
            |row| {
                Ok(ServerAdmin {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    username_norm: row.get(2)?,
                    password_hash: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(DbError::from)
    }

    pub fn list_users(&self) -> Result<Vec<ListedUser>, DbError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, username, created_at FROM users ORDER BY username_norm",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ListedUser {
                id: row.get(0)?,
                username: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
    }

    pub fn set_user_password(&self, user_id: &str, password: &str) -> Result<(), DbError> {
        let password_hash = hash_password(password)?;
        let conn = self.lock()?;
        let changed = conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            params![password_hash, user_id],
        )?;
        if changed == 0 {
            return Err(DbError::Password("user not found".into()));
        }
        Ok(())
    }

    pub fn delete_user(&self, user_id: &str) -> Result<bool, DbError> {
        let conn = self.lock()?;
        let changed = conn.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
        Ok(changed > 0)
    }

    pub fn revoke_user_sessions(&self, user_id: &str) -> Result<(), DbError> {
        let now = Utc::now().timestamp();
        let conn = self.lock()?;
        conn.execute(
            "UPDATE refresh_tokens SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL",
            params![now, user_id],
        )?;
        Ok(())
    }

    pub fn setting(&self, key: &str) -> Result<Option<String>, DbError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT value FROM server_settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(DbError::from)
    }

    pub fn setting_bool(&self, key: &str, fallback: bool) -> bool {
        match self.setting(key) {
            Ok(Some(value)) => matches!(value.as_str(), "1" | "true" | "yes" | "on"),
            _ => fallback,
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), DbError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO server_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn issue_refresh(
        &self,
        user_id: &str,
        cfg: &Config,
        family_id: Option<String>,
    ) -> Result<(String, String), DbError> {
        let raw = random_token();
        let token_hash = hash_token(&raw);
        let id = Uuid::new_v4().to_string();
        let family = family_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = Utc::now().timestamp();
        let expires_at = (Utc::now() + Duration::seconds(cfg.refresh_ttl_secs)).timestamp();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO refresh_tokens
             (id, user_id, family_id, token_hash, expires_at, created_at, revoked_at, replaced_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL)",
            params![id, user_id, family, token_hash, expires_at, now],
        )?;
        Ok((raw, family))
    }

    pub fn rotate_refresh(
        &self,
        presented: &str,
        cfg: &Config,
    ) -> Result<(UserRow, String), DbError> {
        let presented_hash = hash_token(presented);
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT id, user_id, family_id, token_hash, expires_at, revoked_at
                 FROM refresh_tokens WHERE token_hash = ?1",
                params![presented_hash],
                |r| {
                    Ok(RefreshRow {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        family_id: r.get(2)?,
                        token_hash: r.get(3)?,
                        expires_at: r.get(4)?,
                        revoked_at: r.get(5)?,
                    })
                },
            )
            .optional()?;

        let Some(existing) = row else {
            return Err(DbError::Password("invalid_token".into()));
        };

        let now = Utc::now().timestamp();
        if existing.revoked_at.is_some() {
            // Reuse detection: revoke the whole family.
            conn.execute(
                "UPDATE refresh_tokens SET revoked_at = ?1
                 WHERE family_id = ?2 AND revoked_at IS NULL",
                params![now, existing.family_id],
            )?;
            return Err(DbError::Password("invalid_token".into()));
        }
        if existing.expires_at < now {
            return Err(DbError::Password("invalid_token".into()));
        }

        let user = conn.query_row(
            "SELECT id, username, username_norm, password_hash FROM users WHERE id = ?1",
            params![existing.user_id],
            |row| {
                Ok(UserRow {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    username_norm: row.get(2)?,
                    password_hash: row.get(3)?,
                })
            },
        )?;

        let new_raw = random_token();
        let new_hash = hash_token(&new_raw);
        let new_id = Uuid::new_v4().to_string();
        let expires_at = (Utc::now() + Duration::seconds(cfg.refresh_ttl_secs)).timestamp();

        conn.execute(
            "UPDATE refresh_tokens SET revoked_at = ?1, replaced_by = ?2 WHERE id = ?3",
            params![now, new_id, existing.id],
        )?;
        conn.execute(
            "INSERT INTO refresh_tokens
             (id, user_id, family_id, token_hash, expires_at, created_at, revoked_at, replaced_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL)",
            params![
                new_id,
                user.id,
                existing.family_id,
                new_hash,
                expires_at,
                now
            ],
        )?;

        Ok((user, new_raw))
    }

    pub fn revoke_refresh(&self, presented: &str) -> Result<(), DbError> {
        let presented_hash = hash_token(presented);
        let now = Utc::now().timestamp();
        let conn = self.lock()?;
        conn.execute(
            "UPDATE refresh_tokens SET revoked_at = ?1
             WHERE token_hash = ?2 AND revoked_at IS NULL",
            params![now, presented_hash],
        )?;
        Ok(())
    }

    pub fn get_settings(&self, user_id: &str) -> Result<Option<SettingsRow>, DbError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT revision, document, updated_at FROM user_settings WHERE user_id = ?1",
            params![user_id],
            settings_row,
        )
        .optional()
        .map_err(DbError::from)
    }

    /// Create when `expected` is `None` and this user has no document.
    /// Update when `expected` matches the stored revision. Otherwise report the current row.
    pub fn put_settings(
        &self,
        user_id: &str,
        expected: Option<i64>,
        document: &str,
    ) -> Result<SettingsWrite, DbError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let existing = tx
            .query_row(
                "SELECT revision, document, updated_at FROM user_settings WHERE user_id = ?1",
                params![user_id],
                settings_row,
            )
            .optional()?;
        let now = Utc::now().timestamp();
        let outcome = match existing {
            None if expected.is_none() => {
                tx.execute(
                    "INSERT INTO user_settings (user_id, revision, document, updated_at)
                     VALUES (?1, 1, ?2, ?3)",
                    params![user_id, document, now],
                )?;
                SettingsWrite::Saved(SettingsRow {
                    revision: 1,
                    document: document.to_string(),
                    updated_at: now,
                })
            }
            Some(row) if expected == Some(row.revision) => {
                let revision = row.revision + 1;
                tx.execute(
                    "UPDATE user_settings
                     SET revision = ?1, document = ?2, updated_at = ?3
                     WHERE user_id = ?4",
                    params![revision, document, now, user_id],
                )?;
                SettingsWrite::Saved(SettingsRow {
                    revision,
                    document: document.to_string(),
                    updated_at: now,
                })
            }
            Some(row) => SettingsWrite::Conflict(row),
            None => SettingsWrite::Missing,
        };
        if matches!(outcome, SettingsWrite::Saved(_)) {
            tx.commit()?;
        }
        Ok(outcome)
    }

    pub fn list_secrets(&self, user_id: &str) -> Result<BTreeMap<String, String>, DbError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT name, value FROM user_secrets WHERE user_id = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map(params![user_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (name, value) = row?;
            out.insert(name, value);
        }
        Ok(out)
    }

    pub fn replace_secrets(
        &self,
        user_id: &str,
        secrets: &BTreeMap<String, String>,
    ) -> Result<(), DbError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM user_secrets WHERE user_id = ?1",
            params![user_id],
        )?;
        let now = Utc::now().timestamp();
        for (name, value) in secrets {
            tx.execute(
                "INSERT INTO user_secrets (user_id, name, value, updated_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![user_id, name, value, now],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn export_snapshot(&self) -> Result<Snapshot, DbError> {
        let conn = self.lock()?;
        let users = {
            let mut stmt = conn.prepare(
                "SELECT id, username, username_norm, password_hash, created_at
                 FROM users ORDER BY username_norm",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(SnapshotUser {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    username_norm: row.get(2)?,
                    password_hash: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let refresh_tokens = {
            let mut stmt = conn.prepare(
                "SELECT id, user_id, family_id, token_hash, expires_at, created_at, revoked_at, replaced_by
                 FROM refresh_tokens ORDER BY created_at",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(SnapshotRefresh {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    family_id: row.get(2)?,
                    token_hash: row.get(3)?,
                    expires_at: row.get(4)?,
                    created_at: row.get(5)?,
                    revoked_at: row.get(6)?,
                    replaced_by: row.get(7)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let settings = {
            let mut stmt = conn.prepare(
                "SELECT user_id, revision, document, updated_at FROM user_settings ORDER BY user_id",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(SnapshotSettings {
                    user_id: row.get(0)?,
                    revision: row.get(1)?,
                    document: row.get(2)?,
                    updated_at: row.get(3)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let secrets = {
            let mut stmt = conn.prepare(
                "SELECT user_id, name, value, updated_at FROM user_secrets ORDER BY user_id, name",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(SnapshotSecret {
                    user_id: row.get(0)?,
                    name: row.get(1)?,
                    value: row.get(2)?,
                    updated_at: row.get(3)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let admins = {
            let mut stmt = conn.prepare(
                "SELECT id, username, username_norm, password_hash, created_at
                 FROM server_admin ORDER BY username_norm",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(SnapshotAdmin {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    username_norm: row.get(2)?,
                    password_hash: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        Ok(Snapshot {
            users,
            refresh_tokens,
            settings,
            secrets,
            admins: Some(admins),
        })
    }

    /// Replace accounts, sessions, boards, and stored secrets with a snapshot.
    pub fn import_snapshot(&self, snapshot: &Snapshot) -> Result<(), DbError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM users", [])?;
        for user in &snapshot.users {
            tx.execute(
                "INSERT INTO users (id, username, username_norm, password_hash, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    user.id,
                    user.username,
                    user.username_norm,
                    user.password_hash,
                    user.created_at
                ],
            )?;
        }
        for token in &snapshot.refresh_tokens {
            tx.execute(
                "INSERT INTO refresh_tokens
                 (id, user_id, family_id, token_hash, expires_at, created_at, revoked_at, replaced_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    token.id,
                    token.user_id,
                    token.family_id,
                    token.token_hash,
                    token.expires_at,
                    token.created_at,
                    token.revoked_at,
                    token.replaced_by
                ],
            )?;
        }
        for row in &snapshot.settings {
            tx.execute(
                "INSERT INTO user_settings (user_id, revision, document, updated_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![row.user_id, row.revision, row.document, row.updated_at],
            )?;
        }
        for secret in &snapshot.secrets {
            tx.execute(
                "INSERT INTO user_secrets (user_id, name, value, updated_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![secret.user_id, secret.name, secret.value, secret.updated_at],
            )?;
        }
        if let Some(admins) = &snapshot.admins {
            tx.execute("DELETE FROM server_admin", [])?;
            for admin in admins {
                tx.execute(
                    "INSERT INTO server_admin (id, username, username_norm, password_hash, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        admin.id,
                        admin.username,
                        admin.username_norm,
                        admin.password_hash,
                        admin.created_at
                    ],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub users: Vec<SnapshotUser>,
    pub refresh_tokens: Vec<SnapshotRefresh>,
    pub settings: Vec<SnapshotSettings>,
    pub secrets: Vec<SnapshotSecret>,
    /// `None` means this backup did not mention the server admin, so import leaves it alone.
    pub admins: Option<Vec<SnapshotAdmin>>,
}

#[derive(Clone, Debug)]
pub struct SnapshotUser {
    pub id: String,
    pub username: String,
    pub username_norm: String,
    pub password_hash: String,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct SnapshotRefresh {
    pub id: String,
    pub user_id: String,
    pub family_id: String,
    pub token_hash: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub replaced_by: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SnapshotSettings {
    pub user_id: String,
    pub revision: i64,
    pub document: String,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct SnapshotSecret {
    pub user_id: String,
    pub name: String,
    pub value: String,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct SnapshotAdmin {
    pub id: String,
    pub username: String,
    pub username_norm: String,
    pub password_hash: String,
    pub created_at: i64,
}

fn settings_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SettingsRow> {
    Ok(SettingsRow {
        revision: row.get(0)?,
        document: row.get(1)?,
        updated_at: row.get(2)?,
    })
}

pub fn normalize_username(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

fn hash_password(password: &str) -> Result<String, DbError> {
    if password.len() < 8 {
        return Err(DbError::Password(
            "password must be at least 8 characters".into(),
        ));
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| DbError::Password(e.to_string()))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    hex::encode(bytes)
}

fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (Db, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "auth-settings-{}-{}.db",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let db = Db::open(&path).unwrap();
        (db, path)
    }

    #[test]
    fn settings_create_conflict_and_update() {
        let (db, path) = temp_db();
        let user = db.create_user("ada", "correct-password").unwrap();
        assert!(db.get_settings(&user.id).unwrap().is_none());

        let missing = db.put_settings(&user.id, Some(1), r#"{"title":"x"}"#).unwrap();
        assert!(matches!(missing, SettingsWrite::Missing));

        let created = db
            .put_settings(&user.id, None, r#"{"title":"Ops"}"#)
            .unwrap();
        let SettingsWrite::Saved(row) = created else {
            panic!("expected create");
        };
        assert_eq!(row.revision, 1);

        let stale = db
            .put_settings(&user.id, None, r#"{"title":"Other"}"#)
            .unwrap();
        let SettingsWrite::Conflict(current) = stale else {
            panic!("expected conflict");
        };
        assert_eq!(current.revision, 1);
        assert!(current.document.contains("Ops"));

        let updated = db
            .put_settings(&user.id, Some(1), r#"{"title":"Local"}"#)
            .unwrap();
        let SettingsWrite::Saved(row) = updated else {
            panic!("expected update");
        };
        assert_eq!(row.revision, 2);
        let stored = db.get_settings(&user.id).unwrap().unwrap();
        assert_eq!(stored.revision, 2);
        assert!(stored.document.contains("Local"));

        let err = db.put_settings("missing-user", None, "{}").unwrap_err();
        assert!(matches!(err, DbError::Sqlite(_)));
        let _ = fs::remove_file(path);
    }
}
