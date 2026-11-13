use crate::config::Config;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::{Duration, Utc};
use rand::rngs::OsRng;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
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
            ",
        )?;
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
        conn.execute(
            "INSERT INTO users (id, username, username_norm, password_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, display, norm, password_hash, now],
        )?;
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
        let parsed = PasswordHash::new(&user.password_hash)
            .map_err(|e| DbError::Password(e.to_string()))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
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
