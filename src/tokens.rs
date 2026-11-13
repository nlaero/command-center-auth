use crate::config::Config;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    pub username: String,
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("jwt: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

pub fn issue_access(cfg: &Config, user_id: &str, username: &str) -> Result<String, TokenError> {
    let now = Utc::now();
    let claims = AccessClaims {
        sub: user_id.to_string(),
        username: username.to_string(),
        iss: cfg.jwt_iss.clone(),
        aud: cfg.jwt_aud.clone(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(cfg.access_ttl_secs)).timestamp(),
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )?)
}

pub fn verify_access(cfg: &Config, token: &str) -> Result<AccessClaims, TokenError> {
    let mut validation = Validation::default();
    validation.set_audience(&[cfg.jwt_aud.clone()]);
    validation.set_issuer(&[cfg.jwt_iss.clone()]);
    let data = decode::<AccessClaims>(
        token,
        &DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        &validation,
    )?;
    Ok(data.claims)
}
