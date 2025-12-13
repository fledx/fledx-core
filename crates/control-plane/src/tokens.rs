use rand::Rng;
use subtle::ConstantTimeEq;

use crate::Result;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sha2::{Digest, Sha256};

/// How a stored hash matched the provided token.
pub enum TokenMatch {
    /// Matched an argon2 hash.
    Argon2,
    /// Matched the legacy SHA-256 hash (no pepper).
    Legacy,
}

/// Generate a random bearer token.
pub fn generate_token() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..48)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Hash a token using argon2id and a pepper.
pub fn hash_token(token: &str, pepper: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let password = format!("{token}{pepper}");
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| anyhow::anyhow!("failed to hash token: {}", err))?
        .to_string())
}

/// Try to match a provided token against the stored hash.
pub fn match_token(token: &str, stored_hash: &str, pepper: &str) -> Result<Option<TokenMatch>> {
    if verify_argon2(token, stored_hash, pepper)? {
        return Ok(Some(TokenMatch::Argon2));
    }

    if verify_legacy(token, stored_hash) {
        return Ok(Some(TokenMatch::Legacy));
    }

    Ok(None)
}

/// Legacy SHA-256 hashing used before argon2 support.
pub fn legacy_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn verify_argon2(token: &str, stored_hash: &str, pepper: &str) -> Result<bool> {
    let password = format!("{token}{pepper}");
    let Ok(password_hash) = PasswordHash::new(stored_hash) else {
        return Ok(false);
    };

    let result = Argon2::default()
        .verify_password(password.as_bytes(), &password_hash)
        .map(|_| true)
        .unwrap_or_else(|_| false);

    Ok(result)
}

fn verify_legacy(token: &str, stored_hash: &str) -> bool {
    let expected = legacy_hash(token);
    let matches = expected.len() == stored_hash.len()
        && expected.as_bytes().ct_eq(stored_hash.as_bytes()).into();
    matches
}
