//! Cryptographic password generation module
//!
//! This module provides deterministic password generation using multiple algorithms.
//! Given the same salt and feature identifier, it will always produce the same password.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};

type HmacSha256 = Hmac<Sha256>;

/// Password generation algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Algorithm {
    /// HMAC-SHA256 (fast, suitable for password generation)
    #[default]
    HmacSha256,
    /// Argon2i (memory-hard, slower)
    Argon2i,
    /// Argon2id (hybrid mode)
    Argon2id,
    /// Pbkdf2-SHA256
    Pbkdf2,
    /// Scrypt (memory-hard)
    Scrypt,
}

impl Algorithm {
    pub fn name(&self) -> &str {
        match self {
            Algorithm::HmacSha256 => "HMAC-SHA256",
            Algorithm::Argon2i => "Argon2i",
            Algorithm::Argon2id => "Argon2id",
            Algorithm::Pbkdf2 => "PBKDF2",
            Algorithm::Scrypt => "Scrypt",
        }
    }

    pub fn all() -> &'static [Algorithm] {
        &[
            Algorithm::HmacSha256,
            Algorithm::Argon2i,
            Algorithm::Argon2id,
            Algorithm::Pbkdf2,
            Algorithm::Scrypt,
        ]
    }
}

/// Password generator using any hash algorithm
pub struct PasswordGenerator;

impl PasswordGenerator {
    /// Generate a deterministic password from salt and feature identifier
    ///
    /// # Arguments
    ///
    /// * `salt` - Master salt (stored in memory only)
    /// * `feature` - Feature identifier (e.g., "github.com")
    /// * `length` - Desired password length (clamped between 12-64)
    ///
    /// # Returns
    ///
    /// A strong password containing uppercase, lowercase, digits, and special characters
    ///
    /// # Examples
    ///
    /// ```
    /// use SaltPass::crypto::{PasswordGenerator, Algorithm};
    ///
    /// let password = PasswordGenerator::generate_with_algo("my-secret-salt", "github.com", 16, Algorithm::HmacSha256);
    /// assert_eq!(password.len(), 16);
    /// ```
    pub fn generate(salt: &str, feature: &str, length: usize) -> String {
        Self::generate_with_algo(salt, feature, length, Algorithm::HmacSha256)
    }

    /// Generate a password using a specific algorithm
    pub fn generate_with_algo(salt: &str, feature: &str, length: usize, algo: Algorithm) -> String {
        let bytes = match algo {
            Algorithm::HmacSha256 => Self::derive_hmac_sha256(salt, feature),
            Algorithm::Argon2i => Self::derive_argon2(salt, feature, argon2::Algorithm::Argon2i),
            Algorithm::Argon2id => Self::derive_argon2(salt, feature, argon2::Algorithm::Argon2id),
            Algorithm::Pbkdf2 => Self::derive_pbkdf2(salt, feature),
            Algorithm::Scrypt => Self::derive_scrypt(salt, feature),
        };

        let base64_encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);

        Self::format_password(&base64_encoded, length)
    }

    fn derive_hmac_sha256(salt: &str, feature: &str) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(salt.as_bytes()).expect("HMAC can take key of any size");
        mac.update(feature.as_bytes());
        let result = mac.finalize();
        *result.into_bytes().as_ref()
    }

    fn derive_argon2(salt: &str, feature: &str, alg: argon2::Algorithm) -> [u8; 32] {
        use argon2::{Argon2, Version, Params};
        let params = Params::new(65536, 1, 1, None).unwrap();
        let argon2 = Argon2::new(alg, Version::V0x13, params);
        let mut output = [0u8; 32];
        argon2.hash_password_into(feature.as_bytes(), salt.as_bytes(), &mut output).unwrap();
        output
    }

    fn derive_pbkdf2(salt: &str, feature: &str) -> [u8; 32] {
        use sha2::Sha256;
        use pbkdf2::pbkdf2_hmac;

        let mut output = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            feature.as_bytes(),
            salt.as_bytes(),
            10000,
            &mut output
        );
        output
    }

    fn derive_scrypt(salt: &str, feature: &str) -> [u8; 32] {
        use scrypt::{scrypt, Params};

        // Params::new(log_n, r, p, output_length)
        let params = Params::new(15, 8, 1, 32).unwrap();
        let mut output = [0u8; 32];
        scrypt(
            feature.as_bytes(),
            salt.as_bytes(),
            &params,
            &mut output
        ).expect("scrypt failed");
        output
    }

    fn format_password(raw: &str, length: usize) -> String {
        let length = length.clamp(12, 64);

        let mut password = String::new();
        let chars: Vec<char> = raw.chars().collect();

        let mut idx = 0;
        let mut has_upper = false;
        let mut has_digit = false;
        let mut has_special = false;

        for ch in chars.iter() {
            if password.len() >= length {
                break;
            }

            let processed = match ch {
                'A'..='Z' => {
                    has_upper = true;
                    Some(*ch)
                }
                'a'..='z' => Some(*ch),
                '0'..='9' => {
                    has_digit = true;
                    Some(*ch)
                }
                '+' | '/' | '=' => {
                    has_special = true;
                    Some(Self::map_special(*ch, idx))
                }
                _ => None,
            };

            if let Some(c) = processed {
                password.push(c);
                idx += 1;
            }
        }

        if !has_upper
            && !password.is_empty()
            && let Some(first) = password.chars().next()
        {
            password = format!("{}{}", first.to_uppercase(), &password[1..]);
        }

        if !has_digit && password.len() > 1 {
            let digit = (idx % 10).to_string();
            password.replace_range(1..2, &digit);
        }

        if !has_special && password.len() > 2 {
            password.replace_range(2..3, "!");
        }

        password.truncate(length);
        password
    }

    fn map_special(ch: char, idx: usize) -> char {
        let specials = ['!', '@', '#', '$', '%', '^', '&', '*'];
        match ch {
            '+' => specials[idx % specials.len()],
            '/' => specials[(idx + 1) % specials.len()],
            '=' => specials[(idx + 2) % specials.len()],
            _ => '!',
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_generation() {
        let salt = "my-secret-salt";
        let feature = "github.com";

        let pwd1 = PasswordGenerator::generate(salt, feature, 16);
        let pwd2 = PasswordGenerator::generate(salt, feature, 16);

        assert_eq!(pwd1, pwd2, "Same inputs should produce same password");
    }

    #[test]
    fn test_different_features() {
        let salt = "my-secret-salt";

        let pwd1 = PasswordGenerator::generate(salt, "github.com", 16);
        let pwd2 = PasswordGenerator::generate(salt, "google.com", 16);

        assert_ne!(
            pwd1, pwd2,
            "Different features should produce different passwords"
        );
    }

    #[test]
    fn test_different_salts() {
        let feature = "github.com";

        let pwd1 = PasswordGenerator::generate("salt1", feature, 16);
        let pwd2 = PasswordGenerator::generate("salt2", feature, 16);

        assert_ne!(
            pwd1, pwd2,
            "Different salts should produce different passwords"
        );
    }
}
