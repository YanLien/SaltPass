//! Cryptographic password generation module
//!
//! This module provides deterministic password generation using HMAC-SHA256.
//! Given the same salt and feature identifier, it will always produce the same password.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Password generator using HMAC-SHA256
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
    /// use SaltPass::crypto::PasswordGenerator;
    ///
    /// let password = PasswordGenerator::generate("my-secret-salt", "github.com", 16);
    /// assert_eq!(password.len(), 16);
    /// ```
    pub fn generate(salt: &str, feature: &str, length: usize) -> String {
        let key = salt.as_bytes();
        let message = feature.as_bytes();

        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(message);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        let base64_encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);

        Self::format_password(&base64_encoded, length)
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
