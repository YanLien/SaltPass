//! Cryptographic password generation module
//!
//! This module provides deterministic password generation using multiple algorithms.
//! Given the same salt and feature identifier, it will always produce the same password.

use crate::error::{CryptoError, CryptoResult};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, rand_core::RngCore},
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

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
    /// Returns the human-readable algorithm name shown by the CLI.
    pub fn name(&self) -> &str {
        match self {
            Algorithm::HmacSha256 => "HMAC-SHA256",
            Algorithm::Argon2i => "Argon2i",
            Algorithm::Argon2id => "Argon2id",
            Algorithm::Pbkdf2 => "PBKDF2",
            Algorithm::Scrypt => "Scrypt",
        }
    }

    /// Returns every algorithm in the order used by selection menus.
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
    /// let password = PasswordGenerator::generate_with_algo("my-secret-salt", "github.com", 16, Algorithm::HmacSha256).unwrap();
    /// assert_eq!(password.len(), 16);
    /// ```
    #[allow(dead_code)]
    pub fn generate(salt: &str, feature: &str, length: usize) -> CryptoResult<String> {
        Self::generate_with_algo(salt, feature, length, Algorithm::HmacSha256)
    }

    /// Generate a password using a specific algorithm
    pub fn generate_with_algo(
        salt: &str,
        feature: &str,
        length: usize,
        algo: Algorithm,
    ) -> CryptoResult<String> {
        let mut root = match algo {
            Algorithm::HmacSha256 => Self::derive_hmac_sha256(salt, feature),
            Algorithm::Argon2i => Self::derive_argon2(salt, feature, argon2::Algorithm::Argon2i)?,
            Algorithm::Argon2id => Self::derive_argon2(salt, feature, argon2::Algorithm::Argon2id)?,
            Algorithm::Pbkdf2 => Self::derive_pbkdf2(salt, feature),
            Algorithm::Scrypt => Self::derive_scrypt(salt, feature)?,
        };
        let password = Self::format_password(&root, feature, length);
        root.zeroize();
        Ok(password)
    }

    /// Hashes a feature into a fixed-length, domain-separated KDF salt.
    fn feature_salt(feature: &str) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"SaltPass/password/v2/feature\0");
        hash.update(feature.as_bytes());
        hash.finalize().into()
    }

    /// Derives a password root with the selected Argon2 variant.
    fn derive_argon2(salt: &str, feature: &str, alg: argon2::Algorithm) -> CryptoResult<[u8; 32]> {
        use argon2::{Argon2, Params, Version};
        let params = Params::new(65536, 2, 2, Some(32))
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        let argon2 = Argon2::new(alg, Version::V0x13, params);
        let mut output = [0u8; 32];
        argon2
            .hash_password_into(salt.as_bytes(), &Self::feature_salt(feature), &mut output)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        Ok(output)
    }

    /// Derives a password root with PBKDF2-HMAC-SHA256.
    fn derive_pbkdf2(salt: &str, feature: &str) -> [u8; 32] {
        let mut output = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(
            salt.as_bytes(),
            &Self::feature_salt(feature),
            100_000,
            &mut output,
        );
        output
    }

    /// Derives a password root with scrypt.
    fn derive_scrypt(salt: &str, feature: &str) -> CryptoResult<[u8; 32]> {
        let params = scrypt::Params::new(15, 8, 1, 32)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        let mut output = [0u8; 32];
        scrypt::scrypt(
            salt.as_bytes(),
            &Self::feature_salt(feature),
            &params,
            &mut output,
        )
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        Ok(output)
    }

    /// Expands a root key into a deterministic password satisfying all character classes.
    fn format_password(root: &[u8; 32], feature: &str, length: usize) -> String {
        const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const DIGIT: &[u8] = b"0123456789";
        const SPECIAL: &[u8] = b"!@#$%^&*";
        const ALL: &[u8] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
        let length = length.clamp(12, 64);
        let mut stream = Vec::with_capacity(length * 2);
        let mut counter = 0u32;
        while stream.len() < length * 2 {
            let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(root).expect("valid HMAC key");
            mac.update(b"SaltPass/password/v2/output\0");
            mac.update(feature.as_bytes());
            mac.update(&(length as u64).to_be_bytes());
            mac.update(&counter.to_be_bytes());
            stream.extend_from_slice(&mac.finalize().into_bytes());
            counter += 1;
        }
        let mut password = vec![
            LOWER[stream[0] as usize % LOWER.len()],
            UPPER[stream[1] as usize % UPPER.len()],
            DIGIT[stream[2] as usize % DIGIT.len()],
            SPECIAL[stream[3] as usize % SPECIAL.len()],
        ];
        for byte in &stream[4..length] {
            password.push(ALL[*byte as usize % ALL.len()]);
        }
        for i in (1..password.len()).rev() {
            let j = stream[length + i] as usize % (i + 1);
            password.swap(i, j);
        }
        String::from_utf8(password).expect("password alphabet is ASCII")
    }

    /// Derives a password root by authenticating the feature with the master secret.
    fn derive_hmac_sha256(salt: &str, feature: &str) -> [u8; 32] {
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(salt.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(feature.as_bytes());
        let result = mac.finalize();
        *result.into_bytes().as_ref()
    }
}

/// AES-256-GCM encryption for feature storage
///
/// Provides authenticated encryption for secure data persistence.
pub struct StorageCipher;

impl StorageCipher {
    const PREFIX: &str = "SP:";
    const SALT_SIZE: usize = 16;
    const NONCE_SIZE: usize = 12;
    const KEY_SIZE: usize = 32;

    /// Derives a 256-bit storage key from a password and per-file salt.
    fn derive_key(password: &str, salt: &[u8]) -> [u8; Self::KEY_SIZE] {
        use pbkdf2::pbkdf2_hmac;

        let mut key = [0u8; Self::KEY_SIZE];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 200_000, &mut key);
        key
    }

    /// Encrypt data using AES-256-GCM
    ///
    /// # Arguments
    ///
    /// * `password` - Encryption password
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// Base64-encoded ciphertext with nonce prepended (nonce || ciphertext || tag)
    pub fn encrypt(password: &str, plaintext: &[u8]) -> CryptoResult<String> {
        let mut salt = [0u8; Self::SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let mut key = Self::derive_key(password, &salt);
        let cipher = Aes256Gcm::new(&key.into());
        key.zeroize();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        cipher
            .encrypt(&nonce, plaintext)
            .map(|ciphertext| {
                let mut result = salt.to_vec();
                result.extend_from_slice(&nonce);
                result.extend_from_slice(&ciphertext);
                format!(
                    "{}{}",
                    Self::PREFIX,
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, result)
                )
            })
            .map_err(|_| CryptoError::Encryption)
    }

    /// Decrypt data using AES-256-GCM
    ///
    /// # Arguments
    ///
    /// * `password` - Decryption password
    /// * `encoded` - Base64-encoded ciphertext (nonce || ciphertext || tag)
    ///
    /// # Returns
    ///
    /// Decrypted plaintext
    pub fn decrypt(password: &str, encoded: &str) -> CryptoResult<Vec<u8>> {
        let payload = encoded
            .strip_prefix(Self::PREFIX)
            .ok_or(CryptoError::InvalidCiphertext("unsupported storage format"))?;
        let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload)
            .map_err(|e| CryptoError::InvalidEncoding(e.to_string()))?;

        if data.len() < Self::SALT_SIZE + Self::NONCE_SIZE + 16 {
            return Err(CryptoError::InvalidCiphertext("payload is too short"));
        }

        let (salt, encrypted) = data.split_at(Self::SALT_SIZE);
        let mut key = Self::derive_key(password, salt);
        let cipher = Aes256Gcm::new(&key.into());
        key.zeroize();
        let (nonce_bytes, ciphertext) = encrypted.split_at(Self::NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::Decryption)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_generation() {
        let salt = "my-secret-salt";
        let feature = "github.com";

        let pwd1 = PasswordGenerator::generate(salt, feature, 16).unwrap();
        let pwd2 = PasswordGenerator::generate(salt, feature, 16).unwrap();

        assert_eq!(pwd1, pwd2, "Same inputs should produce same password");
    }

    #[test]
    fn test_different_features() {
        let salt = "my-secret-salt";

        let pwd1 = PasswordGenerator::generate(salt, "github.com", 16).unwrap();
        let pwd2 = PasswordGenerator::generate(salt, "google.com", 16).unwrap();

        assert_ne!(
            pwd1, pwd2,
            "Different features should produce different passwords"
        );
    }

    #[test]
    fn test_different_salts() {
        let feature = "github.com";

        let pwd1 = PasswordGenerator::generate("salt1", feature, 16).unwrap();
        let pwd2 = PasswordGenerator::generate("salt2", feature, 16).unwrap();

        assert_ne!(
            pwd1, pwd2,
            "Different salts should produce different passwords"
        );
    }

    #[test]
    fn supports_every_documented_length_and_character_class() {
        for length in 12..=64 {
            let password = PasswordGenerator::generate_with_algo(
                "correct horse battery staple",
                "example.com",
                length,
                Algorithm::HmacSha256,
            )
            .unwrap();
            assert_eq!(password.len(), length);
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.chars().any(|c| "!@#$%^&*".contains(c)));
        }
    }

    #[test]
    fn encrypted_storage_round_trip_and_authentication() {
        let encrypted = StorageCipher::encrypt("master secret", b"sensitive features").unwrap();
        assert!(encrypted.starts_with(StorageCipher::PREFIX));
        assert_eq!(
            StorageCipher::decrypt("master secret", &encrypted).unwrap(),
            b"sensitive features"
        );
        assert!(StorageCipher::decrypt("wrong secret", &encrypted).is_err());

        let mut tampered = encrypted.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert!(
            StorageCipher::decrypt("master secret", std::str::from_utf8(&tampered).unwrap())
                .is_err()
        );
    }
}
