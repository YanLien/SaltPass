//! Application-wide error types.
//!
//! Errors are separated by layer so callers can react to a damaged file,
//! a conflicting write, and a cryptographic failure without parsing text.

use std::error::Error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum CryptoError {
    KeyDerivation(String),
    Encryption,
    Decryption,
    InvalidCiphertext(&'static str),
    InvalidEncoding(String),
}

impl fmt::Display for CryptoError {
    /// Formats a user-facing cryptographic error without leaking sensitive details.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyDerivation(message) => write!(f, "key derivation failed: {message}"),
            Self::Encryption => f.write_str("encryption failed"),
            Self::Decryption => f.write_str("decryption failed (wrong secret or damaged data)"),
            Self::InvalidCiphertext(message) => write!(f, "invalid ciphertext: {message}"),
            Self::InvalidEncoding(message) => write!(f, "invalid ciphertext encoding: {message}"),
        }
    }
}

impl Error for CryptoError {}

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    Crypto(CryptoError),
    MissingPassword,
    Utf8(std::string::FromUtf8Error),
    Json(serde_json::Error),
    TomlDecode(toml::de::Error),
    TomlEncode(toml::ser::Error),
    /// The file changed after this process loaded it; saving would lose data.
    ConcurrentModification,
}

impl fmt::Display for StorageError {
    /// Formats a storage error with its operation-specific context.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "storage I/O failed: {error}"),
            Self::Crypto(error) => write!(f, "encrypted storage failed: {error}"),
            Self::MissingPassword => f.write_str("encrypted storage password is not set"),
            Self::Utf8(error) => write!(f, "storage is not valid UTF-8: {error}"),
            Self::Json(error) => write!(f, "invalid JSON storage: {error}"),
            Self::TomlDecode(error) => write!(f, "invalid TOML storage: {error}"),
            Self::TomlEncode(error) => write!(f, "TOML serialization failed: {error}"),
            Self::ConcurrentModification => {
                f.write_str("storage changed since it was loaded; reload before saving")
            }
        }
    }
}

impl Error for StorageError {
    /// Exposes the wrapped lower-level error, when one exists.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Utf8(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::TomlDecode(error) => Some(error),
            Self::TomlEncode(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StorageError {
    /// Wraps filesystem and stream failures as storage errors.
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CryptoError> for StorageError {
    /// Wraps encryption and decryption failures as storage errors.
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

#[derive(Debug)]
pub enum AppError {
    Io(io::Error),
    Crypto(CryptoError),
    Storage(StorageError),
}

impl fmt::Display for AppError {
    /// Formats the top-level error presented by the executable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Crypto(error) => write!(f, "password generation failed: {error}"),
            Self::Storage(error) => error.fmt(f),
        }
    }
}

impl Error for AppError {
    /// Exposes the wrapped application-layer error.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Storage(error) => Some(error),
        }
    }
}

impl From<io::Error> for AppError {
    /// Promotes a general I/O failure into an application error.
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CryptoError> for AppError {
    /// Promotes a password-generation failure into an application error.
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<StorageError> for AppError {
    /// Promotes a persistence failure into an application error.
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

pub type AppResult<T> = Result<T, AppError>;
pub type CryptoResult<T> = Result<T, CryptoError>;
pub type StorageResult<T> = Result<T, StorageError>;
