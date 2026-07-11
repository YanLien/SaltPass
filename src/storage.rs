//! Storage layer for feature persistence
//!
//! This module handles loading and saving features to disk in JSON or TOML format,
//! with optional AES-256-GCM encryption.

use crate::crypto::StorageCipher;
use crate::error::{StorageError, StorageResult};
use crate::models::FeatureStore;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Storage format for features
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum StorageFormat {
    Json,
    Toml,
}

impl StorageFormat {
    /// Returns the filename extension associated with this format.
    pub fn extension(&self) -> &str {
        match self {
            StorageFormat::Json => "json",
            StorageFormat::Toml => "toml",
        }
    }

    #[allow(dead_code)]
    /// Parses a storage format from a filename extension.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "json" => Some(StorageFormat::Json),
            "toml" => Some(StorageFormat::Toml),
            _ => None,
        }
    }
}

/// Storage handler for feature persistence
///
/// Manages loading and saving features to disk in the specified format.
pub struct Storage {
    file_path: PathBuf,
    format: StorageFormat,
    encrypted: bool,
    encryption_password: Option<Zeroizing<String>>,
    // Hash of the exact on-disk representation read by `load`. Interior
    // mutability keeps loading available through a shared Storage reference.
    loaded_hash: RefCell<Option<[u8; 32]>>,
}

impl Storage {
    /// Creates a storage handle for a specific path and representation.
    pub fn new(file_path: PathBuf, format: StorageFormat, encrypted: bool) -> Self {
        Self {
            file_path,
            format,
            encrypted,
            encryption_password: None,
            loaded_hash: RefCell::new(None),
        }
    }

    /// Sets the in-memory password used by encrypted storage.
    pub fn set_password(&mut self, password: String) {
        self.encryption_password = Some(Zeroizing::new(password));
    }

    #[allow(dead_code)]
    /// Reports whether this handle reads and writes encrypted content.
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Returns the canonical SaltPass path for a format and encryption mode.
    pub fn default_path(format: StorageFormat, encrypted: bool) -> StorageResult<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| {
            StorageError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "home directory not found",
            ))
        })?;

        let config_dir = home.join(".saltpass");
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
        }

        let ext = if encrypted {
            format!("{}.enc", format.extension())
        } else {
            format.extension().to_string()
        };
        Ok(config_dir.join(format!("features.{}", ext)))
    }

    /// Finds canonical SaltPass storage files that already exist.
    pub fn discover() -> StorageResult<Vec<(PathBuf, StorageFormat, bool)>> {
        // Only recognize canonical SaltPass filenames. Arbitrary files in the
        // configuration directory must never be offered as password stores.
        let mut found = Vec::new();
        for format in [StorageFormat::Toml, StorageFormat::Json] {
            for encrypted in [false, true] {
                let path = Self::default_path(format, encrypted)?;
                if path.is_file() {
                    found.push((path, format, encrypted));
                }
            }
        }
        Ok(found)
    }

    /// Loads and deserializes the feature collection from disk.
    pub fn load(&self) -> StorageResult<FeatureStore> {
        if !self.file_path.exists() {
            return Ok(FeatureStore::new());
        }

        let content = fs::read_to_string(&self.file_path)?;
        *self.loaded_hash.borrow_mut() = Some(Sha256::digest(content.as_bytes()).into());

        if self.encrypted {
            let password = self
                .encryption_password
                .as_ref()
                .ok_or(StorageError::MissingPassword)?;
            let decrypted = StorageCipher::decrypt(password.as_str(), &content)?;
            let decrypted_string = String::from_utf8(decrypted).map_err(StorageError::Utf8)?;
            match self.format {
                StorageFormat::Json => {
                    serde_json::from_str(&decrypted_string).map_err(StorageError::Json)
                }
                StorageFormat::Toml => {
                    toml::from_str(&decrypted_string).map_err(StorageError::TomlDecode)
                }
            }
        } else {
            match self.format {
                StorageFormat::Json => serde_json::from_str(&content).map_err(StorageError::Json),
                StorageFormat::Toml => toml::from_str(&content).map_err(StorageError::TomlDecode),
            }
        }
    }

    /// Serializes and atomically saves a feature collection.
    pub fn save(&self, store: &FeatureStore) -> StorageResult<()> {
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if self.file_path.exists() {
            // Refuse a lost update if another process edited the file after
            // this instance loaded it.
            let current: [u8; 32] = Sha256::digest(fs::read(&self.file_path)?).into();
            if let Some(loaded) = *self.loaded_hash.borrow()
                && loaded != current
            {
                return Err(StorageError::ConcurrentModification);
            }
        }

        let data = match self.format {
            StorageFormat::Json => serde_json::to_vec_pretty(store).map_err(StorageError::Json)?,
            StorageFormat::Toml => toml::to_string_pretty(store)
                .map_err(StorageError::TomlEncode)?
                .into_bytes(),
        };

        let content = if self.encrypted {
            let password = self
                .encryption_password
                .as_ref()
                .ok_or(StorageError::MissingPassword)?;
            StorageCipher::encrypt(password.as_str(), &data)?
        } else {
            String::from_utf8(data).map_err(StorageError::Utf8)?
        };

        self.atomic_write(content.as_bytes())?;
        *self.loaded_hash.borrow_mut() = Some(Sha256::digest(content.as_bytes()).into());
        Ok(())
    }

    /// Writes content to a same-directory temporary file and replaces the destination.
    fn atomic_write(&self, content: &[u8]) -> io::Result<()> {
        // Writing in the destination directory ensures the final rename stays
        // on the same filesystem and can be atomic.
        let file_name = self
            .file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("features");
        let temp_path = self.file_path.with_file_name(format!(
            ".{file_name}.tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            use std::io::Write;
            let mut file = options.open(&temp_path)?;
            file.write_all(content)?;
            file.sync_all()?;
            replace_file(&temp_path, &self.file_path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    /// Returns the backing file path.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Export decrypted content as TOML string for viewing
    pub fn export_decrypted(&self) -> StorageResult<String> {
        if !self.file_path.exists() {
            return Err(StorageError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "storage file not found",
            )));
        }

        let content = fs::read_to_string(&self.file_path)?;

        if self.encrypted {
            let password = self
                .encryption_password
                .as_ref()
                .ok_or(StorageError::MissingPassword)?;
            let decrypted = StorageCipher::decrypt(password.as_str(), &content)?;
            let decrypted_string = String::from_utf8(decrypted).map_err(StorageError::Utf8)?;
            // Always show as TOML for consistency
            match self.format {
                StorageFormat::Json => {
                    let store: FeatureStore =
                        serde_json::from_str(&decrypted_string).map_err(StorageError::Json)?;
                    toml::to_string_pretty(&store).map_err(StorageError::TomlEncode)
                }
                StorageFormat::Toml => Ok(decrypted_string),
            }
        } else {
            match self.format {
                StorageFormat::Json => {
                    // Parse JSON and convert to TOML for viewing
                    let store: FeatureStore =
                        serde_json::from_str(&content).map_err(StorageError::Json)?;
                    toml::to_string_pretty(&store).map_err(StorageError::TomlEncode)
                }
                StorageFormat::Toml => Ok(content),
            }
        }
    }
}

#[cfg(not(windows))]
/// Atomically renames a completed temporary file on Unix-like platforms.
fn replace_file(source: &Path, target: &Path) -> io::Result<()> {
    fs::rename(source, target)
}

#[cfg(windows)]
/// Atomically replaces a destination file using the Windows filesystem API.
fn replace_file(source: &Path, target: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    // `std::fs::rename` cannot replace an existing Windows file. MoveFileExW
    // provides replacement semantics and requests the metadata flush.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Feature;
    use std::fs;

    #[test]
    fn test_json_save_load() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_features.json");

        if test_file.exists() {
            fs::remove_file(&test_file).unwrap();
        }

        let storage = Storage::new(test_file.clone(), StorageFormat::Json, false);
        let mut store = FeatureStore::new();
        store.add_feature(Feature::new(
            "GitHub".to_string(),
            "github.com".to_string(),
            crate::crypto::Algorithm::HmacSha256,
            Some("Main account".to_string()),
        ));

        storage.save(&store).unwrap();

        let loaded = storage.load().unwrap();
        assert_eq!(loaded.features.len(), 1);
        assert_eq!(loaded.features[0].name, "GitHub");

        fs::remove_file(&test_file).unwrap();
    }

    #[test]
    fn reports_structured_storage_errors() {
        let path =
            std::env::temp_dir().join(format!("saltpass-errors-{}.json", std::process::id()));
        fs::write(&path, "not json").unwrap();
        let storage = Storage::new(path.clone(), StorageFormat::Json, false);
        assert!(matches!(storage.load(), Err(StorageError::Json(_))));
        fs::remove_file(path).unwrap();

        let encrypted = Storage::new(PathBuf::from("unused.enc"), StorageFormat::Json, true);
        assert!(matches!(
            encrypted.save(&FeatureStore::new()),
            Err(StorageError::MissingPassword)
        ));
    }

    #[test]
    fn detects_concurrent_modification() {
        let path =
            std::env::temp_dir().join(format!("saltpass-conflict-{}.json", std::process::id()));
        fs::write(&path, r#"{"features":[]}"#).unwrap();
        let storage = Storage::new(path.clone(), StorageFormat::Json, false);
        let store = storage.load().unwrap();
        fs::write(&path, r#"{"features":[],"external":true}"#).unwrap();
        assert!(matches!(
            storage.save(&store),
            Err(StorageError::ConcurrentModification)
        ));
        fs::remove_file(path).unwrap();
    }
}
