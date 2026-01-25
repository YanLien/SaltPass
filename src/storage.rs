//! Storage layer for feature persistence
//!
//! This module handles loading and saving features to disk in JSON or TOML format,
//! with optional AES-256-GCM encryption.

use crate::crypto::StorageCipher;
use crate::models::FeatureStore;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

/// Storage format for features
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum StorageFormat {
    Json,
    Toml,
}

impl StorageFormat {
    pub fn extension(&self) -> &str {
        match self {
            StorageFormat::Json => "json",
            StorageFormat::Toml => "toml",
        }
    }

    #[allow(dead_code)]
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
    encryption_password: Option<String>,
}

impl Storage {
    pub fn new(file_path: PathBuf, format: StorageFormat, encrypted: bool) -> Self {
        Self {
            file_path,
            format,
            encrypted,
            encryption_password: None,
        }
    }

    /// Set the encryption password for encrypted storage
    pub fn set_password(&mut self, password: String) {
        self.encryption_password = Some(password);
    }

    #[allow(dead_code)]
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn default_path(format: StorageFormat, encrypted: bool) -> io::Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "Home directory not found"))?;

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

    pub fn load(&self) -> io::Result<FeatureStore> {
        if !self.file_path.exists() {
            return Ok(FeatureStore::new());
        }

        let content = fs::read_to_string(&self.file_path)?;

        if self.encrypted {
            let password = self.encryption_password.as_ref().ok_or_else(|| {
                io::Error::new(ErrorKind::NotFound, "Encryption password not set")
            })?;
            let decrypted = StorageCipher::decrypt(password, &content)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
            let decrypted_string = String::from_utf8(decrypted)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
            match self.format {
                StorageFormat::Json => serde_json::from_str(&decrypted_string)
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e)),
                StorageFormat::Toml => toml::from_str(&decrypted_string)
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e)),
            }
        } else {
            match self.format {
                StorageFormat::Json => serde_json::from_str(&content)
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e)),
                StorageFormat::Toml => {
                    toml::from_str(&content).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
                }
            }
        }
    }

    pub fn save(&self, store: &FeatureStore) -> io::Result<()> {
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let data = match self.format {
            StorageFormat::Json => serde_json::to_vec_pretty(store)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
            StorageFormat::Toml => toml::to_string_pretty(store)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
                .into_bytes(),
        };

        let content = if self.encrypted {
            let password = self.encryption_password.as_ref().ok_or_else(|| {
                io::Error::new(ErrorKind::NotFound, "Encryption password not set")
            })?;
            StorageCipher::encrypt(password, &data)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        } else {
            String::from_utf8(data).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        };

        fs::write(&self.file_path, content)?;
        Ok(())
    }

    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Export decrypted content as TOML string for viewing
    pub fn export_decrypted(&self) -> io::Result<String> {
        if !self.file_path.exists() {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                "Storage file not found",
            ));
        }

        let content = fs::read_to_string(&self.file_path)?;

        if self.encrypted {
            let password = self.encryption_password.as_ref().ok_or_else(|| {
                io::Error::new(ErrorKind::NotFound, "Encryption password not set")
            })?;
            let decrypted = StorageCipher::decrypt(password, &content)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
            let decrypted_string = String::from_utf8(decrypted)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
            // Always show as TOML for consistency
            match self.format {
                StorageFormat::Json => {
                    let store: FeatureStore = serde_json::from_str(&decrypted_string)
                        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
                    toml::to_string_pretty(&store)
                        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
                }
                StorageFormat::Toml => Ok(decrypted_string),
            }
        } else {
            match self.format {
                StorageFormat::Json => {
                    // Parse JSON and convert to TOML for viewing
                    let store: FeatureStore = serde_json::from_str(&content)
                        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
                    toml::to_string_pretty(&store)
                        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
                }
                StorageFormat::Toml => Ok(content),
            }
        }
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
}
