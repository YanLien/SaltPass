//! Storage layer for feature persistence
//!
//! This module handles loading and saving features to disk in JSON or TOML format.

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
}

impl Storage {
    pub fn new(file_path: PathBuf, format: StorageFormat) -> Self {
        Self { file_path, format }
    }

    pub fn default_path(format: StorageFormat) -> io::Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "Home directory not found"))?;

        let config_dir = home.join(".saltpass");
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
        }

        Ok(config_dir.join(format!("features.{}", format.extension())))
    }

    pub fn load(&self) -> io::Result<FeatureStore> {
        if !self.file_path.exists() {
            return Ok(FeatureStore::new());
        }

        let content = fs::read_to_string(&self.file_path)?;

        match self.format {
            StorageFormat::Json => serde_json::from_str(&content)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e)),
            StorageFormat::Toml => {
                toml::from_str(&content).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
            }
        }
    }

    pub fn save(&self, store: &FeatureStore) -> io::Result<()> {
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = match self.format {
            StorageFormat::Json => serde_json::to_string_pretty(store)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
            StorageFormat::Toml => toml::to_string_pretty(store)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
        };

        fs::write(&self.file_path, content)?;
        Ok(())
    }

    pub fn file_path(&self) -> &Path {
        &self.file_path
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

        let storage = Storage::new(test_file.clone(), StorageFormat::Json);
        let mut store = FeatureStore::new();
        store.add_feature(Feature::new(
            "GitHub".to_string(),
            "github.com".to_string(),
            Some("Main account".to_string()),
        ));

        storage.save(&store).unwrap();

        let loaded = storage.load().unwrap();
        assert_eq!(loaded.features.len(), 1);
        assert_eq!(loaded.features[0].name, "GitHub");

        fs::remove_file(&test_file).unwrap();
    }
}
