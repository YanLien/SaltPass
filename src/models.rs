//! Data models for SaltPass
//!
//! This module defines the core data structures used in SaltPass:
//! - `Salt`: Master salt stored securely in memory
//! - `Feature`: Feature identifiers for password generation
//! - `FeatureStore`: Collection of features

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Master salt that is automatically zeroed when dropped
///
/// The salt is never written to disk and exists only in memory during the application's lifetime.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Salt {
    #[zeroize(skip)]
    salt_value: String,
}

impl Salt {
    pub fn new(value: String) -> Self {
        Self { salt_value: value }
    }

    pub fn value(&self) -> &str {
        &self.salt_value
    }
}

/// Feature identifier for password generation
///
/// Each feature represents a unique identifier (e.g., website domain) that combined
/// with the master salt produces a unique password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feature {
    pub name: String,
    pub feature: String,
    pub created: DateTime<Utc>,
    pub hint: Option<String>,
}

impl Feature {
    pub fn new(name: String, feature: String, hint: Option<String>) -> Self {
        Self {
            name,
            feature,
            created: Utc::now(),
            hint,
        }
    }
}

/// Collection of features stored on disk
///
/// This structure holds all feature identifiers and can be serialized to/from JSON or TOML.
#[derive(Debug, Serialize, Deserialize)]
pub struct FeatureStore {
    pub features: Vec<Feature>,
}

impl FeatureStore {
    pub fn new() -> Self {
        Self {
            features: Vec::new(),
        }
    }

    pub fn add_feature(&mut self, feature: Feature) {
        self.features.push(feature);
    }

    pub fn remove_feature(&mut self, index: usize) -> Option<Feature> {
        if index < self.features.len() {
            Some(self.features.remove(index))
        } else {
            None
        }
    }

    pub fn list_features(&self) -> &[Feature] {
        &self.features
    }
}

impl Default for FeatureStore {
    fn default() -> Self {
        Self::new()
    }
}
