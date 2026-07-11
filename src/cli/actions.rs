//! Command-line interface for SaltPass.
//!
//! This module provides an interactive CLI for managing features and generating passwords.

use crate::crypto::{Algorithm, PasswordGenerator};
use crate::error::{AppError, AppResult};
use crate::models::{Feature, FeatureStore, Salt};
use crate::storage::Storage;
use arboard::Clipboard;
use dialoguer::{Input, Select, theme::ColorfulTheme};
use std::io;

use super::{password_input, preferences};

/// Command-line interface handler
pub struct Cli {
    storage: Storage,
    store: FeatureStore,
    salt: Option<Salt>,
}

impl Cli {
    /// Discovers storage, reads the master secret, and initializes the CLI state.
    pub fn new() -> AppResult<Self> {
        // Discover first so selecting a different format cannot accidentally
        // make an existing store appear to have disappeared.
        let existing = Storage::discover()?;
        let (file_path, format, should_encrypt) = match preferences::choose_existing(&existing)? {
            Some(config) => config,
            None => {
                let encrypted = preferences::ask_encryption()?;
                let format = preferences::ask_format()?;
                (Storage::default_path(format, encrypted)?, format, encrypted)
            }
        };
        let mut storage = Storage::new(file_path, format, should_encrypt);

        // Ask for salt
        let salt = Self::ask_salt_before_init()?;

        // Set password if encrypted and load store
        if should_encrypt {
            storage.set_password(salt.clone());
        }

        let store = storage.load()?;

        Ok(Self {
            storage,
            store,
            salt: Some(Salt::new(salt)),
        })
    }

    /// Reads and validates the master secret before loading encrypted data.
    fn ask_salt_before_init() -> AppResult<String> {
        let salt = password_input::read_master_secret()?;

        if salt.is_empty() {
            return Err(AppError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Salt cannot be empty",
            )));
        }

        Ok(salt)
    }

    /// Runs the interactive menu until the user chooses to exit.
    pub fn run(&mut self) -> AppResult<()> {
        println!("🔐 Welcome to SaltPass - Deterministic Password Generator");
        println!("📁 Storage: {}", self.storage.file_path().display());
        println!("✅ Salt accepted (stored in memory only)");
        println!();

        loop {
            let choices = vec![
                "Generate Password",
                "Add New Feature",
                "List All Features",
                "Delete Feature",
                "View Decrypted Content",
                "Exit",
            ];

            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("What would you like to do?")
                .items(&choices)
                .default(0)
                .interact()
                .map_err(io::Error::other)?;

            match selection {
                0 => self.generate_password()?,
                1 => self.add_feature()?,
                2 => self.list_features()?,
                3 => self.delete_feature()?,
                4 => self.view_decrypted()?,
                5 => {
                    println!("👋 Goodbye! Salt cleared from memory.");
                    break;
                }
                _ => unreachable!(),
            }

            println!();
        }

        Ok(())
    }

    /// Prompts for a feature and length, then generates and copies its password.
    fn generate_password(&self) -> AppResult<()> {
        if self.store.list_features().is_empty() {
            println!("⚠️  No features found. Please add a feature first.");
            return Ok(());
        }

        let features: Vec<String> = self
            .store
            .list_features()
            .iter()
            .map(|f| {
                let algo = format!("[{}]", f.algorithm.name());
                if let Some(hint) = &f.hint {
                    format!("{} {} ({}) - {}", algo, f.name, f.feature, hint)
                } else {
                    format!("{} {} ({})", algo, f.name, f.feature)
                }
            })
            .collect();

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a feature to generate password")
            .items(&features)
            .default(0)
            .interact()
            .map_err(io::Error::other)?;

        let feature = &self.store.list_features()[selection];
        let salt = self.salt.as_ref().unwrap();

        let length_input: String = Input::new()
            .with_prompt("Password length (12-64)")
            .default("16".to_string())
            .interact_text()
            .map_err(io::Error::other)?;

        let length = length_input.parse::<usize>().unwrap_or(16).clamp(12, 64);

        let password = PasswordGenerator::generate_with_algo(
            salt.value(),
            &feature.feature,
            length,
            feature.algorithm,
        )?;

        println!("\n🎯 Generated Password:");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Feature: {} ({})", feature.name, feature.feature);
        println!("Algorithm: {}", feature.algorithm.name());
        println!("Password: {}", password);
        println!("Length: {}", password.len());
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        if let Ok(mut clipboard) = Clipboard::new()
            && clipboard.set_text(&password).is_ok()
        {
            println!("📋 Password copied to clipboard!");
        }

        Ok(())
    }

    /// Collects feature metadata and persists a new feature.
    fn add_feature(&mut self) -> AppResult<()> {
        let name: String = Input::new()
            .with_prompt("Feature name (e.g., GitHub)")
            .interact_text()
            .map_err(io::Error::other)?;

        let feature: String = Input::new()
            .with_prompt("Feature identifier (e.g., github.com)")
            .interact_text()
            .map_err(io::Error::other)?;

        // Select algorithm
        let algo_items: Vec<String> = Algorithm::all()
            .iter()
            .map(|a| {
                format!("{} - {}", a.name(), {
                    match a {
                        Algorithm::HmacSha256 => "Fast (Recommended for password generation)",
                        Algorithm::Argon2i => "Memory-hard (Slower, more secure)",
                        Algorithm::Argon2id => "Hybrid (Balanced)",
                        Algorithm::Pbkdf2 => "Standard (Compatible)",
                        Algorithm::Scrypt => "Memory-hard (Slower)",
                    }
                })
            })
            .collect();

        let algo_selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select password generation algorithm")
            .items(&algo_items)
            .default(0)
            .interact()
            .map_err(io::Error::other)?;

        let algorithm = Algorithm::all()[algo_selection];

        let hint: String = Input::new()
            .with_prompt("Hint (optional, press Enter to skip)")
            .allow_empty(true)
            .interact_text()
            .map_err(io::Error::other)?;

        let hint_option = if hint.is_empty() { None } else { Some(hint) };

        let new_feature = Feature::new(name.clone(), feature, algorithm, hint_option);
        self.store.add_feature(new_feature);
        self.storage.save(&self.store)?;

        println!("✅ Feature '{}' added successfully!", name);

        Ok(())
    }

    /// Prints every stored feature without exposing generated passwords.
    fn list_features(&self) -> AppResult<()> {
        let features = self.store.list_features();

        if features.is_empty() {
            println!("📭 No features stored yet.");
            return Ok(());
        }

        println!("\n📋 Stored Features:");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        for (idx, feature) in features.iter().enumerate() {
            println!("{}. {} ({})", idx + 1, feature.name, feature.feature);
            println!("   Algorithm: {}", feature.algorithm.name());
            if let Some(hint) = &feature.hint {
                println!("   Hint: {}", hint);
            }
            println!(
                "   Created: {}",
                feature.created.format("%Y-%m-%d %H:%M:%S")
            );
            println!();
        }

        Ok(())
    }

    /// Selects, removes, and persists deletion of a feature.
    fn delete_feature(&mut self) -> AppResult<()> {
        if self.store.list_features().is_empty() {
            println!("⚠️  No features to delete.");
            return Ok(());
        }

        let features: Vec<String> = self
            .store
            .list_features()
            .iter()
            .map(|f| format!("{} ({})", f.name, f.feature))
            .collect();

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a feature to delete")
            .items(&features)
            .default(0)
            .interact()
            .map_err(io::Error::other)?;

        let feature_name = self.store.list_features()[selection].name.clone();
        self.store.remove_feature(selection);
        self.storage.save(&self.store)?;

        println!("🗑️  Feature '{}' deleted successfully!", feature_name);

        Ok(())
    }

    /// Decrypts and displays the current feature store as TOML.
    fn view_decrypted(&self) -> AppResult<()> {
        if !self.storage.file_path().exists() {
            println!("📭 No storage file found yet.");
            return Ok(());
        }

        match self.storage.export_decrypted() {
            Ok(content) => {
                println!("\n📄 Decrypted Content (TOML):");
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("{}", content);
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            }
            Err(e) => {
                println!("❌ Failed to decrypt: {}", e);
                println!(
                    "💡 Note: If using encrypted storage, the encryption password must match."
                );
            }
        }

        Ok(())
    }
}
