//! Command-line interface for SaltPass
//!
//! This module provides an interactive CLI for managing features and generating passwords.

use crate::crypto::PasswordGenerator;
use crate::models::{Feature, FeatureStore, Salt};
use crate::storage::{Storage, StorageFormat};
use arboard::Clipboard;
use dialoguer::{Input, Password, Select, theme::ColorfulTheme};
use std::io;

/// Command-line interface handler
pub struct Cli {
    storage: Storage,
    store: FeatureStore,
    salt: Option<Salt>,
}

impl Cli {
    pub fn new(format: StorageFormat) -> io::Result<Self> {
        let file_path = Storage::default_path(format)?;
        let storage = Storage::new(file_path, format);
        let store = storage.load()?;

        Ok(Self {
            storage,
            store,
            salt: None,
        })
    }

    pub fn run(&mut self) -> io::Result<()> {
        println!("🔐 Welcome to SaltPass - Deterministic Password Generator");
        println!("📁 Storage: {}", self.storage.file_path().display());
        println!();

        self.enter_salt()?;

        loop {
            let choices = vec![
                "Generate Password",
                "Add New Feature",
                "List All Features",
                "Delete Feature",
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
                4 => {
                    println!("👋 Goodbye! Salt cleared from memory.");
                    break;
                }
                _ => unreachable!(),
            }

            println!();
        }

        Ok(())
    }

    fn enter_salt(&mut self) -> io::Result<()> {
        let salt_input = Password::new()
            .with_prompt("🔑 Enter your master salt (hidden)")
            .interact()
            .map_err(io::Error::other)?;

        self.salt = Some(Salt::new(salt_input));
        println!("✅ Salt accepted (stored in memory only)");
        println!();

        Ok(())
    }

    fn generate_password(&self) -> io::Result<()> {
        if self.store.list_features().is_empty() {
            println!("⚠️  No features found. Please add a feature first.");
            return Ok(());
        }

        let features: Vec<String> = self
            .store
            .list_features()
            .iter()
            .map(|f| {
                if let Some(hint) = &f.hint {
                    format!("{} ({}) - {}", f.name, f.feature, hint)
                } else {
                    format!("{} ({})", f.name, f.feature)
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

        let password = PasswordGenerator::generate(salt.value(), &feature.feature, length);

        println!("\n🎯 Generated Password:");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Feature: {} ({})", feature.name, feature.feature);
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

    fn add_feature(&mut self) -> io::Result<()> {
        let name: String = Input::new()
            .with_prompt("Feature name (e.g., GitHub)")
            .interact_text()
            .map_err(io::Error::other)?;

        let feature: String = Input::new()
            .with_prompt("Feature identifier (e.g., github.com)")
            .interact_text()
            .map_err(io::Error::other)?;

        let hint: String = Input::new()
            .with_prompt("Hint (optional, press Enter to skip)")
            .allow_empty(true)
            .interact_text()
            .map_err(io::Error::other)?;

        let hint_option = if hint.is_empty() { None } else { Some(hint) };

        let new_feature = Feature::new(name.clone(), feature, hint_option);
        self.store.add_feature(new_feature);
        self.storage.save(&self.store)?;

        println!("✅ Feature '{}' added successfully!", name);

        Ok(())
    }

    fn list_features(&self) -> io::Result<()> {
        let features = self.store.list_features();

        if features.is_empty() {
            println!("📭 No features stored yet.");
            return Ok(());
        }

        println!("\n📋 Stored Features:");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        for (idx, feature) in features.iter().enumerate() {
            println!("{}. {} ({})", idx + 1, feature.name, feature.feature);
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

    fn delete_feature(&mut self) -> io::Result<()> {
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
}
