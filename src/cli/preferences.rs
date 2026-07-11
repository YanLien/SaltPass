//! First-run preferences and selection of existing storage files.

use crate::error::AppResult;
use crate::storage::StorageFormat;
use dialoguer::{Select, theme::ColorfulTheme};
use std::io;
use std::path::PathBuf;

/// Chooses an existing store, returning it directly when only one is present.
pub fn choose_existing(
    stores: &[(PathBuf, StorageFormat, bool)],
) -> AppResult<Option<(PathBuf, StorageFormat, bool)>> {
    // Avoid asking configuration questions again when a prior store is found.
    if stores.is_empty() {
        return Ok(None);
    }
    if stores.len() == 1 {
        return Ok(Some(stores[0].clone()));
    }
    let labels: Vec<String> = stores
        .iter()
        .map(|(path, _, encrypted)| {
            format!(
                "{}{}",
                path.display(),
                if *encrypted { " (encrypted)" } else { "" }
            )
        })
        .collect();
    let selected = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select existing storage")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(io::Error::other)?;
    Ok(Some(stores[selected].clone()))
}

/// Prompts for the serialization format used by a new store.
pub fn ask_format() -> AppResult<StorageFormat> {
    println!("📁 Choose file format:");
    let choices = ["TOML (Recommended)", "JSON"];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Format")
        .items(&choices)
        .default(0)
        .interact()
        .map_err(io::Error::other)?;

    Ok(if selection == 0 {
        StorageFormat::Toml
    } else {
        StorageFormat::Json
    })
}

/// Prompts whether a new store should be encrypted.
pub fn ask_encryption() -> AppResult<bool> {
    println!("🔐 Would you like to encrypt your features file? (Experimental)");
    println!("   - Encrypted: Features are encrypted with your salt (more secure)");
    println!("   - Plain: Features are stored as plain text (easier to view/backup)");
    println!("   ⚠️  WARNING: Encrypted mode is experimental. If you forget your salt,");
    println!("      your data cannot be recovered. Consider exporting regularly.");
    println!();

    let choices = ["Encrypted (Experimental)", "Plain Text (Recommended)"];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose storage format")
        .items(&choices)
        .default(1)
        .interact()
        .map_err(io::Error::other)?;

    Ok(selection == 0)
}
