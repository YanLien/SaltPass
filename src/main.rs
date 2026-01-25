//! SaltPass - A deterministic password generator
//!
//! SaltPass generates unique, strong passwords based on a master salt and feature identifiers.
//! The master salt is stored only in memory and automatically zeroed when the application exits.
//!
//! # Features
//!
//! - Deterministic password generation using HMAC-SHA256
//! - Memory-only storage of master salt
//! - Feature management (add, list, delete)
//! - Auto-copy passwords to clipboard
//! - Cross-platform support
//!
//! # Usage
//!
//! Run the application and follow the interactive prompts:
//!
//! ```bash
//! cargo run --release
//! ```

mod cli;
mod crypto;
mod models;
mod storage;

use cli::Cli;
use std::process;

fn main() {
    let mut app = match Cli::new() {
        Ok(app) => app,
        Err(e) => {
            eprintln!("\r\x1b[2K❌ Error: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = app.run() {
        eprintln!("\r\x1b[2K❌ Error: {}", e); // \x1b[2K clears the line
        process::exit(1);
    }
}
