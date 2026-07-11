//! Secure master-secret input.
//!
//! `dialoguer` owns terminal mode changes and restoration, keeping platform-
//! specific raw-terminal code out of the application workflow.

use crate::error::AppResult;
use dialoguer::Password;
use std::io;

/// Reads a hidden master secret from the controlling terminal.
pub fn read_master_secret() -> AppResult<String> {
    Password::new()
        .with_prompt("🔑 Enter your master secret")
        .interact()
        .map_err(io::Error::other)
        .map_err(Into::into)
}
