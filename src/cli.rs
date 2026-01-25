//! Command-line interface for SaltPass
//!
//! This module provides an interactive CLI for managing features and generating passwords.

use crate::crypto::{Algorithm, PasswordGenerator};
use crate::models::{Feature, FeatureStore, Salt};
use crate::storage::{Storage, StorageFormat};
use arboard::Clipboard;
use dialoguer::{Input, Select, theme::ColorfulTheme};
use std::io::{self, Read};

/// Command-line interface handler
pub struct Cli {
    storage: Storage,
    store: FeatureStore,
    salt: Option<Salt>,
}

impl Cli {
    pub fn new() -> io::Result<Self> {
        // Ask for preferences first
        let should_encrypt = Self::ask_encryption_preference()?;
        let format = Self::ask_format_preference()?;

        // Get file path
        let file_path = Storage::default_path(format, should_encrypt)?;
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

    /// Ask for salt before/during initialization
    fn ask_salt_before_init() -> io::Result<String> {
        use std::io::Write;
        print!("🔑 Enter your master salt (Tab: Show/Hide): ");
        io::stdout().flush()?;

        // Create a temporary Cli instance just to use the password reading method
        let temp_cli = Cli {
            storage: Storage::new(
                Storage::default_path(StorageFormat::Toml, false)?,
                StorageFormat::Toml,
                false,
            ),
            store: FeatureStore::new(),
            salt: None,
        };

        let salt = temp_cli.read_password_with_asterisks()?;

        if salt.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Salt cannot be empty",
            ));
        }

        Ok(salt)
    }

    fn ask_format_preference() -> io::Result<StorageFormat> {
        println!("📁 Choose file format:");
        let choices = vec!["TOML (Recommended)", "JSON"];
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

    fn ask_encryption_preference() -> io::Result<bool> {
        println!("🔐 Would you like to encrypt your features file? (Experimental)");
        println!("   - Encrypted: Features are encrypted with your salt (more secure)");
        println!("   - Plain: Features are stored as plain text (easier to view/backup)");
        println!("   ⚠️  WARNING: Encrypted mode is experimental. If you forget your salt,");
        println!("      your data cannot be recovered. Consider exporting regularly.");
        println!();

        let choices = vec!["Encrypted (Experimental)", "Plain Text (Recommended)"];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose storage format")
            .items(&choices)
            .default(1) // Default to Plain Text for safety
            .interact()
            .map_err(io::Error::other)?;

        Ok(selection == 0)
    }

    pub fn run(&mut self) -> io::Result<()> {
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

    /// Read password with asterisk feedback (instance method)
    fn read_password_with_asterisks(&self) -> io::Result<String> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;

            let stdin = io::stdin();
            let fd = stdin.as_raw_fd();

            let mut termios = unsafe { std::mem::zeroed() };
            unsafe {
                if libc::tcgetattr(fd, &mut termios) != 0 {
                    return Err(io::Error::last_os_error());
                }

                let original_termios = termios;
                termios.c_lflag &= !(libc::ECHO | libc::ICANON);
                // Also disable signals so we can handle all keys manually
                termios.c_lflag &= !libc::ISIG;
                // Set raw mode for proper key handling
                termios.c_iflag &= !(libc::IGNBRK
                    | libc::BRKINT
                    | libc::PARMRK
                    | libc::ISTRIP
                    | libc::INLCR
                    | libc::IGNCR
                    | libc::ICRNL
                    | libc::IXON);
                termios.c_oflag &= !libc::OPOST;
                termios.c_cflag |= libc::CS8;

                if libc::tcsetattr(fd, libc::TCSANOW, &termios) != 0 {
                    return Err(io::Error::last_os_error());
                }

                let result = self.read_password_chars();

                // Restore terminal settings
                libc::tcsetattr(fd, libc::TCSANOW, &original_termios);
                result
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::System::Console::{
                ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode,
                SetConsoleMode,
            };

            let stdin = io::stdin();
            let handle: HANDLE = stdin.as_raw_handle() as *mut _;

            let mut original_mode = 0u32;
            unsafe {
                if GetConsoleMode(handle, &mut original_mode) == 0 {
                    return Err(io::Error::last_os_error());
                }

                let new_mode = original_mode
                    & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
                if SetConsoleMode(handle, new_mode) == 0 {
                    return Err(io::Error::last_os_error());
                }

                let result = self.read_password_chars();

                SetConsoleMode(handle, original_mode);
                result
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            // Fallback for other platforms - use regular input (will show characters)
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            Ok(input.trim().to_string())
        }
    }

    #[cfg(any(unix, windows))]
    fn read_password_chars(&self) -> io::Result<String> {
        use std::io::{self, Write};

        let mut password = String::new();
        let mut visible = false;
        let mut cursor_pos = 0; // Cursor position in bytes
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut handle = stdin.lock();
        let mut buf = [0u8; 1];

        loop {
            handle.read_exact(&mut buf)?;
            let c = buf[0] as char;

            match c {
                '\x1b' => {
                    // Start of escape sequence - read next chars
                    let mut seq_buf = [0u8; 3];
                    handle.read_exact(&mut seq_buf[..2])?;
                    // Check for arrow keys: ESC [ <letter>
                    if seq_buf[0] == b'[' {
                        match seq_buf[1] {
                            b'D' => {
                                // Left arrow
                                if cursor_pos > 0 {
                                    // Move back one character (not byte)
                                    let prev_char_len = password[..cursor_pos]
                                        .chars()
                                        .last()
                                        .map(|c| c.len_utf8())
                                        .unwrap_or(1);
                                    cursor_pos -= prev_char_len;
                                    print!("\x08"); // Move cursor left
                                    stdout.flush()?;
                                }
                            }
                            b'C' => {
                                // Right arrow
                                if cursor_pos < password.len() {
                                    // Move forward one character (not byte)
                                    let next_char_len = password[cursor_pos..]
                                        .chars()
                                        .next()
                                        .map(|c| c.len_utf8())
                                        .unwrap_or(1);
                                    cursor_pos += next_char_len;
                                    print!("\x1b[C"); // Move cursor right
                                    stdout.flush()?;
                                }
                            }
                            b'3' => {
                                // Delete key (ESC [ 3 ~) - read the tilde
                                handle.read_exact(&mut seq_buf[2..3])?;
                                if seq_buf[2] == b'~' && cursor_pos < password.len() {
                                    // Remove character at cursor position
                                    password.remove(cursor_pos);
                                    // Redraw entire line from cursor position
                                    let rest: String = password[cursor_pos..].chars().collect();
                                    for _ in 0..=rest.len() {
                                        print!(" ");
                                    }
                                    for _ in 0..=rest.len() {
                                        print!("\x08");
                                    }
                                    // Redraw remaining characters
                                    if visible {
                                        print!("{}", rest);
                                    } else {
                                        for _ in 0..rest.chars().count() {
                                            print!("*");
                                        }
                                    }
                                    // Move cursor back to correct position
                                    for _ in 0..rest.chars().count() {
                                        print!("\x08");
                                    }
                                    stdout.flush()?;
                                }
                            }
                            b'A' | b'B' => {
                                // Up/Down arrows - ignore
                            }
                            _ => {}
                        }
                    }
                }
                '\t' => {
                    visible = !visible;
                    // Clear current display
                    let char_count = password.chars().count();
                    for _ in 0..char_count {
                        print!("\x08 \x08");
                    }
                    // Redraw in new mode
                    if visible {
                        print!("{}", password);
                    } else {
                        for _ in 0..char_count {
                            print!("*");
                        }
                    }
                    // Restore cursor position
                    let display_char_count = password.chars().count();
                    let cursor_char_pos = password[..cursor_pos].chars().count();
                    if cursor_char_pos < display_char_count {
                        for _ in cursor_char_pos..display_char_count {
                            print!("\x08");
                        }
                    }
                    stdout.flush()?;
                }
                '\n' | '\r' => {
                    // In raw mode with OPOST disabled, we need explicit CRLF
                    print!("\r\n");
                    stdout.flush()?;
                    break;
                }
                '\x08' | '\x7f' => {
                    // Backspace - delete character to the left of cursor
                    if cursor_pos > 0 {
                        // Find the character before cursor and get its byte length
                        let prev_char_len = password[..cursor_pos]
                            .chars()
                            .last()
                            .map(|c| c.len_utf8())
                            .unwrap_or(1);
                        // Move cursor back
                        let new_cursor_pos = cursor_pos - prev_char_len;
                        // Remove the character before cursor (at new_cursor_pos)
                        password.remove(new_cursor_pos);
                        // Update cursor position
                        cursor_pos = new_cursor_pos;
                        // Move visual cursor back one position
                        print!("\x08");
                        // Clear from new cursor position to end
                        let rest: String = password[cursor_pos..].chars().collect();
                        let rest_count = rest.chars().count();
                        // Print spaces to clear (1 for deleted char + rest)
                        for _ in 0..=rest_count {
                            print!(" ");
                        }
                        // Move cursor back to the start of cleared area
                        for _ in 0..=rest_count {
                            print!("\x08");
                        }
                        // Redraw remaining characters
                        if visible {
                            print!("{}", rest);
                        } else {
                            for _ in 0..rest_count {
                                print!("*");
                            }
                        }
                        // Move cursor back to correct position (at end of redrawn text)
                        for _ in 0..rest_count {
                            print!("\x08");
                        }
                        stdout.flush()?;
                    }
                }
                '\x03' | '\x1c' => {
                    // Ctrl+C (0x03) or Ctrl+\ (0x1c)
                    println!();
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Interrupted by user",
                    ));
                }
                c if c.is_ascii_graphic() => {
                    // Insert character at cursor position
                    password.insert(cursor_pos, c);
                    cursor_pos += c.len_utf8();
                    // Display the new character
                    if visible {
                        print!("{}", c);
                    } else {
                        print!("*");
                    }
                    // Redraw the rest of the line
                    let rest: String = password[cursor_pos..].chars().collect();
                    if visible {
                        print!("{}", rest);
                    } else {
                        for _ in 0..rest.chars().count() {
                            print!("*");
                        }
                    }
                    // Move cursor back to correct position
                    for _ in 0..rest.chars().count() {
                        print!("\x08");
                    }
                    stdout.flush()?;
                }
                _ => {}
            }
        }

        Ok(password)
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
        );

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

    fn add_feature(&mut self) -> io::Result<()> {
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

    fn view_decrypted(&self) -> io::Result<()> {
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
