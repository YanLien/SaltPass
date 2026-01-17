//! Command-line interface for SaltPass
//!
//! This module provides an interactive CLI for managing features and generating passwords.

use crate::crypto::PasswordGenerator;
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
        println!("🔑 Enter your master salt (input will show asterisks):");
        let salt_input = self.read_password_with_asterisks()?;
        
        if salt_input.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Salt cannot be empty"));
        }

        self.salt = Some(Salt::new(salt_input));
        println!("✅ Salt accepted (stored in memory only)");
        println!();

        Ok(())
    }

    /// Read password with asterisk feedback
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
                // Enable signal interrupt (ISIG) to allow Ctrl+C / Cmd+C to work
                termios.c_lflag |= libc::ISIG;
                
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
            use winapi::um::wincon::{ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode, SetConsoleMode};
            
            let stdin = io::stdin();
            let handle = stdin.as_raw_handle();
            
            let mut original_mode = 0u32;
            unsafe {
                if GetConsoleMode(handle, &mut original_mode) == 0 {
                    return Err(io::Error::last_os_error());
                }
                
                let new_mode = original_mode & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
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
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut handle = stdin.lock();
        let mut buf = [0u8; 1];
        
        loop {
            handle.read_exact(&mut buf)?;
            let c = buf[0] as char;
            
            match c {
                '\n' | '\r' => {
                    println!();
                    break;
                }
                '\x08' | '\x7f' => {
                    // Backspace
                    if !password.is_empty() {
                        password.pop();
                        // Move cursor back, clear character, move back again
                        print!("\x08 \x08");
                        stdout.flush()?;
                    }
                }
                '\x03' => {
                    // Ctrl+C
                    println!();
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "Interrupted by user"));
                }
                c if c.is_ascii_graphic() => {
                    password.push(c);
                    print!("*");
                    stdout.flush()?;
                }
                _ => {
                    // Ignore other control characters
                }
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
