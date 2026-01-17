# SaltPass

🔐 A deterministic password generator based on cryptographic algorithms. Just remember one salt, combine it with public feature identifiers, and generate unique strong passwords for every account. No password vault, no cloud sync, security in your control.

**[中文文档](README_CN.md)** | English Documentation

## ✨ Features

- 🔑 **Deterministic Generation**: Same salt + feature = same password, always
- 🧠 **Memory Only**: Master salt never touches disk
- 🔒 **Strong Encryption**: HMAC-SHA256 algorithm
- 📋 **Auto Clipboard**: Generated passwords auto-copy to clipboard
- 💾 **Local Storage**: Features stored in `~/.saltpass/features.toml`
- 🎨 **Beautiful CLI**: Interactive colorful command-line interface
- 🧹 **Memory Safety**: Auto-zero salt on exit using `zeroize`

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/YanLien/SaltPass.git
cd SaltPass

# Build and run
cargo run --release
```

### Build Binary

```bash
cargo build --release
# Binary will be at: ./target/release/SaltPass
```

## 📖 Usage

### Workflow

```
1. Launch application
      ↓
2. Enter master salt (stored in memory only)
      ↓
3. Choose action from menu
      ↓
4. Generate password / Add feature / Manage features
      ↓
5. Password auto-copied to clipboard
      ↓
6. Exit → salt cleared from memory
```

### Example Session

```bash
$ ./target/release/SaltPass

🔐 Welcome to SaltPass - Deterministic Password Generator
📁 Storage: /Users/username/.saltpass/features.toml

🔑 Enter your master salt (hidden): ********
✅ Salt accepted (stored in memory only)

? What would you like to do?
❯ Generate Password
  Add New Feature
  List All Features
  Delete Feature
  Exit
```

### Adding a Feature

```
Feature name: GitHub
Feature identifier: github.com
Hint: Personal account
✅ Feature 'GitHub' added successfully!
```

### Generating a Password

```
? Select a feature to generate password
❯ GitHub (github.com) - Personal account

Password length (12-64): 16

🎯 Generated Password:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Feature: GitHub (github.com)
Password: Xy3!bN7kLmP9QrSt
Length: 16
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 Password copied to clipboard!
```

## 🏗️ Architecture

### Data Structures

```rust
// Salt - stored in memory only, auto-zeroed on drop
struct Salt {
    salt_value: String  // Protected by zeroize
}

// Feature - stored on disk
struct Feature {
    name: String,           // Display name (e.g., "GitHub")
    feature: String,        // Identifier (e.g., "github.com")
    created: DateTime<Utc>, // Creation timestamp
    hint: Option<String>    // Optional reminder
}
```

### Password Generation Algorithm

```
Input: Salt + Feature
        ↓
    HMAC-SHA256
        ↓
    Base64 Encode
        ↓
Format & Strengthen (ensure uppercase, digit, special char)
        ↓
Output: Strong Password
```

## 🛠️ Technical Details

### Dependencies

- **serde**: Serialization/deserialization
- **serde_json**: JSON support (optional)
- **toml**: TOML storage format (default)
- **sha2**: SHA-256 hashing
- **hmac**: HMAC implementation
- **base64**: Base64 encoding
- **dialoguer**: Interactive CLI
- **arboard**: Clipboard integration
- **zeroize**: Secure memory zeroing
- **chrono**: Timestamp handling
- **dirs**: Platform-specific directories

### Storage Location

- **macOS/Linux**: `~/.saltpass/features.toml`
- **Windows**: `C:\Users\Username\.saltpass\features.toml`

### Security Features

1. **Memory Protection**: Salt uses `zeroize` crate with `ZeroizeOnDrop` trait
2. **No Disk Storage**: Master salt never written to disk
3. **Deterministic**: No randomness, reproducible passwords
4. **Offline First**: No network, no cloud, no third parties

## 🧪 Testing

```bash
# Run all tests
cargo test

# Test with verbose output
cargo test -- --nocapture
```

## 📝 Version Updates

To update a password (e.g., after a breach), modify the feature identifier:

```
Original: github.com
Updated:  github.com.v2
New:      github.com.v3
```

Each version generates a completely different password.

## 🗺️ Future Roadmap

### Password Management
- [ ] 🔄 **Password Versioning System**: Built-in version management for rotating passwords (e.g., `github.com.v2`)
- [ ] ⚙️ **Custom Password Policies**: Per-feature password strength configuration (length, character sets)
- [ ] 📊 **Usage Statistics**: Track last used, generation count, password age alerts
- [ ] 🔔 **Rotation Reminders**: Smart notifications for old passwords (90+ days)
- [ ] 📦 **Export/Import**: Backup and restore feature configurations (not passwords)

### Multi-Profile Support
- [ ] 🔐 **Multiple Salt Profiles**: Separate work/personal/family salt configurations
- [ ] 🏷️ **Feature Tagging**: Organize features by category (social, banking, work, etc.)
- [ ] 🔍 **Advanced Search**: Quick filter by tags, age, or usage frequency

### Security Enhancements
- [ ] 🗑️ **Auto-clear Clipboard**: Configurable timeout to clear copied passwords
- [ ] 🔒 **Optional Feature Encryption**: Encrypt stored feature names with master password
- [ ] 🔐 **Two-Factor Salt**: Combine master salt with device-specific salt
- [ ] 🛡️ **Breach Detection**: Check feature domains against known breach databases (offline)

### User Experience
- [ ] 🎨 **GUI Version**: Desktop app using egui/iced framework
- [ ] 🌐 **Browser Extension**: One-click password generation and auto-fill
- [ ] 📱 **Mobile Apps**: iOS/Android with cross-device feature sync
- [ ] ⌨️ **Quick Access Mode**: Hotkey-triggered floating window

### Cross-Platform
- [ ] ☁️ **Feature File Sync**: iCloud/Dropbox/Git sync for feature configurations
- [ ] 🔄 **Conflict Resolution**: Smart merge for multi-device feature updates
- [ ] 📲 **QR Code Transfer**: Quick feature transfer between devices

### Developer Features
- [ ] 🔌 **Plugin System**: Custom password generation algorithms
- [ ] 🛠️ **CLI Improvements**: Scripting support, JSON output, batch operations
- [ ] 📚 **API Library**: Use SaltPass as a Rust library in other projects

## Non-Goals

To maintain security and simplicity, we will **NOT** implement:
- ❌ Storing generated passwords (defeats deterministic purpose)
- ❌ Cloud password sync (increases attack surface)
- ❌ Password recovery without salt (impossible by design)
- ❌ Built-in password sharing (use deterministic generation instead)

## 📜 License

MIT License - see LICENSE file

## 🤝 Contributing

Contributions welcome! Please feel free to submit a Pull Request.

## ⚠️ Security Notice

### Critical: Master Salt Management

- **Remember your salt**: Lost salt = lost access to **ALL** passwords forever
- **Keep salt private**: Never share your master salt with anyone
- **Backup features**: Sync `~/.saltpass/features.toml` across devices
- **Use unique salt**: Different from any of your existing passwords

### Recommended Salt Backup Strategies

Choose **one or more** of these methods:

1. **Memory Palace** (Most Secure)
   - Create a memorable phrase/formula only you know
   - Example: "FirstPet + BirthYear + FavoriteColor" → Fluffy1990Blue
   - **DO NOT** write this formula down exactly

2. **Physical Backup** (Balanced)
   - Write salt on paper, store in safe deposit box
   - Split into parts, store in different secure locations
   - Use a password manager for the salt (ironically, but practical)

3. **Encrypted Digital Backup**
   - Store in encrypted USB drive in a safe place
   - Use KeePass/1Password just for the master salt
   - Encrypt with a separate passphrase and store locally

4. **Shamir's Secret Sharing** (Advanced)
   - Split salt into 3 parts, need any 2 to recover
   - Give parts to trusted family/friends
   - Use tools like `ssss` (Shamir's Secret Sharing Scheme)

### What If I Forget My Salt?

**There is NO recovery option.** This is by design for maximum security.

If you lose your salt:
1. Export your feature list: `~/.saltpass/features.toml`
2. Visit each website and use "Forgot Password"
3. Create a NEW salt and start fresh
4. Delete old features, add new ones with new passwords

### Salt Verification

When first setting up, SaltPass will:
- Ask for an optional hint (stored locally)
- Create a verification hash (to confirm correct salt entry)
- **Never store the actual salt**
