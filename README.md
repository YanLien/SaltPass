# SaltPass

🔐 A deterministic password generator based on cryptographic algorithms. Just remember one salt, combine it with public feature identifiers, and generate unique strong passwords for every account. No password vault, no cloud sync, security in your control.

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

- [ ] 🔐 Multiple salt profiles (work/personal)
- [ ] 📱 Cross-device sync (iCloud/self-hosted)
- [ ] 🔄 Password versioning UI
- [ ] 🌐 Browser extension
- [ ] 🗑️ Auto-clear clipboard after timeout
- [ ] 🔐 Optional feature encryption
- [ ] 🎨 GUI version (egui/iced)

## 📜 License

MIT License - see LICENSE file

## 🤝 Contributing

Contributions welcome! Please feel free to submit a Pull Request.

## ⚠️ Security Notice

- **Remember your salt**: Lost salt = lost access to all passwords
- **Keep salt private**: Never share your master salt
- **Backup features**: Sync `~/.saltpass/features.toml` across devices
- **Use unique salt**: Different from your passwords
