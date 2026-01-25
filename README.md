# SaltPass

🔐 A deterministic password generator based on cryptographic algorithms. Just remember one salt, combine it with public feature identifiers, and generate unique strong passwords for every account. No password vault, no cloud sync, security in your control.

**[中文文档](README_CN.md)** | English Documentation

## ✨ Features

- 🔑 **Deterministic Generation**: Same salt + feature = same password, always
- 🧠 **Memory Only**: Master salt never touches disk
- 🔒 **Multiple Algorithms**: HMAC-SHA256, Argon2i, Argon2id, Pbkdf2, Scrypt
- 📋 **Auto Clipboard**: Generated passwords auto-copy to clipboard
- 💾 **Local Storage**: Features stored in `~/.saltpass/features.toml`
- 🎨 **Beautiful CLI**: Interactive colorful command-line interface
- 🧹 **Memory Safety**: Auto-zero salt on exit using `zeroize`
- ⚙️ **Per-Feature Algorithm**: Choose different algorithms for each feature
- 🔐 **File Encryption** (Experimental): AES-256-GCM encryption for stored features
- 📁 **Multiple Formats**: Support for TOML and JSON storage formats
- ⌨️ **Enhanced Input**: Arrow key navigation, delete support, show/hide toggle

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

? Select password generation algorithm
❯ HMAC-SHA256 - Fast (Recommended for password generation)
  Argon2i - Memory-hard (Slower, more secure)
  Argon2id - Hybrid (Balanced)
  PBKDF2 - Standard (Compatible)
  Scrypt - Memory-hard (Slower)

Hint (optional, press Enter to skip): Personal account
✅ Feature 'GitHub' added successfully!
```

### Generating a Password

```
? Select a feature to generate password
❯ [HMAC-SHA256] GitHub (github.com) - Personal account

Password length (12-64): 16

🎯 Generated Password:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Feature: GitHub (github.com)
Algorithm: HMAC-SHA256
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
    algorithm: Algorithm,   // Password generation algorithm
    created: DateTime<Utc>, // Creation timestamp
    hint: Option<String>    // Optional reminder
}

// Algorithm - available password generation algorithms
enum Algorithm {
    HmacSha256,   // Fast (default, recommended)
    Argon2i,      // Memory-hard (slower)
    Argon2id,     // Hybrid mode
    Pbkdf2,       // Standard PBKDF2-HMAC-SHA256
    Scrypt,       // Memory-hard (slower)
}
```

### Password Generation Algorithm

```
Input: Salt + Feature + Algorithm
        ↓
    Key Derivation Function (KDF)
        ↓
    (HMAC-SHA256 | Argon2i | Argon2id | PBKDF2 | Scrypt)
        ↓
    Base64 Encode
        ↓
Format & Strengthen (ensure uppercase, digit, special char)
        ↓
Output: Strong Password
```

### Supported Algorithms

| Algorithm | Type | Speed | Security | Use Case |
|-----------|------|-------|----------|----------|
| **HMAC-SHA256** | Fast | ⚡⚡⚡ | 🔒🔒🔒 | Default, recommended for password generation |
| **Argon2i** | Memory-hard | ⚡ | 🔒🔒🔒🔒 | Maximum security, slower |
| **Argon2id** | Hybrid | ⚡⚡ | 🔒🔒🔒🔒 | Balanced security/performance |
| **PBKDF2** | Standard | ⚡⚡ | 🔒🔒🔒 | Wide compatibility |
| **Scrypt** | Memory-hard | ⚡ | 🔒🔒🔒🔒 | ASIC-resistant, slower |

## 🛠️ Technical Details

### Dependencies

- **serde**: Serialization/deserialization
- **serde_json**: JSON support (optional)
- **toml**: TOML storage format (default)
- **sha2**: SHA-256 hashing
- **hmac**: HMAC implementation
- **argon2**: Argon2i/Argon2id password hashing
- **pbkdf2**: PBKDF2-HMAC-SHA256
- **scrypt**: Scrypt password hashing
- **base64**: Base64 encoding
- **dialoguer**: Interactive CLI
- **arboard**: Clipboard integration
- **zeroize**: Secure memory zeroing
- **chrono**: Timestamp handling
- **dirs**: Platform-specific directories

### Storage Location

- **macOS/Linux**: `~/.saltpass/features.toml`
- **Windows**: `C:\Users\Username\.saltpass\features.toml`

### Encryption (Experimental)

⚠️ **WARNING**: Encryption is experimental. If you forget your master salt, your data cannot be recovered.

**Encrypted Storage** (`*.enc` files):
- Features encrypted with AES-256-GCM
- Uses your master salt as the encryption key
- Same password = same decryption key
- Provides at-rest encryption for feature data

**Plain Text Storage** (recommended):
- Features stored as readable TOML/JSON
- Easier to backup and view
- Can be edited manually if needed
- No risk of data loss from forgotten password

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

## 🗺️ Roadmap

### Recent Enhancements (v0.1.2)
- [x] 🔐 **Feature File Encryption** (Experimental): AES-256-GCM encryption for stored features
- [x] 📁 **Multiple Storage Formats**: TOML and JSON support
- [x] ⌨️ **Enhanced Password Input**: Arrow keys, delete key, visual cursor feedback
- [x] 🌐 **Internationalization**: Chinese (Simplified) support

### Planned Enhancements
- [ ] 📦 **Export/Import**: Backup and restore feature configurations
- [ ] 🔑 **Device-based Encryption**: Use device UUID as encryption key
- [ ] 🗑️ **Auto-clear Clipboard**: Configurable timeout to clear copied passwords
- [ ] 🛠️ **CLI Improvements**: Scripting support, JSON output, batch operations

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
