# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-01-24

### Changed
- **Windows API migration**: Replaced deprecated `winapi` crate with modern `windows-sys 0.59`
- **Updated console API calls**: Migrated Windows console mode API to use `windows-sys` interface

### Fixed
- Fixed test case in `storage.rs` to include required `algorithm` parameter

## [0.1.1] - 2026-01-24

### Added
- **Multiple password generation algorithms**: Support for HMAC-SHA256, Argon2i, Argon2id, PBKDF2, and Scrypt
- **Per-feature algorithm selection**: Each feature can now use a different password generation algorithm
- **Algorithm information display**: Show the algorithm used for each feature in password generation and list views
- **Algorithm comparison**: Added documentation comparing speed, security, and use cases for each algorithm

### Changed
- **Feature data structure**: Added `algorithm` field to `Feature` struct (defaults to HMAC-SHA256 for backward compatibility)
- **CLI workflow**: Algorithm selection prompt added to the "Add New Feature" flow
- **Password generation output**: Now displays the algorithm used alongside the generated password

### Technical
- Added `argon2` crate for Argon2i/Argon2id support
- Added `pbkdf2` crate with `simple` feature for PBKDF2-HMAC-SHA256
- Added `scrypt` crate for Scrypt password hashing
- Implemented `derive_argon2()`, `derive_pbkdf2()`, and `derive_scrypt()` functions in `PasswordGenerator`
- Made `Algorithm` enum serializable with `serde` for persistence

## [0.1.0] - 2026-01-17

### Added
- Initial release of SaltPass
- Deterministic password generation using HMAC-SHA256
- Master salt stored in memory only with automatic zeroing
- Feature management (add, list, delete)
- Interactive CLI with colorful interface
- Password auto-copy to clipboard
- TOML storage format for features
- JSON storage format support
- Cross-platform support (Linux, macOS, Windows)
- Comprehensive test suite
- Security audit integration

### Security
- Memory protection using `zeroize` crate
- No disk storage of master salt
- Offline-first design (no network required)

[Unreleased]: https://github.com/YanLien/SaltPass/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/YanLien/SaltPass/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/YanLien/SaltPass/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/YanLien/SaltPass/releases/tag/v0.1.0
