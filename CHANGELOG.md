# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/YanLien/SaltPass/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YanLien/SaltPass/releases/tag/v0.1.0
