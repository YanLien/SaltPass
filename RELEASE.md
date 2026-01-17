# Release Guide

This document outlines the steps to release a new version of SaltPass.

## Prerequisites

1. Ensure you have a crates.io account and API token
2. Configure your crates.io token:
   ```bash
   cargo login <your-api-token>
   ```

## Release Process

### 1. Update Version

Update the version in `Cargo.toml`:
```toml
[package]
version = "0.2.0"  # or whatever the new version is
```

### 2. Update CHANGELOG.md

Add a new section for the release with:
- Release date
- Added features
- Changed functionality
- Deprecated features
- Removed features
- Fixed bugs
- Security updates

Example:
```markdown
## [0.2.0] - 2026-01-20

### Added
- New feature X
- New feature Y

### Fixed
- Bug Z
```

### 3. Commit Changes

```bash
git add .
git commit -m "Bump version to 0.2.0"
git push origin main
```

### 4. Create Git Tag

```bash
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

This will trigger the release workflow which will:
- Build binaries for Linux, macOS, and Windows
- Create a GitHub release
- Automatically publish to crates.io

### 5. Manual crates.io Publish (if needed)

If you prefer to publish manually:

```bash
# Dry run to check everything
cargo publish --dry-run

# Actual publish
cargo publish
```

## GitHub Secrets Setup

For automated releases, you need to set up these secrets in your GitHub repository:

1. **CARGO_REGISTRY_TOKEN**: Your crates.io API token
   - Go to https://crates.io/settings/tokens
   - Generate a new token
   - Add it to GitHub Secrets

2. **GITHUB_TOKEN**: Automatically provided by GitHub Actions

## Post-Release

1. Verify the release on GitHub releases page
2. Verify the package on crates.io
3. Test installation: `cargo install SaltPass`
4. Update documentation if needed
5. Announce the release (Twitter, Reddit, etc.)

## Version Numbering

Follow [Semantic Versioning](https://semver.org/):
- **MAJOR** version for incompatible API changes
- **MINOR** version for backward-compatible functionality additions
- **PATCH** version for backward-compatible bug fixes

## Troubleshooting

### Build fails on specific platform
- Check the CI logs in GitHub Actions
- Test locally with cross-compilation if possible
- Fix platform-specific issues

### crates.io publish fails
- Ensure all required metadata is in Cargo.toml
- Check that README.md and LICENSE files exist
- Verify package builds with `cargo package --list`

### Release workflow doesn't trigger
- Ensure tag format is `v*` (e.g., v0.2.0)
- Check GitHub Actions permissions
- Verify workflow file syntax
