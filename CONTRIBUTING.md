# Contributing to SaltPass

Thank you for your interest in contributing to SaltPass! This document provides guidelines for contributing to the project.

## Code of Conduct

Please be respectful and constructive in all interactions. We aim to maintain a welcoming and inclusive community.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Your environment (OS, Rust version)
- Any relevant logs or screenshots

### Suggesting Features

Feature suggestions are welcome! Please open an issue with:
- A clear description of the feature
- Use cases and benefits
- Any implementation ideas you have

### Pull Requests

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cargo test`)
5. Run clippy (`cargo clippy -- -D warnings`)
6. Format code (`cargo fmt`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/YanLien/SaltPass.git
cd SaltPass

# Build the project
cargo build

# Run tests
cargo test

# Run the application
cargo run
```

### Code Style

- Follow Rust standard formatting (`cargo fmt`)
- Pass all clippy lints (`cargo clippy -- -D warnings`)
- Write tests for new features
- Add documentation for public APIs
- Keep commits focused and atomic

### Testing

- Write unit tests for new functions
- Update integration tests if needed
- Ensure all tests pass before submitting PR
- Add tests for bug fixes to prevent regressions

### Documentation

- Update README.md if adding user-facing features
- Add doc comments for public APIs
- Update CHANGELOG.md with your changes
- Include examples in documentation where helpful

## Security

If you discover a security vulnerability, please email the maintainer directly instead of opening a public issue.

## License

By contributing to SaltPass, you agree that your contributions will be licensed under the MIT License.

## Questions?

Feel free to open an issue for any questions about contributing!
