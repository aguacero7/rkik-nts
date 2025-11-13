# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.2.0] - 2025-11-13

### Fixed
- **CRITICAL**: Fixed CI/CD typo "carbo" → "cargo"
- **CRITICAL**: Removed hardcoded localhost fallback that could cause security issues
- **CRITICAL**: Replaced dangerous unwraps with proper error handling
- Fixed dead_code warning on `nts_data` field
- Corrected .gitignore configuration
- IPv6 compatibility: bind address now correctly uses `[::]:0` for IPv6 or `0.0.0.0:0` for IPv4 based on remote server detection

### Added
- 13 new unit tests for core functionality
- `cargo test` integration in CI/CD pipeline
- Comprehensive test suite (all 13 tests passing)
- `rust-version` specification in Cargo.toml
- Documentation for `__internal-test` feature with TODO for future migration

### Changed
- Updated GitHub repository URL
- Optimized tokio feature flags for better performance
- Bumped dependencies:
  - thiserror = "2.0.17"
  - webpki-roots = "1.0.4"

### Quality Improvements
- ✅ All tests passing (13 unit tests)
- ✅ Clippy clean with `-D warnings`
- ✅ Release build compiles without errors

## [0.1.0] - 2025-11-05

### Added
- Initial release of rkik-nts library
- High-level NTS (Network Time Security) client implementation
- Full NTS-KE (Key Exchange) protocol support over TLS
- Async/await API built on Tokio
- `NtsClient` - Main client for querying NTS-secured NTP servers
- `NtsClientConfig` - Builder pattern configuration
- `TimeSnapshot` - Structured time query results with offset and authentication info
- Comprehensive error handling with custom error types
- Support for multiple public NTS servers
- TLS certificate verification with system certificates and webpki-roots
- Configurable timeouts, retries, and NTP versions
- Two example programs: `simple_client` and `custom_config`
- Full documentation with inline examples
- Integration tests
- Based on ntpd-rs from the Pendulum Project

### Documentation
- Comprehensive README with quick start guide
- API documentation for all public types
- Contributing guidelines
- Examples of basic and advanced usage
- List of public NTS servers for testing

[Unreleased]: https://github.com/aguacero7/rkik-nts/compare/v0.1.0...HEAD
