# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.0.0] - 2026-04-28

### Added
- Complete self-contained RFC 8915 implementation for authenticated NTP queries
- Live network test suite behind the `network-tests` feature
- End-to-end coverage for Cloudflare and Netnod public NTS servers

### Changed
- Promoted crate version to `1.0.0` for stable integration into `rkik`
- Derived NTS exporter keys with the correct NTPv4 protocol context
- Serialized the NTS Authenticator (`0x0404`) in the server-compatible wire format
- Removed dependency on unstable packet-building assumptions from earlier iterations
- Changed crate author contact
- Changed License for MIT

### Fixed
- Public NTS queries now authenticate successfully against real servers such as `time.cloudflare.com` and `nts.ntp.se`
- PTB network coverage is treated as opportunistic in tests because PTB explicitly does not guarantee uninterrupted public service availability

### Documentation
- Updated crate docs, README and integration guidance for the `1.0.0` release line
- Removed outdated claims that the crate is based on `ntpd-rs`

## [0.4.0] - 2026-01-23

### Added
- Enforced NTS response validation for origin timestamps and Unique Identifiers
- Explicit error variants for missing cookies, missing authenticators, AEAD failures, and malformed NTS extensions
- New end-to-end example `nts_end_to_end` for authenticated NTS verification

### Fixed
- Reject unauthenticated NTP responses that lack NTS encrypted fields
- Simplified `PlatformVerifier` initialization in TLS config by migrating from deprecated `new_with_extra_roots()` to new `new()` constructor
  - Removed unnecessary error handling since `new()` returns `Self` directly and cannot fail
  - Updated [nts_ke.rs:305-306](src/nts_ke.rs#L305-L306) to use the new API
- Removed reference to non-existent `validation_client` example from Cargo.toml

### Documentation
- Updated README and INTEGRATION.md for version 0.4 usage and the new NTS validation example

## [0.3.0] - 2025-12-15

### Added
- **TLS Certificate Information Capture**: Full support for capturing and exposing TLS certificate details during NTS-KE handshake
  - New `CertificateInfo` struct with comprehensive certificate details:
    - Subject and Issuer information
    - Validity period (valid_from, valid_until)
    - Serial number (hex format)
    - Subject Alternative Names (SANs)
    - Signature and public key algorithms
    - SHA-256 fingerprint
    - Self-signed certificate detection
  - `certificate` field added to `NtsKeResult` (publicly accessible)
  - Custom `CapturingVerifier` that captures certificates while maintaining security
  - Works with both verified and unverified (self-signed) certificate modes
- New example `test_certificate` demonstrating certificate information extraction
- **TLS Keylog Support**: Added `SSLKEYLOGFILE` environment variable support for Wireshark decryption
  - Enables debugging of TLS-encrypted NTS-KE traffic
  - Automatically logs TLS session keys when `SSLKEYLOGFILE` is set
  - Useful for network analysis and troubleshooting
- Three new dependencies for certificate parsing:
  - `x509-parser = "0.18"` - X.509 certificate parsing
  - `sha2 = "0.10"` - SHA-256 fingerprint calculation
  - `chrono = "0.4"` - Date/time handling (transitive)

### Changed
- `NtsKeResult::new()` signature updated to accept `certificate: Option<CertificateInfo>`
- `build_tls_config()` now returns tuple with captured certificates container
- Enhanced debug logging to include certificate subject and issuer upon capture

### Security
- ✅ Certificate capture does NOT compromise security: all verification still delegated to platform verifier
- ✅ Works in both verified and unverified modes
- ✅ No changes to TLS handshake validation logic

### Documentation
- Added comprehensive inline documentation for `CertificateInfo` struct
- Updated examples to demonstrate certificate feature
- Certificate information is opt-in via `CertificateInfo` support with serde feature

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

[Unreleased]: https://github.com/aguacero7/rkik-nts/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/aguacero7/rkik-nts/compare/v0.4.0...v1.0.0
[0.4.0]: https://github.com/aguacero7/rkik-nts/compare/v0.3.0...v0.4.0
