# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

- Ensured IPv6 compatibility with bind address being either `0.0.0.0:0` or `[::]:0`

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
