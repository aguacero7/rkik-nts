//! # rkik-nts
//!
//! A high-level NTS (Network Time Security) client library for Rust.
//!
//! This library provides a simple, safe, and ergonomic API for querying time from NTS-secured NTP servers.
//! It handles the complexity of NTS key exchange and authenticated time synchronization, making it easy
//! to integrate secure time synchronization into your applications.
//!
//! ## Features
//!
//! - **Simple API**: Easy-to-use client interface with sensible defaults
//! - **Real NTS Authentication (RFC 8915)**: Proper cryptographic authentication of NTP queries
//! - **AEAD Protection**: All NTP packets are authenticated using negotiated AEAD algorithms
//! - **Anti-Replay**: Unique identifiers prevent replay attacks
//! - **Cookie Management**: Automatic cookie consumption and replenishment
//! - **Certificate Diagnostics**: TLS certificate information capture for security auditing
//! - **TLS Debugging**: SSLKEYLOGFILE support for Wireshark traffic analysis
//! - **Async/Await**: Built on Tokio for efficient async I/O
//! - **Configurable**: Flexible configuration options for advanced use cases
//! - **Self-contained RFC 8915 implementation**: NTS-KE and NTS-protected NTP implemented directly in this crate
//!
//! ## Security
//!
//! This library implements real NTS authentication according to RFC 8915:
//!
//! - **NTS-KE (Key Exchange)**: TLS handshake to negotiate AEAD algorithm and obtain keys
//! - **NTS-Protected NTP**: UDP packets contain NTS extension fields:
//!   - Unique Identifier (anti-replay)
//!   - NTS Cookie (authenticates client)
//!   - Cookie Placeholder (requests new cookies)
//!   - AEAD Authenticator (protects entire packet)
//!
//! All responses are cryptographically verified. Modified or spoofed responses are rejected.
//!
//! ## Quick Start
//!
//! ```no_run
//! use rkik_nts::{NtsClient, NtsClientConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a client configuration
//!     let config = NtsClientConfig::new("time.cloudflare.com");
//!
//!     // Create and connect the client
//!     let mut client = NtsClient::new(config);
//!     client.connect().await?;
//!
//!     // Query the current time (authenticated)
//!     let time = client.get_time().await?;
//!
//!     println!("Network time: {:?}", time.network_time);
//!     println!("System time:  {:?}", time.system_time);
//!     println!("Offset:       {} ms", time.offset_signed());
//!     println!("Authenticated: {}", time.authenticated);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Configuration
//!
//! The library supports extensive configuration through [`NtsClientConfig`]:
//!
//! ```
//! use rkik_nts::NtsClientConfig;
//! use std::time::Duration;
//!
//! let config = NtsClientConfig::new("time.cloudflare.com")
//!     .with_port(4460)
//!     .with_timeout(Duration::from_secs(5))
//!     .with_max_retries(3);
//! ```
//!
//! ## Certificate Information
//!
//! Access TLS certificate information from the NTS-KE handshake:
//!
//! ```no_run
//! use rkik_nts::{NtsClient, NtsClientConfig};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = NtsClientConfig::new("time.cloudflare.com");
//! let mut client = NtsClient::new(config);
//! client.connect().await?;
//!
//! // Access certificate and NTS-KE information
//! if let Some(ke_info) = client.nts_ke_info() {
//!     println!("AEAD Algorithm: {}", ke_info.aead_algorithm);
//!     println!("Initial Cookies: {}", ke_info.initial_cookie_count);
//!     if let Some(cert) = &ke_info.certificate {
//!         println!("Certificate Subject: {}", cert.subject);
//!         println!("Certificate Issuer: {}", cert.issuer);
//!         println!("Valid: {} to {}", cert.valid_from, cert.valid_until);
//!         println!("Fingerprint: {}", cert.fingerprint_sha256);
//!         println!("Self-signed: {}", cert.is_self_signed);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Integration with rkik
//!
//! This library is designed for seamless integration with rkik, but can also be used
//! as a standalone NTS client library in any Rust application.

#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

mod cipher;
pub mod client;
pub mod config;
pub mod error;
mod nts_ke;
pub(crate) mod nts_ntp;
pub mod types;

// Re-export main types for convenience
pub use client::{NtsClient, NtsKeInfo};
pub use config::NtsClientConfig;
pub use error::{Error, Result};
pub use types::{CertificateInfo, TimeSnapshot};
