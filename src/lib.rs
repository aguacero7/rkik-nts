//! # rkik-nts
//!
//! A high-level NTS (Network Time Security) Client library based on ntpd-rs from the Pendulum Project.
//!
//! This library provides a simple, safe, and ergonomic API for querying time from NTS-secured NTP servers.
//! It handles the complexity of NTS key exchange and authenticated time synchronization, making it easy
//! to integrate secure time synchronization into your applications.
//!
//! ## Features
//!
//! - **Simple API**: Easy-to-use client interface with sensible defaults
//! - **NTS Support**: Full Network Time Security implementation for authenticated time
//! - **Async/Await**: Built on Tokio for efficient async I/O
//! - **Configurable**: Flexible configuration options for advanced use cases
//! - **Based on ntpd-rs**: Built on the battle-tested ntpd-rs implementation from Project Pendulum
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
//!     // Query the current time
//!     let time = client.get_time().await?;
//!
//!     println!("Network time: {:?}", time.network_time);
//!     println!("System time:  {:?}", time.system_time);
//!     println!("Offset:       {:?}", time.offset);
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
//! ## Integration with rkik
//!
//! This library is designed for seamless integration with rkik, but can also be used
//! as a standalone NTS client library in any Rust application.

#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod client;
pub mod config;
pub mod error;
mod nts_ke;
pub mod types;

// Re-export main types for convenience
pub use client::NtsClient;
pub use config::NtsClientConfig;
pub use error::{Error, Result};
pub use types::{NtsKeResult, TimeSnapshot};
