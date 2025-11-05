//! Error types for the NTS client library.

use std::io;
use thiserror::Error;

/// Result type for NTS operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during NTS client operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Network I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// TLS/connection error during NTS key exchange.
    #[error("TLS error: {0}")]
    Tls(String),

    /// NTS key exchange failed.
    #[error("NTS key exchange failed: {0}")]
    KeyExchange(String),

    /// NTP protocol error.
    #[error("NTP protocol error: {0}")]
    Protocol(String),

    /// Invalid server response.
    #[error("Invalid server response: {0}")]
    InvalidResponse(String),

    /// Timeout occurred during operation.
    #[error("Operation timed out")]
    Timeout,

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Server not available or unreachable.
    #[error("Server unreachable: {0}")]
    ServerUnavailable(String),

    /// Authentication failed.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Generic error.
    #[error("{0}")]
    Other(String),
}

impl From<rustls::Error> for Error {
    fn from(err: rustls::Error) -> Self {
        Error::Tls(err.to_string())
    }
}
