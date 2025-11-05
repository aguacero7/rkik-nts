//! Configuration for NTS client.

use std::net::SocketAddr;
use std::time::Duration;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Configuration for an NTS client.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NtsClientConfig {
    /// The NTS key exchange server hostname.
    pub nts_ke_server: String,

    /// The NTS key exchange server port (default: 4460).
    pub nts_ke_port: u16,

    /// Timeout for network operations.
    pub timeout: Duration,

    /// Maximum number of retry attempts for failed operations.
    pub max_retries: u32,

    /// Whether to verify the server's TLS certificate.
    pub verify_tls_cert: bool,

    /// Optional: Specific NTP server address to use after key exchange.
    /// If None, uses the server provided during NTS-KE.
    pub ntp_server: Option<SocketAddr>,

    /// NTP version to use (default: 4).
    pub ntp_version: u8,
}

impl Default for NtsClientConfig {
    fn default() -> Self {
        Self {
            nts_ke_server: String::new(),
            nts_ke_port: 4460, // Standard NTS-KE port
            timeout: Duration::from_secs(10),
            max_retries: 3,
            verify_tls_cert: true,
            ntp_server: None,
            ntp_version: 4,
        }
    }
}

impl NtsClientConfig {
    /// Create a new configuration with the given NTS-KE server.
    ///
    /// # Arguments
    ///
    /// * `server` - The hostname or IP address of the NTS-KE server.
    ///
    /// # Examples
    ///
    /// ```
    /// use rkik_nts::config::NtsClientConfig;
    ///
    /// let config = NtsClientConfig::new("time.cloudflare.com");
    /// ```
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            nts_ke_server: server.into(),
            ..Default::default()
        }
    }

    /// Set the NTS-KE server port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.nts_ke_port = port;
        self
    }

    /// Set the timeout duration.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum number of retries.
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Set whether to verify TLS certificates.
    pub fn with_tls_verification(mut self, verify: bool) -> Self {
        self.verify_tls_cert = verify;
        self
    }

    /// Set a specific NTP server to use.
    pub fn with_ntp_server(mut self, server: SocketAddr) -> Self {
        self.ntp_server = Some(server);
        self
    }

    /// Set the NTP version.
    pub fn with_ntp_version(mut self, version: u8) -> Self {
        self.ntp_version = version;
        self
    }

    /// Validate the configuration.
    pub(crate) fn validate(&self) -> crate::error::Result<()> {
        if self.nts_ke_server.is_empty() {
            return Err(crate::error::Error::InvalidConfig(
                "NTS-KE server hostname is required".to_string(),
            ));
        }

        if self.ntp_version < 3 || self.ntp_version > 4 {
            return Err(crate::error::Error::InvalidConfig(
                "NTP version must be 3 or 4".to_string(),
            ));
        }

        Ok(())
    }
}
