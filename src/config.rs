//! Configuration for NTS client.

use std::net::SocketAddr;
use std::time::Duration;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// IP address family restriction for NTS-KE and NTP traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AddressFamily {
    /// Use whatever the resolver returns (IPv6 is preferred for NTP when available).
    #[default]
    Any,
    /// Only use IPv4 addresses.
    Ipv4,
    /// Only use IPv6 addresses.
    Ipv6,
}

impl AddressFamily {
    /// Whether `addr` is allowed by this restriction.
    pub fn matches(self, addr: &SocketAddr) -> bool {
        match self {
            AddressFamily::Any => true,
            AddressFamily::Ipv4 => addr.is_ipv4(),
            AddressFamily::Ipv6 => addr.is_ipv6(),
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AddressFamily::Any => "IP",
            AddressFamily::Ipv4 => "IPv4",
            AddressFamily::Ipv6 => "IPv6",
        })
    }
}

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

    /// Maximum number of retry attempts for time queries after transport or
    /// validation failures.
    pub max_retries: u32,

    /// Whether to verify the server's TLS certificate.
    ///
    /// Disabling certificate verification is rejected unless the crate is
    /// compiled with the `dangerous-configuration` feature.
    pub verify_tls_cert: bool,

    /// Optional override for the NTP server address to use after key exchange.
    ///
    /// When set, this overrides the server/port negotiated by NTS-KE.
    pub ntp_server: Option<SocketAddr>,

    /// NTP version to use.
    ///
    /// Only NTPv4 is supported by this crate.
    pub ntp_version: u8,

    /// Restrict NTS-KE and NTP traffic to one IP address family.
    ///
    /// Applies to the addresses resolved for the NTS-KE server and to the NTP
    /// server negotiated during key exchange. Defaults to [`AddressFamily::Any`].
    #[cfg_attr(feature = "serde", serde(default))]
    pub address_family: AddressFamily,
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
            address_family: AddressFamily::Any,
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

    /// Set the maximum number of retries for time queries.
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
    ///
    /// Only version 4 is supported.
    pub fn with_ntp_version(mut self, version: u8) -> Self {
        self.ntp_version = version;
        self
    }

    /// Restrict NTS-KE and NTP traffic to one IP address family.
    ///
    /// # Examples
    ///
    /// ```
    /// use rkik_nts::{AddressFamily, NtsClientConfig};
    ///
    /// let config = NtsClientConfig::new("time.cloudflare.com")
    ///     .with_address_family(AddressFamily::Ipv6);
    /// ```
    pub fn with_address_family(mut self, family: AddressFamily) -> Self {
        self.address_family = family;
        self
    }

    /// Validate the configuration.
    pub(crate) fn validate(&self) -> crate::error::Result<()> {
        if self.nts_ke_server.is_empty() {
            return Err(crate::error::Error::InvalidConfig(
                "NTS-KE server hostname is required".to_string(),
            ));
        }

        if self.timeout.is_zero() {
            return Err(crate::error::Error::InvalidConfig(
                "timeout must be greater than zero".to_string(),
            ));
        }

        if self.ntp_version != 4 {
            return Err(crate::error::Error::InvalidConfig(
                "only NTPv4 is supported".to_string(),
            ));
        }

        if let Some(addr) = self.ntp_server {
            if !self.address_family.matches(&addr) {
                return Err(crate::error::Error::InvalidConfig(format!(
                    "NTP server override {addr} is not an {} address",
                    self.address_family
                )));
            }
        }

        if !self.verify_tls_cert && !cfg!(feature = "dangerous-configuration") {
            return Err(crate::error::Error::InvalidConfig(
                "TLS verification can only be disabled with the dangerous-configuration feature"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NtsClientConfig::default();
        assert_eq!(config.nts_ke_server, ""); // Default is empty
        assert_eq!(config.nts_ke_port, 4460);
        assert_eq!(config.ntp_version, 4);
        assert!(config.verify_tls_cert);
        // Default config with empty server should fail validation
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_builder_pattern() {
        let config = NtsClientConfig::new("custom.server.com")
            .with_port(1234)
            .with_timeout(std::time::Duration::from_secs(10))
            .with_max_retries(5);

        assert_eq!(config.nts_ke_server, "custom.server.com");
        assert_eq!(config.nts_ke_port, 1234);
        assert_eq!(config.timeout, std::time::Duration::from_secs(10));
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_empty_server_validation() {
        let config = NtsClientConfig {
            nts_ke_server: String::new(),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("hostname is required"));
    }

    #[test]
    fn test_invalid_ntp_version() {
        let config = NtsClientConfig {
            ntp_version: 3,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = NtsClientConfig {
            ntp_version: 5,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_valid_ntp_versions() {
        let config4 = NtsClientConfig::new("test.server.com").with_ntp_version(4);
        assert!(config4.validate().is_ok());
    }

    #[test]
    fn test_tls_verification_disable() {
        let config = NtsClientConfig::new("test.server.com").with_tls_verification(false);
        assert!(!config.verify_tls_cert);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_address_family_defaults_to_any() {
        let config = NtsClientConfig::new("test.server.com");
        assert_eq!(config.address_family, AddressFamily::Any);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_address_family_matches() {
        let v4: SocketAddr = "192.0.2.1:123".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:123".parse().unwrap();
        assert!(AddressFamily::Any.matches(&v4) && AddressFamily::Any.matches(&v6));
        assert!(AddressFamily::Ipv4.matches(&v4) && !AddressFamily::Ipv4.matches(&v6));
        assert!(AddressFamily::Ipv6.matches(&v6) && !AddressFamily::Ipv6.matches(&v4));
    }

    #[test]
    fn test_ntp_server_override_must_match_address_family() {
        let config = NtsClientConfig::new("test.server.com")
            .with_ntp_server("192.0.2.1:123".parse().unwrap())
            .with_address_family(AddressFamily::Ipv6);
        assert!(config.validate().is_err());

        let config = NtsClientConfig::new("test.server.com")
            .with_ntp_server("[2001:db8::1]:123".parse().unwrap())
            .with_address_family(AddressFamily::Ipv6);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_zero_timeout_is_invalid() {
        let config = NtsClientConfig::new("test.server.com").with_timeout(Duration::ZERO);
        assert!(config.validate().is_err());
    }
}
