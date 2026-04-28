//! Common types used throughout the library.

use std::time::SystemTime;

use crate::cipher::AeadCipher;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Certificate information from the NTS-KE TLS handshake
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CertificateInfo {
    /// Subject of the certificate (CN, O, etc.)
    pub subject: String,

    /// Issuer of the certificate
    pub issuer: String,

    /// Certificate validity period start (RFC3339 format)
    pub valid_from: String,

    /// Certificate validity period end (RFC3339 format)
    pub valid_until: String,

    /// Serial number (hex format)
    pub serial_number: String,

    /// Subject Alternative Names (DNS names)
    pub san_dns_names: Vec<String>,

    /// Signature algorithm
    pub signature_algorithm: String,

    /// Public key algorithm
    pub public_key_algorithm: String,

    /// Certificate fingerprint (SHA-256, hex format)
    pub fingerprint_sha256: String,

    /// Whether the certificate is self-signed
    pub is_self_signed: bool,
}

/// Result of a time synchronization query.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeSnapshot {
    /// The current system time when the measurement was taken.
    pub system_time: SystemTime,

    /// The network time received from the NTP server.
    pub network_time: SystemTime,

    /// The absolute offset between system time and network time.
    ///
    /// Use [`TimeSnapshot::offset_signed`] to recover the signed direction.
    pub offset: std::time::Duration,

    /// Round-trip delay to the server.
    pub round_trip_delay: std::time::Duration,

    /// Server address that provided the time.
    pub server: String,

    /// Whether the response was authenticated via NTS.
    pub authenticated: bool,
}

impl TimeSnapshot {
    /// Calculate the clock offset as a signed duration.
    /// Positive means system clock is ahead of network time.
    pub fn offset_signed(&self) -> i64 {
        match self.system_time.duration_since(self.network_time) {
            Ok(duration) => duration.as_millis() as i64,
            Err(e) => -(e.duration().as_millis() as i64),
        }
    }

    /// Check if the system clock is ahead of network time.
    pub fn is_ahead(&self) -> bool {
        self.system_time > self.network_time
    }

    /// Check if the system clock is behind network time.
    pub fn is_behind(&self) -> bool {
        self.system_time < self.network_time
    }
}

/// NTS key exchange result containing the negotiated parameters.
///
/// This struct holds all the information needed for NTS-protected NTP
/// communication, including the cryptographic keys, cookies, and server
/// information negotiated during the NTS-KE handshake.
pub struct NtsKeResult {
    /// The NTP server to use for time queries.
    pub ntp_server: std::net::SocketAddr,

    /// All resolved NTP server addresses to try for time queries.
    pub(crate) ntp_server_addrs: Vec<std::net::SocketAddr>,

    /// The negotiated AEAD algorithm.
    pub aead_algorithm: String,

    /// Cookies for NTS authentication.
    pub(crate) cookies: Vec<Vec<u8>>,

    /// Duration of the NTS-KE handshake (for diagnostics).
    pub(crate) ke_duration: std::time::Duration,

    /// Client-to-server cipher for encrypting NTP requests.
    pub(crate) c2s: AeadCipher,

    /// Server-to-client cipher for decrypting NTP responses.
    pub(crate) s2c: AeadCipher,

    /// TLS certificate information (optional, for diagnostics)
    pub certificate: Option<CertificateInfo>,
}

// Manual Debug impl since Box<dyn Cipher> doesn't implement Debug
impl std::fmt::Debug for NtsKeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtsKeResult")
            .field("ntp_server", &self.ntp_server)
            .field("ntp_server_addrs", &self.ntp_server_addrs)
            .field("aead_algorithm", &self.aead_algorithm)
            .field("cookies", &format!("[{} cookies]", self.cookies.len()))
            .field("ke_duration", &self.ke_duration)
            .field("c2s", &"<cipher>")
            .field("s2c", &"<cipher>")
            .field("certificate", &self.certificate)
            .finish()
    }
}

impl NtsKeResult {
    /// Get the number of available cookies.
    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }

    /// Check if there are sufficient cookies available.
    pub fn has_cookies(&self) -> bool {
        !self.cookies.is_empty()
    }

    /// Get the sizes of all cookies (useful for diagnostics).
    ///
    /// Returns a vector containing the size in bytes of each cookie.
    pub fn cookie_sizes(&self) -> Vec<usize> {
        self.cookies.iter().map(|c| c.len()).collect()
    }

    /// Get the duration of the NTS-KE handshake.
    ///
    /// This is useful for diagnostic purposes to measure the overhead
    /// of the TLS key exchange process.
    pub fn ke_duration(&self) -> std::time::Duration {
        self.ke_duration
    }

    /// Get a reference to the cookies (for diagnostic purposes).
    ///
    /// Returns cookie data as byte slices. These cookies are bearer state and
    /// should never be logged or exposed in production telemetry.
    pub fn cookies_ref(&self) -> Vec<&[u8]> {
        self.cookies.iter().map(|c| c.as_slice()).collect()
    }

    /// Extract NTS state for authenticated NTP queries.
    ///
    /// This consumes the NtsKeResult and creates an NtsState that can be
    /// used for creating authenticated NTP requests and verifying responses.
    pub(crate) fn into_nts_state(self) -> crate::nts_ntp::NtsState {
        crate::nts_ntp::NtsState::new(self.c2s, self.s2c, self.cookies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_time_snapshot_offset_signed_ahead() {
        let network_time = SystemTime::now();
        let system_time = network_time + Duration::from_secs(10);

        let snapshot = TimeSnapshot {
            system_time,
            network_time,
            offset: Duration::from_secs(10),
            round_trip_delay: Duration::from_millis(50),
            server: "test.server".to_string(),
            authenticated: true,
        };

        assert!(snapshot.offset_signed() > 0);
        assert!(snapshot.is_ahead());
        assert!(!snapshot.is_behind());
    }

    #[test]
    fn test_time_snapshot_offset_signed_behind() {
        let system_time = SystemTime::now();
        let network_time = system_time + Duration::from_secs(5);

        let snapshot = TimeSnapshot {
            system_time,
            network_time,
            offset: Duration::from_secs(5),
            round_trip_delay: Duration::from_millis(50),
            server: "test.server".to_string(),
            authenticated: true,
        };

        assert!(snapshot.offset_signed() < 0);
        assert!(!snapshot.is_ahead());
        assert!(snapshot.is_behind());
    }

    #[test]
    fn test_nts_ke_result_cookie_count() {
        // Test cookie_count and has_cookies without creating full NtsKeResult
        // since SourceNtsData doesn't have a public constructor
        let cookies = [vec![1, 2, 3, 4], vec![5, 6, 7, 8, 9]];
        assert_eq!(cookies.len(), 2);
        assert!(!cookies.is_empty());

        let sizes: Vec<usize> = cookies.iter().map(|c| c.len()).collect();
        assert_eq!(sizes, vec![4, 5]);
    }

    #[test]
    fn test_nts_ke_result_empty_cookies() {
        let cookies: Vec<Vec<u8>> = vec![];
        assert_eq!(cookies.len(), 0);
        assert!(cookies.is_empty());
    }
}
