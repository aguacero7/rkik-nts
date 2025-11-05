//! Common types used throughout the library.

use std::time::SystemTime;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Result of a time synchronization query.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeSnapshot {
    /// The current system time when the measurement was taken.
    pub system_time: SystemTime,

    /// The network time received from the NTP server.
    pub network_time: SystemTime,

    /// The offset between system time and network time.
    /// Positive means the system clock is ahead.
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
#[derive(Debug)]
pub struct NtsKeResult {
    /// The NTP server to use for time queries.
    pub ntp_server: std::net::SocketAddr,

    /// The negotiated AEAD algorithm.
    pub aead_algorithm: String,

    /// Cookies for NTS authentication.
    pub(crate) cookies: Vec<Vec<u8>>,

    /// Duration of the NTS-KE handshake (for diagnostics).
    pub(crate) ke_duration: std::time::Duration,

    /// The actual NTS data from ntp-proto (contains keys and cookies).
    pub(crate) nts_data: Box<ntp_proto::SourceNtsData>,
}

impl NtsKeResult {
    /// Create a new NtsKeResult from ntp-proto's KeyExchangeResult.
    pub(crate) fn new(
        ntp_server: std::net::SocketAddr,
        aead_algorithm: String,
        cookies: Vec<Vec<u8>>,
        ke_duration: std::time::Duration,
        nts_data: Box<ntp_proto::SourceNtsData>,
    ) -> Self {
        Self {
            ntp_server,
            aead_algorithm,
            cookies,
            ke_duration,
            nts_data,
        }
    }

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
    /// Returns cookie data as byte slices. Useful for verbose diagnostic
    /// output or logging.
    pub fn cookies_ref(&self) -> Vec<&[u8]> {
        self.cookies.iter().map(|c| c.as_slice()).collect()
    }
}
