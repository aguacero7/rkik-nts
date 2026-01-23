//! NTS-aware NTP packet handling (RFC 8915).
//!
//! This module provides the cryptographic authentication layer for NTP packets
//! using the Network Time Security (NTS) protocol. It handles:
//!
//! - Building NTP requests with NTS extension fields (Unique ID, Cookie, Authenticator)
//! - AEAD authentication of outgoing packets
//! - Verification and decryption of incoming responses
//! - Cookie management (consumption and replenishment)

use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ntp_proto::{Cipher, NtpPacket, PacketParsingError, PollInterval};
use tracing::{debug, trace, warn};

use crate::error::{Error, Result};

/// Maximum size of an NTS-protected NTP packet buffer.
const NTS_PACKET_BUFFER_SIZE: usize = 1024;

/// NTP header length in bytes.
const NTP_HEADER_LEN: usize = 48;

/// Minimum number of cookies to maintain before requesting more.
const MIN_COOKIE_COUNT: usize = 4;

/// Number of new cookies to request when the pool is low.
const COOKIES_TO_REQUEST: u8 = 8;

/// Manages NTS state for authenticated NTP queries.
///
/// This struct holds the cryptographic keys and cookies needed for NTS-protected
/// NTP communication. It provides methods to create authenticated requests and
/// verify authenticated responses.
pub struct NtsState {
    /// Client-to-server encryption key.
    c2s: Box<dyn Cipher>,
    /// Server-to-client decryption key.
    s2c: Box<dyn Cipher>,
    /// Pool of available cookies.
    cookies: Vec<Vec<u8>>,
    /// Time when the last request was sent (for RTT calculation).
    send_time: Option<SystemTime>,
    /// Validation context for the last request.
    last_request: Option<RequestValidation>,
}

// Manual Debug impl since Box<dyn Cipher> doesn't implement Debug
impl std::fmt::Debug for NtsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtsState")
            .field("c2s", &"<cipher>")
            .field("s2c", &"<cipher>")
            .field("cookies", &format!("[{} cookies]", self.cookies.len()))
            .field("send_time", &self.send_time)
            .field("has_request", &self.last_request.is_some())
            .finish()
    }
}

#[derive(Debug, Clone)]
struct RequestValidation {
    expected_origin: [u8; 8],
    unique_id: Vec<u8>,
    requested_cookies: u8,
}

impl NtsState {
    /// Create a new NtsState from NTS-KE negotiated parameters.
    ///
    /// # Arguments
    ///
    /// * `c2s` - Client-to-server cipher for encrypting requests
    /// * `s2c` - Server-to-client cipher for decrypting responses
    /// * `cookies` - Initial pool of cookies from NTS-KE
    pub fn new(c2s: Box<dyn Cipher>, s2c: Box<dyn Cipher>, cookies: Vec<Vec<u8>>) -> Self {
        debug!("Creating NtsState with {} cookies", cookies.len());
        Self {
            c2s,
            s2c,
            cookies,
            send_time: None,
            last_request: None,
        }
    }

    /// Get the number of available cookies.
    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }

    /// Check if we have any cookies available.
    pub fn has_cookies(&self) -> bool {
        !self.cookies.is_empty()
    }

    /// Check if we should request more cookies.
    pub fn needs_more_cookies(&self) -> bool {
        self.cookies.len() < MIN_COOKIE_COUNT
    }

    /// Add a new cookie to the pool.
    pub fn store_cookie(&mut self, cookie: Vec<u8>) {
        trace!("Storing new cookie ({} bytes)", cookie.len());
        self.cookies.push(cookie);
    }

    /// Create an NTS-authenticated NTP request packet.
    ///
    /// This builds an NTP packet with:
    /// - A random transmit timestamp
    /// - Unique Identifier extension field (anti-replay)
    /// - NTS Cookie extension field
    /// - Cookie Placeholder extension fields (if more cookies needed)
    /// - AEAD authenticator
    ///
    /// # Returns
    ///
    /// The serialized NTS-protected NTP packet ready for transmission.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No cookies are available
    /// - Packet serialization fails
    pub fn create_request(&mut self, poll_interval: PollInterval) -> Result<Vec<u8>> {
        // Get a cookie from the pool
        let cookie = self.cookies.pop().ok_or_else(|| Error::MissingNtsCookie)?;

        debug!(
            "Creating NTS request with cookie ({} bytes), {} cookies remaining",
            cookie.len(),
            self.cookies.len()
        );

        // Determine how many new cookies to request
        let new_cookies = if self.needs_more_cookies() {
            // Request more cookies, but limit based on packet size
            let max_cookies =
                ((NTS_PACKET_BUFFER_SIZE - 300) / cookie.len().max(1)).min(u8::MAX as usize) as u8;
            max_cookies.min(COOKIES_TO_REQUEST)
        } else {
            1 // Always request at least one to maintain the pool
        };

        // Create the NTS poll message using ntp-proto
        // This generates:
        // - A unique identifier extension field
        // - The cookie extension field
        // - Cookie placeholder extension fields
        // - Proper NTP header with random transmit timestamp
        let (packet, _request_id) =
            NtpPacket::nts_poll_message(&cookie, new_cookies, poll_interval);

        // Record the send time for RTT calculation
        self.send_time = Some(SystemTime::now());

        // Serialize the packet with AEAD encryption
        let mut buffer = [0u8; NTS_PACKET_BUFFER_SIZE];
        let mut cursor = Cursor::new(buffer.as_mut_slice());

        // Use the c2s cipher for encryption
        if let Err(e) = packet.serialize(&mut cursor, &*self.c2s, None) {
            self.cookies.push(cookie);
            return Err(Error::Protocol(format!(
                "Failed to serialize NTS packet: {}",
                e
            )));
        }

        let len = cursor.position() as usize;
        let result = buffer[..len].to_vec();

        let request_validation = match extract_request_validation(&result, new_cookies) {
            Ok(validation) => validation,
            Err(err) => {
                // Return the cookie to the pool on internal validation failures.
                self.cookies.push(cookie);
                return Err(err);
            }
        };
        self.last_request = Some(request_validation);

        debug!("Created NTS request: {} bytes", result.len());
        Ok(result)
    }

    /// Parse and verify an NTS-authenticated NTP response.
    ///
    /// This verifies:
    /// - AEAD authenticator is valid
    /// - Packet structure is correct
    /// - Unique Identifier and origin timestamp match the request
    ///
    /// On success, extracts new cookies from the response and returns the parsed data.
    ///
    /// # Arguments
    ///
    /// * `data` - The received NTP response packet
    ///
    /// # Returns
    ///
    /// The parsed NTS response containing timestamps and authentication status.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - AEAD verification fails
    /// - Packet is malformed
    pub fn parse_response(&mut self, data: &[u8]) -> Result<NtsResponse> {
        let send_time = self.send_time.take().unwrap_or_else(SystemTime::now);

        debug!("Parsing NTS response: {} bytes", data.len());

        // Deserialize and verify the packet using the s2c cipher.
        // This performs AEAD verification - if the packet was modified or spoofed,
        // this will fail with a decryption error.
        let (packet, _cookie) = match NtpPacket::deserialize(data, &*self.s2c) {
            Ok(result) => result,
            Err(PacketParsingError::DecryptError(_)) => {
                warn!("NTS packet verification failed (AEAD tag mismatch)");
                return Err(Error::AeadVerificationFailed(
                    "NTS AEAD verification failed".to_string(),
                ));
            }
            Err(PacketParsingError::MalformedNtsExtensionFields)
            | Err(PacketParsingError::MalformedNonce)
            | Err(PacketParsingError::MalformedCookiePlaceholder) => {
                return Err(Error::MalformedNtsExtension(
                    "Malformed NTS extension fields".to_string(),
                ));
            }
            Err(e) => {
                return Err(Error::Protocol(format!(
                    "Failed to parse NTS packet: {}",
                    e
                )));
            }
        };

        // Check for kiss codes (server error responses)
        if packet.is_kiss_ntsn() {
            return Err(Error::AuthenticationFailed(
                "Server responded with NTS-NAK (key negotiation required)".to_string(),
            ));
        }

        if packet.is_kiss_deny() {
            return Err(Error::AuthenticationFailed(
                "Server denied service".to_string(),
            ));
        }

        if packet.is_kiss_rate(packet.poll()) {
            return Err(Error::Protocol(
                "Server requested rate limiting".to_string(),
            ));
        }

        let request_validation = self.last_request.take().ok_or_else(|| {
            Error::InvalidResponse("No matching request context available".to_string())
        })?;

        // Validate the response using raw packet data
        let response_validation = parse_response_validation(data)?;

        if !response_validation.has_nts_encrypted {
            return Err(Error::MissingAuthenticator);
        }

        if response_validation.unique_id != request_validation.unique_id {
            return Err(Error::InvalidResponse(
                "Unique Identifier mismatch in response".to_string(),
            ));
        }

        if response_validation.origin_timestamp != request_validation.expected_origin {
            return Err(Error::InvalidResponse(
                "Origin timestamp mismatch in response".to_string(),
            ));
        }

        // Calculate round-trip time
        let recv_time = SystemTime::now();
        let round_trip_delay = recv_time
            .duration_since(send_time)
            .unwrap_or(Duration::ZERO);

        // Extract and store new cookies from the response
        let new_cookies: Vec<Vec<u8>> = packet.new_cookies().collect();
        debug!("Received {} new cookies", new_cookies.len());

        if request_validation.requested_cookies > 1 && new_cookies.is_empty() {
            return Err(Error::NoCookiesReturned);
        }

        for cookie in new_cookies {
            self.store_cookie(cookie);
        }

        // Extract the transmit timestamp from the packet
        // The transmit timestamp is the server's time when it sent the response
        let transmit_ts = packet.transmit_timestamp();

        // Convert NTP timestamp to SystemTime
        // NTP timestamps are 64-bit with 32-bit seconds and 32-bit fraction
        // Since we can't easily access the raw bits, we use a workaround:
        // Create a known reference and calculate based on that
        let network_time = ntp_timestamp_to_system_time(transmit_ts);

        let response = NtsResponse {
            network_time,
            system_time: recv_time,
            round_trip_delay,
            stratum: packet.stratum(),
            precision: packet.precision(),
            leap: packet.leap(),
            authenticated: true, // Only set to true after AEAD verification succeeds
        };

        debug!(
            "NTS response verified successfully. Stratum: {}, Cookies remaining: {}",
            response.stratum,
            self.cookies.len()
        );

        Ok(response)
    }
}

/// A verified NTS response containing timestamp data.
#[derive(Debug, Clone)]
pub struct NtsResponse {
    /// Server transmit timestamp converted to SystemTime.
    pub network_time: SystemTime,
    /// Local system time when response was received.
    pub system_time: SystemTime,
    /// Round-trip delay.
    pub round_trip_delay: Duration,
    /// Server stratum level.
    pub stratum: u8,
    /// Server clock precision (log2 seconds).
    pub precision: i8,
    /// Leap indicator.
    pub leap: ntp_proto::NtpLeapIndicator,
    /// Whether the response was cryptographically authenticated.
    pub authenticated: bool,
}

impl NtsResponse {
    /// Calculate the offset between system time and network time.
    ///
    /// Returns the absolute duration difference.
    pub fn offset(&self) -> Duration {
        self.system_time
            .duration_since(self.network_time)
            .unwrap_or_else(|e| e.duration())
    }

    /// Calculate the signed offset in milliseconds.
    ///
    /// Positive means system clock is ahead of network time.
    pub fn offset_signed_ms(&self) -> i64 {
        match self.system_time.duration_since(self.network_time) {
            Ok(duration) => duration.as_millis() as i64,
            Err(e) => -(e.duration().as_millis() as i64),
        }
    }
}

/// Convert NTP timestamp to SystemTime using a fixed UNIX epoch reference.
fn ntp_timestamp_to_system_time(ts: ntp_proto::NtpTimestamp) -> SystemTime {
    // NTP epoch is 1900-01-01, Unix epoch is 1970-01-01.
    const NTP_UNIX_OFFSET: u32 = 2_208_988_800;

    let unix_epoch_ntp =
        ntp_proto::NtpTimestamp::from_seconds_nanos_since_ntp_era(NTP_UNIX_OFFSET, 0);
    let delta = ts - unix_epoch_ntp;
    let (secs, nanos) = delta.as_seconds_nanos();
    let total_nanos = secs as i128 * 1_000_000_000 + nanos as i128;

    if total_nanos >= 0 {
        UNIX_EPOCH + Duration::from_nanos(total_nanos as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos((-total_nanos) as u64)
    }
}

#[derive(Debug)]
struct ParsedExtensions {
    unique_id: Option<Vec<u8>>,
    has_nts_encrypted: bool,
}

#[derive(Debug)]
struct ResponseValidation {
    origin_timestamp: [u8; 8],
    unique_id: Vec<u8>,
    has_nts_encrypted: bool,
}

fn extract_request_validation(data: &[u8], requested_cookies: u8) -> Result<RequestValidation> {
    let expected_origin = extract_transmit_timestamp(data)?;
    let parsed = parse_extension_fields(data)?;
    let unique_id = parsed.unique_id.ok_or_else(|| {
        Error::MalformedNtsExtension("Missing Unique Identifier in request".to_string())
    })?;

    if !parsed.has_nts_encrypted {
        return Err(Error::MalformedNtsExtension(
            "Missing NTS encrypted field in request".to_string(),
        ));
    }

    Ok(RequestValidation {
        expected_origin,
        unique_id,
        requested_cookies,
    })
}

fn parse_response_validation(data: &[u8]) -> Result<ResponseValidation> {
    let origin_timestamp = extract_origin_timestamp(data)?;
    let parsed = parse_extension_fields(data)?;
    let unique_id = parsed.unique_id.ok_or_else(|| {
        Error::InvalidResponse("Missing Unique Identifier in response".to_string())
    })?;

    Ok(ResponseValidation {
        origin_timestamp,
        unique_id,
        has_nts_encrypted: parsed.has_nts_encrypted,
    })
}

fn extract_origin_timestamp(data: &[u8]) -> Result<[u8; 8]> {
    if data.len() < NTP_HEADER_LEN {
        return Err(Error::MalformedNtsExtension(
            "NTP header too short".to_string(),
        ));
    }

    let mut timestamp = [0u8; 8];
    timestamp.copy_from_slice(&data[24..32]);
    Ok(timestamp)
}

fn extract_transmit_timestamp(data: &[u8]) -> Result<[u8; 8]> {
    if data.len() < NTP_HEADER_LEN {
        return Err(Error::MalformedNtsExtension(
            "NTP header too short".to_string(),
        ));
    }

    let mut timestamp = [0u8; 8];
    timestamp.copy_from_slice(&data[40..48]);
    Ok(timestamp)
}

fn parse_extension_fields(data: &[u8]) -> Result<ParsedExtensions> {
    if data.len() < NTP_HEADER_LEN {
        return Err(Error::MalformedNtsExtension(
            "NTP header too short".to_string(),
        ));
    }

    let mut offset = NTP_HEADER_LEN;
    let mut unique_id = None;
    let mut has_nts_encrypted = false;

    while offset + 4 <= data.len() {
        let type_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if length < 4 || length % 4 != 0 {
            return Err(Error::MalformedNtsExtension(
                "Invalid extension field length".to_string(),
            ));
        }

        let end = offset + length;
        if end > data.len() {
            return Err(Error::MalformedNtsExtension(
                "Extension field overruns packet".to_string(),
            ));
        }

        let body = &data[offset + 4..end];
        match type_id {
            0x0104 => {
                if unique_id.is_none() {
                    unique_id = Some(body.to_vec());
                }
            }
            0x0404 => {
                has_nts_encrypted = true;
            }
            _ => {}
        }

        offset = end;
    }

    Ok(ParsedExtensions {
        unique_id,
        has_nts_encrypted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nts_response_offset_calculation() {
        let network_time = UNIX_EPOCH + Duration::from_secs(1000);
        let system_time = UNIX_EPOCH + Duration::from_secs(1005);

        let response = NtsResponse {
            network_time,
            system_time,
            round_trip_delay: Duration::from_millis(50),
            stratum: 1,
            precision: -20,
            leap: ntp_proto::NtpLeapIndicator::NoWarning,
            authenticated: true,
        };

        assert_eq!(response.offset(), Duration::from_secs(5));
        assert_eq!(response.offset_signed_ms(), 5000);
    }

    #[test]
    fn test_nts_response_negative_offset() {
        let network_time = UNIX_EPOCH + Duration::from_secs(1010);
        let system_time = UNIX_EPOCH + Duration::from_secs(1005);

        let response = NtsResponse {
            network_time,
            system_time,
            round_trip_delay: Duration::from_millis(50),
            stratum: 1,
            precision: -20,
            leap: ntp_proto::NtpLeapIndicator::NoWarning,
            authenticated: true,
        };

        assert_eq!(response.offset(), Duration::from_secs(5));
        assert_eq!(response.offset_signed_ms(), -5000);
    }

    #[test]
    fn test_ntp_timestamp_to_system_time() {
        const NTP_UNIX_OFFSET: u32 = 2_208_988_800;
        let ts = ntp_proto::NtpTimestamp::from_seconds_nanos_since_ntp_era(
            NTP_UNIX_OFFSET + 10,
            500_000_000,
        );
        let system_time = ntp_timestamp_to_system_time(ts);
        let delta = system_time.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(delta, Duration::from_millis(10_500));
    }
}
