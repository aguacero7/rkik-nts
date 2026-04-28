//! NTS-aware NTP packet handling (RFC 8915).
//!
//! This module provides the cryptographic authentication layer for NTP packets
//! using the Network Time Security (NTS) protocol. It handles:
//!
//! - Building NTP requests with NTS extension fields (Unique ID, Cookie, Authenticator)
//! - AEAD authentication of outgoing packets
//! - Verification and decryption of incoming responses
//! - Cookie management (consumption and replenishment)

use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use tracing::{debug, trace};
use zeroize::Zeroize;

use crate::cipher::AeadCipher;
use crate::error::{Error, Result};

/// Maximum size of an NTS-protected NTP packet buffer.
const NTS_PACKET_BUFFER_SIZE: usize = 1024;

/// NTP header length in bytes.
const NTP_HEADER_LEN: usize = 48;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

/// Encode a `SystemTime` as a 64-bit NTP timestamp (RFC 5905 §6).
///
/// Upper 32 bits: seconds since 1900-01-01 00:00:00 UTC.
/// Lower 32 bits: binary fraction of a second (1/2^32 s per unit).
fn system_time_to_ntp(t: SystemTime) -> [u8; 8] {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = (d.as_secs() + NTP_EPOCH_OFFSET) as u32;
    let frac = ((d.subsec_nanos() as u64 * (u32::MAX as u64 + 1)) / 1_000_000_000) as u32;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&secs.to_be_bytes());
    out[4..].copy_from_slice(&frac.to_be_bytes());
    out
}

/// Decode a 64-bit NTP timestamp to `SystemTime`.
fn ntp_to_system_time(bytes: [u8; 8]) -> SystemTime {
    let secs = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as u64;
    let frac = u32::from_be_bytes(bytes[4..].try_into().unwrap()) as u64;
    let unix_secs = secs.saturating_sub(NTP_EPOCH_OFFSET);
    let nanos = (frac * 1_000_000_000) / (u32::MAX as u64 + 1);
    UNIX_EPOCH + Duration::from_secs(unix_secs) + Duration::from_nanos(nanos)
}

/// Compute the NTP offset using four timestamps (RFC 5905 §8).
///
/// Returns `(network_time, rtt)` where `network_time` is the best estimate
/// of the true current time (`T4 + θ`), and `rtt` is the round-trip delay.
///
/// - T1: client transmit time
/// - T2: server receive time
/// - T3: server transmit time
/// - T4: client receive time
fn compute_ntp_offset(
    t1: SystemTime,
    t2: SystemTime,
    t3: SystemTime,
    t4: SystemTime,
) -> (SystemTime, Duration) {
    let to_ns = |t: SystemTime| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as i128;
    let (t1, t2, t3, t4) = (to_ns(t1), to_ns(t2), to_ns(t3), to_ns(t4));

    // θ = ((T2 - T1) + (T3 - T4)) / 2
    let theta = ((t2 - t1) + (t3 - t4)) / 2;
    // δ = (T4 - T1) - (T3 - T2)
    let rtt = ((t4 - t1) - (t3 - t2)).max(0) as u64;

    let network_ns = (t4 + theta).max(0) as u128;
    let network_time = UNIX_EPOCH + Duration::from_nanos(network_ns as u64);
    (network_time, Duration::from_nanos(rtt))
}

/// Append an NTS extension field to `buf`.
///
/// Wire format (RFC 7822): type (2B) | total_length (2B, ≥4, multiple of 4) | body | padding
fn write_ef(buf: &mut Vec<u8>, type_id: u16, body: &[u8]) {
    let padded = (body.len() + 3) & !3;
    let total = 4 + padded;
    buf.extend_from_slice(&type_id.to_be_bytes());
    buf.extend_from_slice(&(total as u16).to_be_bytes());
    buf.extend_from_slice(body);
    buf.resize(buf.len() + padded - body.len(), 0);
}

/// Append a NTS Authenticator and Encrypted Extension Fields field (type 0x0404).
///
/// Wire body layout (RFC 8915 §5.5):
///   nonce-length (2B) | ciphertext-length (2B) | nonce | ciphertext
///
/// `ad` is the packet contents up to (not including) this field.
/// `plaintext` carries inner extension fields to encrypt (empty for client requests).
fn write_ef_nts_authenticator(
    buf: &mut Vec<u8>,
    cipher: &AeadCipher,
    ad: &[u8],
    plaintext: &[u8],
) -> Result<()> {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher.encrypt_siv(&[ad, &nonce], plaintext)?;
    let ct_len = ciphertext.len() as u16;
    let mut body = Vec::with_capacity(4 + nonce.len() + ciphertext.len());
    body.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    body.extend_from_slice(&ct_len.to_be_bytes());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ciphertext);
    write_ef(buf, 0x0404, &body);
    Ok(())
}

/// Scan extension fields in a received NTP packet.
///
/// Returns `(auth_field_offset, unique_id)` where `auth_field_offset` is the
/// byte offset of the 0x0404 field (or `None` if absent).
fn scan_response_fields(data: &[u8]) -> Result<(Option<usize>, Option<Vec<u8>>)> {
    let mut offset = NTP_HEADER_LEN;
    let mut auth_offset = None;
    let mut unique_id = None;

    while offset + 4 <= data.len() {
        let type_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if length < 4 || length % 4 != 0 {
            return Err(Error::MalformedNtsExtension(format!(
                "invalid EF length {length} at offset {offset}"
            )));
        }
        if offset + length > data.len() {
            return Err(Error::MalformedNtsExtension(format!(
                "EF at {offset} overruns packet (length {length})"
            )));
        }

        let body = &data[offset + 4..offset + length];
        match type_id {
            0x0104 if unique_id.is_none() => {
                unique_id = Some(body.to_vec());
            }
            0x0104 => {
                return Err(Error::MalformedNtsExtension(
                    "duplicate Unique Identifier extension field".to_string(),
                ));
            }
            0x0404 if auth_offset.is_none() => {
                auth_offset = Some(offset);
            }
            0x0404 => {
                return Err(Error::MalformedNtsExtension(
                    "duplicate NTS authenticator extension field".to_string(),
                ));
            }
            _ => {}
        }
        offset += length;
    }

    if offset != data.len() {
        return Err(Error::MalformedNtsExtension(
            "trailing bytes after final extension field".to_string(),
        ));
    }

    Ok((auth_offset, unique_id))
}

/// Minimum number of cookies to maintain before requesting more.
const MIN_COOKIE_COUNT: usize = 4;

/// NTP leap indicator values (RFC 5905 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NtpLeapIndicator {
    /// No leap second warning.
    NoWarning,
    /// Last minute of the day has 61 seconds.
    LastMinute61,
    /// Last minute of the day has 59 seconds.
    LastMinute59,
    /// Clock is unsynchronized.
    Unknown,
}

impl From<u8> for NtpLeapIndicator {
    /// Parse the leap indicator from the two high bits of NTP header byte 0.
    fn from(byte: u8) -> Self {
        match byte >> 6 {
            0 => NtpLeapIndicator::NoWarning,
            1 => NtpLeapIndicator::LastMinute61,
            2 => NtpLeapIndicator::LastMinute59,
            _ => NtpLeapIndicator::Unknown,
        }
    }
}

/// Manages NTS state for authenticated NTP queries.
///
/// This struct holds the cryptographic keys and cookies needed for NTS-protected
/// NTP communication. It provides methods to create authenticated requests and
/// verify authenticated responses.
pub struct NtsState {
    /// Client-to-server encryption key.
    c2s: AeadCipher,
    /// Server-to-client decryption key.
    s2c: AeadCipher,
    /// Pool of available cookies.
    cookies: VecDeque<Vec<u8>>,
    /// Time when the last request was sent (for RTT calculation).
    send_time: Option<SystemTime>,
    /// Validation context for the last request.
    last_request: Option<RequestValidation>,
    /// The last authenticated server transmit timestamp.
    last_server_transmit: Option<[u8; 8]>,
}

impl std::fmt::Debug for NtsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtsState")
            .field("c2s", &self.c2s)
            .field("s2c", &self.s2c)
            .field("cookies", &format!("[{} cookies]", self.cookies.len()))
            .field("send_time", &self.send_time)
            .field("has_request", &self.last_request.is_some())
            .finish()
    }
}

#[derive(Debug, Clone)]
struct RequestValidation {
    expected_origin: [u8; 8],
    unique_id: [u8; 32],
    pending_cookie: Vec<u8>,
}

impl NtsState {
    /// Create a new NtsState from NTS-KE negotiated parameters.
    ///
    /// # Arguments
    ///
    /// * `c2s` - Client-to-server cipher for encrypting requests
    /// * `s2c` - Server-to-client cipher for decrypting responses
    /// * `cookies` - Initial pool of cookies from NTS-KE
    pub fn new(c2s: AeadCipher, s2c: AeadCipher, cookies: Vec<Vec<u8>>) -> Self {
        debug!("Creating NtsState with {} cookies", cookies.len());
        Self {
            c2s,
            s2c,
            cookies: cookies.into(),
            send_time: None,
            last_request: None,
            last_server_transmit: None,
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
        self.cookies.push_back(cookie);
    }

    /// Restore the in-flight cookie after a transport failure.
    pub fn abandon_request(&mut self) {
        if let Some(mut req) = self.last_request.take() {
            req.unique_id.zeroize();
            self.cookies.push_front(req.pending_cookie);
        }
        self.send_time = None;
    }

    /// Build an NTS-authenticated NTPv4 request packet (RFC 8915 §5).
    ///
    /// Constructs a 48-byte NTPv4 header followed by four NTS extension fields:
    ///
    /// - `0x0104` Unique Identifier (32 random bytes, anti-replay)
    /// - `0x0204` NTS Cookie (consumes one cookie from the pool)
    /// - `0x0304` NTS Cookie Placeholder × N (requests N new cookies)
    /// - `0x0404` NTS Authenticator (AEAD_AES_SIV, empty plaintext)
    ///
    /// The AEAD associated data covers the entire packet preceding field `0x0404`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingNtsCookie`] if the cookie pool is empty.
    pub fn create_request(&mut self) -> Result<Vec<u8>> {
        if self.cookies.is_empty() {
            return Err(Error::MissingNtsCookie);
        }
        let cookie = self.cookies.pop_front().expect("checked is_empty above");
        let cookie_len = cookie.len();

        let mut unique_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut unique_id);

        let mut buf = Vec::with_capacity(NTS_PACKET_BUFFER_SIZE);

        // NTP header — 48 bytes (RFC 5905 §7.3)
        // Byte 0: LI=0 (no warning), VN=4, Mode=3 (client) → 0b_00_100_011 = 0x23
        buf.push(0x23);
        buf.push(0); // stratum = 0 (unspecified)
        buf.push(0); // poll interval
        buf.push(0); // precision
        buf.extend_from_slice(&[0u8; 4]); // root delay
        buf.extend_from_slice(&[0u8; 4]); // root dispersion
        buf.extend_from_slice(&[0u8; 4]); // reference ID
        buf.extend_from_slice(&[0u8; 8]); // reference timestamp
        buf.extend_from_slice(&[0u8; 8]); // origin timestamp (zeroed by client)
        buf.extend_from_slice(&[0u8; 8]); // receive timestamp
        let t1 = SystemTime::now();
        let t1_ntp = system_time_to_ntp(t1);
        buf.extend_from_slice(&t1_ntp); // transmit timestamp T1

        debug_assert_eq!(buf.len(), NTP_HEADER_LEN);

        // EF: Unique Identifier (RFC 8915 §5.3)
        write_ef(&mut buf, 0x0104, &unique_id);

        // EF: NTS Cookie (RFC 8915 §5.4)
        write_ef(&mut buf, 0x0204, &cookie);

        // EF: NTS Cookie Placeholder × N (RFC 8915 §5.4)
        let n_placeholders = MIN_COOKIE_COUNT.saturating_sub(self.cookies.len());
        let placeholder = vec![0u8; cookie_len];
        for _ in 0..n_placeholders {
            write_ef(&mut buf, 0x0304, &placeholder);
        }

        // EF: NTS Authenticator (RFC 8915 §5.5)
        // AD = full packet up to (not including) this field; plaintext = empty.
        let ad = buf.clone();
        write_ef_nts_authenticator(&mut buf, &self.c2s, &ad, &[])?;

        self.send_time = Some(t1);
        self.last_request = Some(RequestValidation {
            expected_origin: t1_ntp,
            unique_id,
            pending_cookie: cookie,
        });

        trace!("NTS request: {} bytes, {} placeholders", buf.len(), n_placeholders);
        Ok(buf)
    }

    /// Verify and parse an NTS-authenticated NTP server response (RFC 8915 §5).
    ///
    /// Performs in order:
    /// 1. Header sanity checks (mode=4, LI≠3, stratum 1–15)
    /// 2. Origin timestamp match against the last transmitted T1 (anti-replay)
    /// 3. Unique Identifier echo match
    /// 4. AEAD decryption and verification of field `0x0404`
    /// 5. New-cookie extraction from the decrypted plaintext
    /// 6. Four-timestamp offset and RTT computation (RFC 5905 §8)
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidResponse`] — header invalid, timestamps mismatch, or UID mismatch
    /// - [`Error::MissingAuthenticator`] — field `0x0404` absent
    /// - [`Error::AeadVerificationFailed`] — AEAD tag does not verify
    /// - [`Error::MalformedNtsExtension`] — extension field lengths are inconsistent
    pub fn parse_response(&mut self, data: &[u8]) -> Result<NtsResponse> {
        let req = self.last_request.as_ref().ok_or_else(|| {
            Error::Other("no pending request; call create_request() first".to_string())
        })?;

        if data.len() < NTP_HEADER_LEN {
            return Err(Error::InvalidResponse(format!(
                "packet too short: {} bytes",
                data.len()
            )));
        }

        let li = (data[0] >> 6) & 0x03;
        let version = (data[0] >> 3) & 0x07;
        let mode = data[0] & 0x07;
        let stratum = data[1];
        let _precision = data[3] as i8;

        if version != 4 {
            return Err(Error::InvalidResponse(format!(
                "expected NTP version 4, got {version}"
            )));
        }
        if li == 3 {
            return Err(Error::InvalidResponse(
                "server reports unsynchronized clock (LI=3)".to_string(),
            ));
        }
        if stratum == 0 {
            let kiss = String::from_utf8_lossy(&data[12..16]).to_string();
            return Err(Error::KissOfDeath(kiss));
        }
        if mode != 4 {
            return Err(Error::InvalidResponse(format!(
                "expected server mode 4, got {mode}"
            )));
        }
        if stratum == 0 || stratum > 15 {
            return Err(Error::InvalidResponse(format!("invalid stratum {stratum}")));
        }

        // Origin timestamp must match T1 we sent (anti-replay).
        let origin: [u8; 8] = data[24..32].try_into().unwrap();
        if origin != req.expected_origin {
            return Err(Error::InvalidResponse(
                "origin timestamp does not match transmitted T1".to_string(),
            ));
        }

        let _leap = NtpLeapIndicator::from(data[0]);

        let (auth_offset, uid_from_resp) = scan_response_fields(data)?;

        match uid_from_resp {
            None => {
                return Err(Error::InvalidResponse(
                    "server did not echo Unique Identifier".to_string(),
                ))
            }
            Some(uid) if uid.as_slice() != req.unique_id => {
                return Err(Error::InvalidResponse(
                    "Unique Identifier mismatch".to_string(),
                ))
            }
            _ => {}
        }

        let auth_off = auth_offset.ok_or(Error::MissingAuthenticator)?;

        // AEAD verification: AD = everything up to (not including) 0x0404.
        let ad = &data[..auth_off];
        let auth_total = u16::from_be_bytes([data[auth_off + 2], data[auth_off + 3]]) as usize;
        if auth_off + auth_total > data.len() || auth_total < 8 {
            return Err(Error::MalformedNtsExtension(
                "NTS authenticator field is truncated".to_string(),
            ));
        }
        let body = &data[auth_off + 4..auth_off + auth_total];
        if body.len() < 4 {
            return Err(Error::MalformedNtsExtension(
                "NTS authenticator body is too short".to_string(),
            ));
        }
        let nonce_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        if 4 + nonce_len > body.len() {
            return Err(Error::MalformedNtsExtension(
                "nonce overruns authenticator body".to_string(),
            ));
        }
        let ct_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        let nonce = &body[4..4 + nonce_len];
        let ciphertext_offset = 4 + nonce_len;
        if ciphertext_offset + ct_len > body.len() {
            return Err(Error::MalformedNtsExtension(
                "nonce+ciphertext lengths overflow authenticator body".to_string(),
            ));
        }
        let ciphertext = &body[ciphertext_offset..ciphertext_offset + ct_len];
        if auth_off + auth_total != data.len() {
            return Err(Error::MalformedNtsExtension(
                "NTS authenticator must be the last extension field".to_string(),
            ));
        }
        let plaintext = self.s2c.decrypt_siv(&[ad, nonce], ciphertext)?;

        // Extract new cookies from the decrypted plaintext (type-0x0204 TLVs).
        let mut pt = 0usize;
        while pt + 4 <= plaintext.len() {
            let ef_type = u16::from_be_bytes([plaintext[pt], plaintext[pt + 1]]);
            let ef_len = u16::from_be_bytes([plaintext[pt + 2], plaintext[pt + 3]]) as usize;
            if ef_len < 4 || pt + ef_len > plaintext.len() {
                return Err(Error::MalformedNtsExtension(
                    "authenticated extension field payload is malformed".to_string(),
                ));
            }
            if ef_type == 0x0204 {
                self.store_cookie(plaintext[pt + 4..pt + ef_len].to_vec());
                trace!("stored new cookie ({} bytes)", ef_len - 4);
            }
            pt += ef_len;
        }
        if pt != plaintext.len() {
            return Err(Error::MalformedNtsExtension(
                "authenticated extension field payload has trailing bytes".to_string(),
            ));
        }

        let t1 = self.send_time.unwrap_or_else(SystemTime::now);
        let t2 = ntp_to_system_time(data[32..40].try_into().unwrap());
        let transmit_timestamp: [u8; 8] = data[40..48].try_into().unwrap();
        if transmit_timestamp == [0u8; 8] {
            return Err(Error::InvalidResponse(
                "server transmit timestamp is zero".to_string(),
            ));
        }
        if self.last_server_transmit == Some(transmit_timestamp) {
            return Err(Error::InvalidResponse(
                "duplicate server transmit timestamp".to_string(),
            ));
        }
        let t3 = ntp_to_system_time(transmit_timestamp);
        let t4 = SystemTime::now();

        let (network_time, round_trip_delay) = compute_ntp_offset(t1, t2, t3, t4);
        self.last_server_transmit = Some(transmit_timestamp);
        if let Some(mut req) = self.last_request.take() {
            req.unique_id.zeroize();
            req.pending_cookie.zeroize();
        }
        self.send_time = None;

        debug!(
            "NTS response ok: stratum={}, cookies_now={}, rtt={:?}",
            stratum,
            self.cookie_count(),
            round_trip_delay
        );

        Ok(NtsResponse {
            network_time,
            system_time: t4,
            round_trip_delay,
            stratum,
            authenticated: true,
        })
    }
}

impl Drop for NtsState {
    fn drop(&mut self) {
        for cookie in &mut self.cookies {
            cookie.zeroize();
        }
        if let Some(req) = self.last_request.as_mut() {
            req.unique_id.zeroize();
            req.pending_cookie.zeroize();
        }
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
            authenticated: true,
        };

        assert_eq!(response.offset(), Duration::from_secs(5));
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
            authenticated: true,
        };

        assert_eq!(response.offset(), Duration::from_secs(5));
    }

    fn make_test_state(cookies: Vec<Vec<u8>>) -> NtsState {
        let c2s = AeadCipher::from_key_bytes(crate::cipher::AEAD_AES_SIV_CMAC_256, &[1u8; 32]).unwrap();
        let s2c = AeadCipher::from_key_bytes(crate::cipher::AEAD_AES_SIV_CMAC_256, &[2u8; 32]).unwrap();
        NtsState::new(c2s, s2c, cookies)
    }

    #[test]
    fn test_build_request_packet_structure() {
        let cookie = vec![0xDEu8; 40];
        let mut state = make_test_state(vec![cookie]);
        let pkt = state.create_request().unwrap();

        assert!(pkt.len() >= 48, "packet too short: {} bytes", pkt.len());
        assert_eq!(pkt[0], 0x23, "wrong LI/VN/Mode byte");

        let mut types = Vec::new();
        let mut offset = 48usize;
        while offset + 4 <= pkt.len() {
            let t = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
            let l = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]) as usize;
            assert!(l >= 4 && l % 4 == 0 && offset + l <= pkt.len(), "malformed EF at {offset}");
            types.push(t);
            offset += l;
        }
        assert!(types.contains(&0x0104), "missing Unique ID field");
        assert!(types.contains(&0x0204), "missing NTS Cookie field");
        assert!(types.contains(&0x0404), "missing NTS Authenticator field");
    }

    #[test]
    fn test_cookie_consumed_on_request() {
        let cookies = vec![vec![1u8; 40], vec![2u8; 40], vec![3u8; 40]];
        let mut state = make_test_state(cookies);
        assert_eq!(state.cookie_count(), 3);
        state.create_request().unwrap();
        assert_eq!(state.cookie_count(), 2, "one cookie should have been consumed");
    }

    #[test]
    fn test_unique_id_is_32_bytes() {
        let cookie = vec![0u8; 40];
        let mut state = make_test_state(vec![cookie]);
        let pkt = state.create_request().unwrap();

        let mut offset = 48usize;
        while offset + 4 <= pkt.len() {
            let t = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
            let l = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]) as usize;
            if t == 0x0104 {
                assert_eq!(l - 4, 32, "Unique ID body must be 32 bytes, got {}", l - 4);
                return;
            }
            offset += l;
        }
        panic!("Unique ID field not found");
    }

    #[test]
    fn test_placeholder_count_matches_deficit() {
        // 3 cookies total, consume 1 → 2 remain; MIN_COOKIE_COUNT=4 → deficit=2
        let cookies = vec![vec![0xABu8; 40]; 3];
        let mut state = make_test_state(cookies);
        let pkt = state.create_request().unwrap();

        let mut placeholder_count = 0usize;
        let mut offset = 48usize;
        while offset + 4 <= pkt.len() {
            let t = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
            let l = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]) as usize;
            if t == 0x0304 {
                placeholder_count += 1;
            }
            offset += l;
        }
        assert_eq!(placeholder_count, 2, "expected 2 placeholders, got {placeholder_count}");
    }

    #[test]
    fn test_create_request_fails_without_cookies() {
        let mut state = make_test_state(vec![]);
        assert!(matches!(state.create_request(), Err(crate::error::Error::MissingNtsCookie)));
    }

    #[test]
    fn test_abandon_request_restores_cookie() {
        let mut state = make_test_state(vec![vec![0xAA; 40]]);
        let _req = state.create_request().unwrap();
        assert_eq!(state.cookie_count(), 0);
        state.abandon_request();
        assert_eq!(state.cookie_count(), 1);
    }

    /// Build a minimal fake NTS server response for unit testing parse_response.
    ///
    /// Mirrors what a real NTS server would send back:
    /// - NTP header with mode=4, stratum=1, origin=T1 from the last request
    /// - Unique Identifier echo (0x0104)
    /// - NTS Authenticator (0x0404) encrypted with s2c, plaintext = cookie TLVs
    fn fake_server_response(state: &NtsState, new_cookies: &[Vec<u8>]) -> Vec<u8> {
        fake_server_response_with_timestamps(
            state,
            new_cookies,
            system_time_to_ntp(SystemTime::now()),
            system_time_to_ntp(SystemTime::now()),
        )
    }

    fn fake_server_response_with_timestamps(
        state: &NtsState,
        new_cookies: &[Vec<u8>],
        t2_ntp: [u8; 8],
        t3_ntp: [u8; 8],
    ) -> Vec<u8> {
        let req = state.last_request.as_ref().unwrap();
        let t1_ntp = req.expected_origin;

        let mut buf = vec![
            0x24,   // LI=0, VN=4, Mode=4 (server)
            1,      // stratum 1
            4,      // poll
            0xECu8, // precision (reinterpreted as i8 = -20)
        ];
        buf.extend_from_slice(&[0u8; 4]); // root delay
        buf.extend_from_slice(&[0u8; 4]); // root dispersion
        buf.extend_from_slice(b"GPS\0"); // reference ID
        buf.extend_from_slice(&[0u8; 8]); // reference timestamp
        buf.extend_from_slice(&t1_ntp);   // origin = T1 echoed
        buf.extend_from_slice(&t2_ntp);   // receive timestamp T2
        buf.extend_from_slice(&t3_ntp);   // transmit timestamp T3

        write_ef(&mut buf, 0x0104, &req.unique_id);

        // Cookie TLVs in AEAD plaintext: type=0x0204, aligned to 4 bytes
        let mut plaintext = Vec::new();
        for ck in new_cookies {
            let padded = (ck.len() + 3) & !3;
            let total = (4 + padded) as u16;
            plaintext.extend_from_slice(&0x0204u16.to_be_bytes());
            plaintext.extend_from_slice(&total.to_be_bytes());
            plaintext.extend_from_slice(ck);
            plaintext.resize(plaintext.len() + padded - ck.len(), 0);
        }

        let ad = buf.clone();
        write_ef_nts_authenticator(&mut buf, &state.s2c, &ad, &plaintext).unwrap();
        buf
    }

    #[test]
    fn test_in_memory_roundtrip_authenticated() {
        let cookie = vec![0xFEu8; 40];
        let mut state = make_test_state(vec![cookie]);
        let _req = state.create_request().unwrap();

        let new_cookie = vec![0xCDu8; 40];
        let resp = fake_server_response(&state, &[new_cookie]);
        let result = state.parse_response(&resp).unwrap();

        assert!(result.authenticated, "response must be authenticated");
        assert_eq!(result.stratum, 1);
        assert_eq!(state.cookie_count(), 1, "new cookie should be stored");
    }

    #[test]
    fn test_reject_wrong_origin_timestamp() {
        let mut state = make_test_state(vec![vec![0u8; 40]]);
        let _req = state.create_request().unwrap();
        let mut resp = fake_server_response(&state, &[]);
        resp[24] ^= 0xFF; // corrupt origin timestamp
        assert!(matches!(
            state.parse_response(&resp),
            Err(crate::error::Error::InvalidResponse(_))
        ));
    }

    #[test]
    fn test_reject_wrong_unique_id() {
        let mut state = make_test_state(vec![vec![0u8; 40]]);
        let _req = state.create_request().unwrap();
        let mut resp = fake_server_response(&state, &[]);
        // Find 0x0104 and corrupt first body byte
        let mut offset = NTP_HEADER_LEN;
        while offset + 4 <= resp.len() {
            let t = u16::from_be_bytes([resp[offset], resp[offset + 1]]);
            let l = u16::from_be_bytes([resp[offset + 2], resp[offset + 3]]) as usize;
            if t == 0x0104 {
                resp[offset + 4] ^= 0xFF;
                break;
            }
            offset += l;
        }
        assert!(matches!(
            state.parse_response(&resp),
            Err(crate::error::Error::InvalidResponse(_))
        ));
    }

    #[test]
    fn test_reject_missing_authenticator() {
        let mut state = make_test_state(vec![vec![0u8; 40]]);
        let _req = state.create_request().unwrap();
        let mut resp = fake_server_response(&state, &[]);
        // Truncate at start of 0x0404
        let mut cut = NTP_HEADER_LEN;
        while cut + 4 <= resp.len() {
            let t = u16::from_be_bytes([resp[cut], resp[cut + 1]]);
            let l = u16::from_be_bytes([resp[cut + 2], resp[cut + 3]]) as usize;
            if t == 0x0404 {
                resp.truncate(cut);
                break;
            }
            cut += l;
        }
        assert!(matches!(
            state.parse_response(&resp),
            Err(crate::error::Error::MissingAuthenticator)
        ));
    }

    #[test]
    fn test_reject_tampered_aead_tag() {
        let mut state = make_test_state(vec![vec![0u8; 40]]);
        let _req = state.create_request().unwrap();
        let mut resp = fake_server_response(&state, &[]);
        // Find 0x0404, flip a byte in the ciphertext (after nonce_len+ct_len header)
        let mut offset = NTP_HEADER_LEN;
        while offset + 4 <= resp.len() {
            let t = u16::from_be_bytes([resp[offset], resp[offset + 1]]);
            let l = u16::from_be_bytes([resp[offset + 2], resp[offset + 3]]) as usize;
            if t == 0x0404 && offset + 9 < resp.len() {
                resp[offset + 8] ^= 0x01;
                break;
            }
            offset += l;
        }
        assert!(matches!(
            state.parse_response(&resp),
            Err(crate::error::Error::AeadVerificationFailed(_))
        ));
    }

    #[test]
    fn test_cookies_stored_from_response() {
        let mut state = make_test_state(vec![vec![0u8; 40]]);
        let _req = state.create_request().unwrap();
        assert_eq!(state.cookie_count(), 0);

        let new_cookies = vec![vec![0x11u8; 40], vec![0x22u8; 40]];
        let resp = fake_server_response(&state, &new_cookies);
        state.parse_response(&resp).unwrap();
        assert_eq!(state.cookie_count(), 2);
    }

    #[test]
    fn test_reject_packet_too_short() {
        let mut state = make_test_state(vec![vec![0u8; 40]]);
        let _req = state.create_request().unwrap();
        assert!(matches!(
            state.parse_response(&[0u8; 20]),
            Err(crate::error::Error::InvalidResponse(_))
        ));
    }

    #[test]
    fn test_reject_unsynchronized_server() {
        let mut state = make_test_state(vec![vec![0u8; 40]]);
        let _req = state.create_request().unwrap();
        let mut resp = fake_server_response(&state, &[]);
        resp[0] = 0xE4; // LI=3 (unsynchronized)
        assert!(matches!(
            state.parse_response(&resp),
            Err(crate::error::Error::InvalidResponse(_))
        ));
    }

    #[test]
    fn test_reject_duplicate_unique_id_extension() {
        let mut state = make_test_state(vec![vec![0u8; 40]]);
        let _req = state.create_request().unwrap();
        let mut resp = fake_server_response(&state, &[]);
        let uid = state.last_request.as_ref().unwrap().unique_id;
        write_ef(&mut resp, 0x0104, &uid);
        assert!(matches!(
            state.parse_response(&resp),
            Err(crate::error::Error::MalformedNtsExtension(_))
        ));
    }

    #[test]
    fn test_reject_trailing_bytes_after_authenticator() {
        let mut state = make_test_state(vec![vec![0u8; 40]]);
        let _req = state.create_request().unwrap();
        let mut resp = fake_server_response(&state, &[]);
        resp.extend_from_slice(&[0, 1, 2, 3]);
        assert!(matches!(
            state.parse_response(&resp),
            Err(crate::error::Error::MalformedNtsExtension(_))
        ));
    }

    #[test]
    fn test_reject_duplicate_server_transmit_timestamp() {
        let mut state = make_test_state(vec![vec![0u8; 40], vec![1u8; 40]]);
        let _req = state.create_request().unwrap();
        let resp = fake_server_response(&state, &[vec![0x11; 40]]);
        state.parse_response(&resp).unwrap();

        let _req = state.create_request().unwrap();
        let replay = fake_server_response_with_timestamps(
            &state,
            &[vec![0x22; 40]],
            resp[32..40].try_into().unwrap(),
            resp[40..48].try_into().unwrap(),
        );
        assert!(matches!(
            state.parse_response(&replay),
            Err(crate::error::Error::InvalidResponse(_))
        ));
    }

    #[test]
    fn test_extension_field_alignment() {
        for body_len in [0usize, 1, 2, 3, 4, 5, 16, 32, 33] {
            let body = vec![0xABu8; body_len];
            let mut buf = Vec::new();
            write_ef(&mut buf, 0x0104, &body);
            assert_eq!(buf.len() % 4, 0, "field for body_len={body_len} not 4-byte aligned");
            let reported_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            assert_eq!(reported_len, buf.len(), "reported length mismatch for body_len={body_len}");
        }
    }

    #[test]
    fn test_write_ef_type_and_body_preserved() {
        let body = b"hello_cookie";
        let mut buf = Vec::new();
        write_ef(&mut buf, 0x0204, body);
        let type_id = u16::from_be_bytes([buf[0], buf[1]]);
        assert_eq!(type_id, 0x0204);
        assert_eq!(&buf[4..4 + body.len()], body.as_ref());
    }

    #[test]
    fn test_ntp_timestamp_roundtrip() {
        let original = UNIX_EPOCH + Duration::from_millis(1_700_000_000_123);
        let encoded = system_time_to_ntp(original);
        let decoded = ntp_to_system_time(encoded);
        let diff = original
            .duration_since(decoded)
            .unwrap_or_else(|e| e.duration());
        assert!(diff < Duration::from_micros(1), "roundtrip error: {diff:?}");
    }

    #[test]
    fn test_ntp_epoch_offset_zero() {
        let encoded = system_time_to_ntp(UNIX_EPOCH);
        let secs = u32::from_be_bytes(encoded[..4].try_into().unwrap()) as u64;
        assert_eq!(secs, NTP_EPOCH_OFFSET);
    }

    #[test]
    fn test_compute_ntp_offset_zero_when_clocks_agree() {
        let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let transit = Duration::from_millis(50);
        let t1 = base;
        let t2 = base + transit;
        let t3 = base + transit;
        let t4 = base + transit * 2;
        let (network_time, rtt) = compute_ntp_offset(t1, t2, t3, t4);
        let diff = network_time
            .duration_since(t4)
            .unwrap_or_else(|e| e.duration());
        assert!(diff < Duration::from_millis(1));
        assert!((rtt.as_millis() as i64 - 100).abs() < 2);
    }

    #[test]
    fn test_compute_ntp_offset_system_behind() {
        let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let lag = Duration::from_secs(5);
        let transit = Duration::from_millis(50);
        let t1 = base;
        let t2 = base + lag + transit;
        let t3 = base + lag + transit;
        let t4 = base + transit * 2;
        let (network_time, _rtt) = compute_ntp_offset(t1, t2, t3, t4);
        let expected = base + lag + transit * 2;
        let diff = network_time
            .duration_since(expected)
            .unwrap_or_else(|e| e.duration());
        assert!(diff < Duration::from_millis(1), "offset error: {diff:?}");
    }
}
