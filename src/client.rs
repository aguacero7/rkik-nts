//! High-level NTS client implementation with real RFC 8915 authentication.

use std::net::SocketAddr;

use ntp_proto::PollInterval;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::NtsClientConfig;
use crate::error::{Error, Result};
use crate::nts_ke::perform_nts_ke;
use crate::nts_ntp::NtsState;
use crate::types::{CertificateInfo, TimeSnapshot};

/// A high-level NTS (Network Time Security) client.
///
/// This client handles NTS key exchange and authenticated NTP time queries
/// according to RFC 8915. All time queries are cryptographically authenticated
/// using AEAD encryption with keys negotiated during the NTS-KE handshake.
///
/// # Security
///
/// - NTP packets contain NTS extension fields (Unique ID, Cookie, Authenticator)
/// - AEAD verification is performed on every response
/// - Spoofed or modified responses are rejected
/// - Cookies are consumed and replenished automatically
///
/// # Examples
///
/// ```no_run
/// use rkik_nts::{NtsClient, NtsClientConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = NtsClientConfig::new("time.cloudflare.com");
///     let mut client = NtsClient::new(config);
///
///     // Connect and perform NTS key exchange
///     client.connect().await?;
///
///     // Get the current time (authenticated)
///     let time = client.get_time().await?;
///     println!("Network time: {:?}", time.network_time);
///     println!("Offset: {} ms", time.offset_signed());
///     println!("Authenticated: {}", time.authenticated);
///
///     Ok(())
/// }
/// ```
pub struct NtsClient {
    config: NtsClientConfig,
    /// NTS cryptographic state (ciphers and cookies).
    nts_state: Option<NtsState>,
    /// UDP socket for NTP queries.
    socket: Option<UdpSocket>,
    /// NTP server address from NTS-KE.
    ntp_server: Option<SocketAddr>,
    /// NTS-KE diagnostic information.
    ke_info: Option<NtsKeInfo>,
}

/// Diagnostic information from the NTS-KE handshake.
#[derive(Debug, Clone)]
pub struct NtsKeInfo {
    /// The NTP server address negotiated during NTS-KE.
    pub ntp_server: SocketAddr,
    /// The negotiated AEAD algorithm.
    pub aead_algorithm: String,
    /// Duration of the NTS-KE handshake.
    pub ke_duration: std::time::Duration,
    /// TLS certificate information.
    pub certificate: Option<CertificateInfo>,
    /// Initial cookie count from NTS-KE.
    pub initial_cookie_count: usize,
}

impl NtsClient {
    /// Create a new NTS client with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the NTS client.
    pub fn new(config: NtsClientConfig) -> Self {
        Self {
            config,
            nts_state: None,
            socket: None,
            ntp_server: None,
            ke_info: None,
        }
    }

    /// Connect to the NTS server and perform key exchange.
    ///
    /// This performs the NTS-KE handshake over TLS to negotiate:
    /// - AEAD algorithm
    /// - Client-to-server and server-to-client encryption keys
    /// - Initial pool of cookies
    ///
    /// This must be called before querying time.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or the key exchange fails.
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to NTS server: {}", self.config.nts_ke_server);

        // Validate configuration
        self.config.validate()?;

        // Perform NTS key exchange
        let nts_result = perform_nts_ke(&self.config).await?;

        let ntp_server = nts_result.ntp_server;
        let aead_algorithm = nts_result.aead_algorithm.clone();
        let ke_duration = nts_result.ke_duration();
        let certificate = nts_result.certificate.clone();
        let initial_cookie_count = nts_result.cookie_count();

        info!(
            "NTS key exchange successful. NTP server: {}, cookies: {}",
            ntp_server, initial_cookie_count
        );

        // Create UDP socket for NTP queries
        // Choose bind address based on server's address family
        let bind_addr = if ntp_server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(ntp_server).await?;

        // Extract NTS state for authenticated queries
        let nts_state = nts_result.into_nts_state();

        self.socket = Some(socket);
        self.nts_state = Some(nts_state);
        self.ntp_server = Some(ntp_server);
        self.ke_info = Some(NtsKeInfo {
            ntp_server,
            aead_algorithm,
            ke_duration,
            certificate,
            initial_cookie_count,
        });

        Ok(())
    }

    /// Query the current time from the NTS-secured NTP server.
    ///
    /// This creates an NTS-authenticated NTP request with:
    /// - Unique Identifier extension field (anti-replay)
    /// - NTS Cookie extension field
    /// - Cookie Placeholder extension fields (to replenish cookies)
    /// - AEAD authenticator
    ///
    /// The response is verified using:
    /// - AEAD decryption and verification
    /// - Unique Identifier matching
    /// - Origin timestamp matching
    ///
    /// Only after successful verification is `authenticated` set to `true`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not connected (call `connect()` first)
    /// - No cookies available (need to reconnect)
    /// - AEAD verification fails (response tampered or spoofed)
    /// - Response doesn't match request (replay attack detected)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rkik_nts::{NtsClient, NtsClientConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = NtsClient::new(NtsClientConfig::new("time.cloudflare.com"));
    /// client.connect().await?;
    /// let time = client.get_time().await?;
    /// assert!(time.authenticated);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_time(&mut self) -> Result<TimeSnapshot> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| Error::Other("Not connected. Call connect() first.".to_string()))?;

        let nts_state = self.nts_state.as_mut().ok_or_else(|| {
            Error::Other("No NTS state available. Call connect() first.".to_string())
        })?;

        let ntp_server = self.ntp_server.ok_or_else(|| {
            Error::Other("No NTP server configured. Call connect() first.".to_string())
        })?;

        // Check if we have cookies available
        if !nts_state.has_cookies() {
            return Err(Error::MissingNtsCookie);
        }

        debug!("Creating NTS-authenticated NTP request ({} cookies available)", nts_state.cookie_count());

        // Create NTS-authenticated NTP request
        let poll_interval = PollInterval::default();
        let request = nts_state.create_request(poll_interval)?;

        // Send request
        debug!("Sending NTS request ({} bytes)", request.len());
        socket.send(&request).await?;

        // Receive response with timeout
        let mut buf = vec![0u8; 1024];
        let len = timeout(self.config.timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| Error::Timeout)??;

        buf.truncate(len);

        // Parse and verify response (AEAD verification happens here)
        debug!("Received {} bytes, verifying NTS response", len);
        let nts_response = nts_state.parse_response(&buf)?;

        debug!(
            "NTS response verified. Stratum: {}, authenticated: {}, cookies remaining: {}",
            nts_response.stratum,
            nts_response.authenticated,
            nts_state.cookie_count()
        );

        // Warn if cookie count is getting low
        if nts_state.needs_more_cookies() {
            warn!(
                "Cookie count is low ({}). Consider reconnecting if queries fail.",
                nts_state.cookie_count()
            );
        }

        // Convert NtsResponse to TimeSnapshot
        let offset = nts_response.offset();

        Ok(TimeSnapshot {
            system_time: nts_response.system_time,
            network_time: nts_response.network_time,
            offset,
            round_trip_delay: nts_response.round_trip_delay,
            server: ntp_server.to_string(),
            authenticated: nts_response.authenticated,
        })
    }

    /// Check if the client is connected and ready to query time.
    pub fn is_connected(&self) -> bool {
        self.socket.is_some() && self.nts_state.is_some()
    }

    /// Get the NTP server address being used.
    pub fn ntp_server(&self) -> Option<SocketAddr> {
        self.ntp_server
    }

    /// Get the current cookie count.
    ///
    /// Each NTP query consumes one cookie, and responses may provide new ones.
    /// If this reaches zero, you need to reconnect to get fresh cookies.
    pub fn cookie_count(&self) -> usize {
        self.nts_state
            .as_ref()
            .map(|s| s.cookie_count())
            .unwrap_or(0)
    }

    /// Check if the client needs more cookies.
    ///
    /// Returns `true` if the cookie count is below the minimum threshold.
    pub fn needs_more_cookies(&self) -> bool {
        self.nts_state
            .as_ref()
            .map(|s| s.needs_more_cookies())
            .unwrap_or(true)
    }

    /// Get diagnostic information from the NTS-KE handshake.
    ///
    /// This provides access to NTS-KE negotiation details including:
    /// - AEAD algorithm
    /// - Initial cookie count
    /// - Key exchange duration
    /// - TLS certificate information
    ///
    /// Returns `None` if not connected.
    pub fn nts_ke_info(&self) -> Option<&NtsKeInfo> {
        self.ke_info.as_ref()
    }

    /// Reconnect and perform a fresh NTS key exchange.
    ///
    /// This is useful when:
    /// - The connection has been idle for a long time
    /// - The server has rotated keys
    /// - Cookies have been exhausted
    /// - AEAD verification failures indicate stale keys
    pub async fn reconnect(&mut self) -> Result<()> {
        debug!("Reconnecting to NTS server");
        self.socket = None;
        self.nts_state = None;
        self.ntp_server = None;
        self.ke_info = None;
        self.connect().await
    }
}

impl Drop for NtsClient {
    fn drop(&mut self) {
        debug!("NtsClient dropped");
    }
}
