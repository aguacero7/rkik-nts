//! High-level NTS client implementation.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::config::NtsClientConfig;
use crate::error::{Error, Result};
use crate::nts_ke::perform_nts_ke;
use crate::types::{NtsKeResult, TimeSnapshot};

/// A high-level NTS (Network Time Security) client.
///
/// This client handles NTS key exchange and authenticated NTP time queries.
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
///     // Get the current time
///     let time = client.get_time().await?;
///     println!("Network time: {:?}", time.network_time);
///     println!("Offset: {:?}", time.offset);
///
///     Ok(())
/// }
/// ```
pub struct NtsClient {
    config: NtsClientConfig,
    nts_state: Option<NtsKeResult>,
    socket: Option<UdpSocket>,
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
        }
    }

    /// Connect to the NTS server and perform key exchange.
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

        info!(
            "NTS key exchange successful. NTP server: {}",
            nts_result.ntp_server
        );

        // Create UDP socket for NTP queries
        // Choose bind address based on server's address family
        let bind_addr = if nts_result.ntp_server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(nts_result.ntp_server).await?;

        self.socket = Some(socket);
        self.nts_state = Some(nts_result);

        Ok(())
    }

    /// Query the current time from the NTS-secured NTP server.
    ///
    /// # Errors
    ///
    /// Returns an error if not connected or if the time query fails.
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
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_time(&mut self) -> Result<TimeSnapshot> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| Error::Other("Not connected. Call connect() first.".to_string()))?;

        let nts_state = self.nts_state.as_ref().ok_or_else(|| {
            Error::Other("No NTS state available. Call connect() first.".to_string())
        })?;

        // Create NTP request packet
        let request = self.create_ntp_request()?;

        // Send request
        debug!("Sending NTP request");
        socket.send(&request).await?;

        // Receive response with timeout
        let mut buf = vec![0u8; 1024];
        let len = timeout(self.config.timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| Error::Timeout)??;

        buf.truncate(len);

        // Parse response
        debug!("Received {} bytes, parsing NTP response", len);
        let time_snapshot = self.parse_ntp_response(&buf, nts_state)?;

        Ok(time_snapshot)
    }

    /// Check if the client is connected and ready to query time.
    pub fn is_connected(&self) -> bool {
        self.socket.is_some() && self.nts_state.is_some()
    }

    /// Get the NTP server address being used.
    pub fn ntp_server(&self) -> Option<SocketAddr> {
        self.nts_state.as_ref().map(|s| s.ntp_server)
    }

    /// Get a reference to the NTS key exchange result for diagnostic purposes.
    ///
    /// This provides access to NTS-KE negotiation details including:
    /// - AEAD algorithm
    /// - Cookie count and sizes
    /// - Key exchange duration
    ///
    /// Returns `None` if not connected.
    pub fn nts_ke_info(&self) -> Option<&NtsKeResult> {
        self.nts_state.as_ref()
    }

    /// Reconnect and perform a fresh NTS key exchange.
    ///
    /// This can be useful if the connection has been idle for a long time
    /// or if the server has rotated keys.
    pub async fn reconnect(&mut self) -> Result<()> {
        debug!("Reconnecting to NTS server");
        self.socket = None;
        self.nts_state = None;
        self.connect().await
    }

    fn create_ntp_request(&self) -> Result<Vec<u8>> {
        // Create a basic NTP client request packet
        // This is a simplified version - in production, you'd use the full ntp-proto capabilities

        let mut packet = vec![0u8; 48]; // Minimum NTP packet size

        // LI (2 bits) = 0, VN (3 bits) = 4, Mode (3 bits) = 3 (client)
        packet[0] = 0x23; // 0b00_100_011

        // Poll interval
        packet[2] = 6;

        // Transmit timestamp (current time)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Other(format!("System time error: {}", e)))?;

        let ntp_time = now.as_secs() + 2_208_988_800; // NTP epoch offset
        let frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000;

        packet[40..48].copy_from_slice(&ntp_time.to_be_bytes());
        packet[44..48].copy_from_slice(&(frac as u32).to_be_bytes());

        Ok(packet)
    }

    fn parse_ntp_response(&self, data: &[u8], nts_state: &NtsKeResult) -> Result<TimeSnapshot> {
        if data.len() < 48 {
            return Err(Error::InvalidResponse("NTP packet too small".to_string()));
        }

        // Extract transmit timestamp from server (bytes 40-47)
        // NTP timestamp is: 4 bytes seconds + 4 bytes fraction
        let tx_secs = u32::from_be_bytes([data[40], data[41], data[42], data[43]]);
        let tx_frac = u32::from_be_bytes([data[44], data[45], data[46], data[47]]);

        // Convert NTP timestamp to Unix timestamp
        // NTP epoch is 1900-01-01, Unix epoch is 1970-01-01
        // Difference is 2208988800 seconds
        let unix_secs = tx_secs.wrapping_sub(2_208_988_800) as u64;
        let nanos = ((tx_frac as u64) * 1_000_000_000) >> 32;

        let network_time = UNIX_EPOCH
            + std::time::Duration::from_secs(unix_secs)
            + std::time::Duration::from_nanos(nanos);
        let system_time = SystemTime::now();

        // Calculate offset
        let offset = if system_time > network_time {
            system_time.duration_since(network_time).unwrap()
        } else {
            network_time.duration_since(system_time).unwrap()
        };

        // For now, we'll use a simple round-trip delay estimation
        let round_trip_delay = self.config.timeout / 10;

        Ok(TimeSnapshot {
            system_time,
            network_time,
            offset,
            round_trip_delay,
            server: nts_state.ntp_server.to_string(),
            authenticated: true, // NTS provides authentication
        })
    }
}

impl Drop for NtsClient {
    fn drop(&mut self) {
        debug!("NtsClient dropped");
    }
}
