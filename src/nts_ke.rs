//! NTS Key Exchange (NTS-KE) implementation using ntp-proto.
//!
//! This module wraps ntp-proto's KeyExchangeClient to provide an async interface.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use ntp_proto::{KeyExchangeClient, KeyExchangeError, KeyExchangeResult, ProtocolVersion};
use tracing::{debug, info, warn};

use crate::config::NtsClientConfig;
use crate::error::{Error, Result};
use crate::types::NtsKeResult;

/// Perform NTS-KE using ntp-proto's KeyExchangeClient
pub(crate) async fn perform_nts_ke(config: &NtsClientConfig) -> Result<NtsKeResult> {
    let ke_start = std::time::Instant::now();

    info!(
        "Starting NTS-KE with {}:{}",
        config.nts_ke_server, config.nts_ke_port
    );

    // Resolve server address
    let server_addr = resolve_server(&config.nts_ke_server, config.nts_ke_port).await?;
    debug!("Resolved server address: {}", server_addr);

    // Build TLS config
    let tls_config = build_tls_config(config)?;

    // Determine protocol version (always V4 for now)
    let protocol_version = ProtocolVersion::V4;

    // Perform key exchange in a blocking task since KeyExchangeClient uses sync I/O
    let server_name = config.nts_ke_server.clone();
    let timeout_duration = config.timeout;

    let result = tokio::task::spawn_blocking(move || {
        perform_nts_ke_blocking(
            server_addr,
            server_name,
            tls_config,
            protocol_version,
            timeout_duration,
        )
    })
    .await
    .map_err(|e| Error::KeyExchange(format!("Task join error: {}", e)))??;

    let ke_duration = ke_start.elapsed();
    debug!("NTS-KE completed in {:?}", ke_duration);

    // Convert KeyExchangeResult to NtsKeResult
    convert_ke_result(result, ke_duration)
}

/// Perform NTS-KE in a blocking context
fn perform_nts_ke_blocking(
    server_addr: SocketAddr,
    server_name: String,
    tls_config: ntp_proto::tls_utils::ClientConfig,
    protocol_version: ProtocolVersion,
    timeout_duration: Duration,
) -> Result<KeyExchangeResult> {
    // Connect TCP socket (blocking)
    let mut socket =
        std::net::TcpStream::connect_timeout(&server_addr, timeout_duration).map_err(Error::Io)?;

    socket.set_nonblocking(true).map_err(Error::Io)?;

    debug!("TCP connection established");

    // Create KeyExchangeClient
    let mut ke_client = KeyExchangeClient::new(
        server_name,
        tls_config,
        protocol_version,
        Vec::<String>::new(), // no denied servers
    )
    .map_err(Error::from)?;

    debug!("KeyExchangeClient created");

    // Run the state machine
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > timeout_duration {
            return Err(Error::Timeout);
        }

        // Write any pending TLS data to socket
        if ke_client.wants_write() {
            match ke_client.write_socket(&mut socket) {
                Ok(n) => {
                    if n > 0 {
                        debug!("Wrote {} bytes to socket", n);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }

        // Read any available data from socket
        if ke_client.wants_read() {
            match ke_client.read_socket(&mut socket) {
                Ok(n) => {
                    if n > 0 {
                        debug!("Read {} bytes from socket", n);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }

        // Progress the state machine
        match ke_client.progress() {
            std::ops::ControlFlow::Break(Ok(result)) => {
                debug!("NTS-KE succeeded");
                return Ok(result);
            }
            std::ops::ControlFlow::Break(Err(e)) => {
                return Err(Error::from(e));
            }
            std::ops::ControlFlow::Continue(client) => {
                ke_client = client;
                // Small sleep to avoid busy-waiting
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// Build TLS config for NTS-KE
fn build_tls_config(config: &NtsClientConfig) -> Result<ntp_proto::tls_utils::ClientConfig> {
    use ntp_proto::tls_utils::{self, Certificate};

    // Ensure a default crypto provider is installed
    // This is safe to call multiple times - it will only install once
    let _ = rustls::crypto::ring::default_provider().install_default();

    if config.verify_tls_cert {
        // Normal verification with system certificates
        let builder = tls_utils::client_config_builder_with_protocol_versions(&[&tls_utils::TLS13]);
        let provider = builder.crypto_provider().clone();

        let verifier =
            tls_utils::PlatformVerifier::new_with_extra_roots(std::iter::empty::<Certificate>())
                .map_err(|e| Error::Tls(format!("Failed to create verifier: {}", e)))?
                .with_provider(provider);

        Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth())
    } else {
        // No verification mode (for self-signed certificates)
        warn!("TLS certificate verification is disabled!");

        let builder = tls_utils::client_config_builder_with_protocol_versions(&[&tls_utils::TLS13]);
        let provider = builder.crypto_provider().clone();

        // Use NoVerification verifier
        let verifier = NoVerification { provider };

        Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth())
    }
}

/// A certificate verifier that accepts all certificates (for testing only!)
#[derive(Debug)]
struct NoVerification {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Resolve server address
async fn resolve_server(server: &str, port: u16) -> Result<SocketAddr> {
    let addrs = format!("{}:{}", server, port)
        .to_socket_addrs()
        .map_err(|e| Error::ServerUnavailable(format!("DNS resolution failed: {}", e)))?;

    addrs
        .into_iter()
        .next()
        .ok_or_else(|| Error::ServerUnavailable("No addresses resolved".to_string()))
}

/// Convert ntp-proto's KeyExchangeResult to our NtsKeResult
fn convert_ke_result(
    mut result: KeyExchangeResult,
    ke_duration: Duration,
) -> std::result::Result<NtsKeResult, Error> {
    // Try to parse the remote as an IP address first, otherwise resolve it
    let ntp_server = if let Ok(ip_addr) = result.remote.parse() {
        SocketAddr::new(ip_addr, result.port)
    } else {
        // If not an IP, try to resolve the hostname
        let addr_str = format!("{}:{}", result.remote, result.port);
        addr_str
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .ok_or_else(|| {
                Error::Other(format!(
                    "Failed to resolve NTP server address: {}:{}. DNS resolution returned no results.",
                    result.remote, result.port
                ))
            })?
    };

    // Extract cookies from the CookieStash by consuming them using the public API
    // CookieStash is not Clone, so we need to extract all cookies into a Vec
    let mut cookies = Vec::new();
    while let Some(cookie) = result.nts.get_cookie() {
        cookies.push(cookie);
    }

    // Get a reference to the cipher to determine the algorithm
    // We use "AEAD_AES_SIV_CMAC_256" as default since it's the most common
    let aead_algorithm = "AEAD_AES_SIV_CMAC_256".to_string();

    Ok(NtsKeResult::new(
        ntp_server,
        aead_algorithm,
        cookies,
        ke_duration,
        result.nts,
    ))
}

/// Convert KeyExchangeError to our Error type
impl From<KeyExchangeError> for Error {
    fn from(err: KeyExchangeError) -> Self {
        match err {
            KeyExchangeError::UnrecognizedCriticalRecord => {
                Error::KeyExchange("Unrecognized critical NTS record".to_string())
            }
            KeyExchangeError::BadRequest => Error::KeyExchange("Bad request".to_string()),
            KeyExchangeError::InternalServerError => {
                Error::KeyExchange("Internal server error".to_string())
            }
            KeyExchangeError::UnknownErrorCode(code) => {
                Error::KeyExchange(format!("Unknown error code: {}", code))
            }
            KeyExchangeError::BadResponse => Error::KeyExchange("Bad response".to_string()),
            KeyExchangeError::NoValidProtocol => {
                Error::KeyExchange("No valid protocol negotiated".to_string())
            }
            KeyExchangeError::NoValidAlgorithm => {
                Error::KeyExchange("No valid AEAD algorithm negotiated".to_string())
            }
            KeyExchangeError::InvalidFixedKeyLength => {
                Error::KeyExchange("Invalid fixed key length".to_string())
            }
            KeyExchangeError::NoCookies => Error::KeyExchange("No cookies received".to_string()),
            KeyExchangeError::CookiesTooBig => Error::KeyExchange("Cookies too big".to_string()),
            KeyExchangeError::Io(e) => Error::Io(e),
            KeyExchangeError::Tls(e) => Error::Tls(format!("TLS error: {:?}", e)),
            KeyExchangeError::Certificate(e) => Error::Tls(format!("Certificate error: {:?}", e)),
            KeyExchangeError::DnsName(e) => Error::Tls(format!("DNS name error: {:?}", e)),
            KeyExchangeError::IncompleteResponse => {
                Error::KeyExchange("Incomplete NTS-KE response".to_string())
            }
        }
    }
}
