//! NTS Key Exchange (NTS-KE) implementation using ntp-proto.
//!
//! This module wraps ntp-proto's KeyExchangeClient to provide an async interface.

use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ntp_proto::{KeyExchangeClient, KeyExchangeError, KeyExchangeResult, ProtocolVersion};
use rustls::pki_types::{CertificateDer, ServerName as RustlsServerName, UnixTime};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use x509_parser::prelude::*;

use crate::config::NtsClientConfig;
use crate::error::{Error, Result};
use crate::types::{CertificateInfo, NtsKeResult};

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

    // Build TLS config with certificate capturing
    let (tls_config, captured_certs) = build_tls_config(config)?;

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

    // Extract certificate information after successful handshake
    let certificate = {
        let certs = captured_certs.lock().unwrap();
        if !certs.is_empty() {
            extract_certificate_info(&certs)
        } else {
            None
        }
    };

    if let Some(ref cert) = certificate {
        debug!(
            "Captured certificate: subject={}, issuer={}",
            cert.subject, cert.issuer
        );
    }

    // Convert KeyExchangeResult to NtsKeResult
    convert_ke_result(result, ke_duration, certificate)
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

/// Extract certificate information from the peer certificate
fn extract_certificate_info(certs: &[CertificateDer<'_>]) -> Option<CertificateInfo> {
    // Get the first certificate (server certificate)
    let cert_der = certs.first()?;

    // Parse the certificate using x509-parser
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref()).ok()?;

    // Extract subject
    let subject = cert.subject().to_string();

    // Extract issuer
    let issuer = cert.issuer().to_string();

    // Extract validity period and convert to RFC3339-like format
    let valid_from = format!("{}", cert.validity().not_before);
    let valid_until = format!("{}", cert.validity().not_after);

    // Extract serial number as hex string
    let serial_number = format!("{:x}", cert.serial);

    // Extract SANs (Subject Alternative Names)
    let san_dns_names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(name) => Some(name.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Extract signature algorithm
    let signature_algorithm = cert.signature_algorithm.algorithm.to_string();

    // Extract public key algorithm
    let public_key_algorithm = cert.public_key().algorithm.algorithm.to_string();

    // Calculate SHA-256 fingerprint
    let mut hasher = Sha256::new();
    hasher.update(cert_der.as_ref());
    let fingerprint_sha256 = format!("{:x}", hasher.finalize());

    // Check if self-signed (simple check: subject == issuer)
    let is_self_signed = cert.subject() == cert.issuer();

    Some(CertificateInfo {
        subject,
        issuer,
        valid_from,
        valid_until,
        serial_number,
        san_dns_names,
        signature_algorithm,
        public_key_algorithm,
        fingerprint_sha256,
        is_self_signed,
    })
}

/// Custom certificate verifier that captures the certificate chain
#[derive(Debug)]
struct CapturingVerifier {
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    captured_certs: Arc<Mutex<Vec<CertificateDer<'static>>>>,
}

impl rustls::client::danger::ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &RustlsServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Capture the certificates
        let mut certs = self.captured_certs.lock().unwrap();
        certs.push(end_entity.clone().into_owned());
        for cert in intermediates {
            certs.push(cert.clone().into_owned());
        }

        // Delegate to the real verifier
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build TLS config for NTS-KE with certificate capturing
fn build_tls_config(
    config: &NtsClientConfig,
) -> Result<(
    ntp_proto::tls_utils::ClientConfig,
    Arc<Mutex<Vec<CertificateDer<'static>>>>,
)> {
    use ntp_proto::tls_utils::{self};

    // Ensure a default crypto provider is installed
    // This is safe to call multiple times - it will only install once
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Enable TLS keylog for Wireshark decryption if SSLKEYLOGFILE is set
    let key_log = std::env::var("SSLKEYLOGFILE")
        .ok()
        .and_then(|path| {
            debug!("Enabling TLS keylog to: {}", path);
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .ok()
        })
        .map(|file| Arc::new(KeyLogFile(Mutex::new(file))) as Arc<dyn rustls::KeyLog>);

    // Create container for captured certificates
    let captured_certs = Arc::new(Mutex::new(Vec::new()));

    if config.verify_tls_cert {
        // Normal verification with system certificates
        let builder = tls_utils::client_config_builder_with_protocol_versions(&[&tls_utils::TLS13]);
        let provider = builder.crypto_provider().clone();

        let platform_verifier = tls_utils::PlatformVerifier::new().with_provider(provider);

        // Wrap with capturing verifier
        let capturing_verifier = CapturingVerifier {
            inner: Arc::new(platform_verifier),
            captured_certs: captured_certs.clone(),
        };

        let mut tls_config = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(capturing_verifier))
            .with_no_client_auth();

        if let Some(kl) = key_log {
            tls_config.key_log = kl;
        }

        Ok((tls_config, captured_certs))
    } else {
        // No verification mode (for self-signed certificates)
        warn!("TLS certificate verification is disabled!");

        let builder = tls_utils::client_config_builder_with_protocol_versions(&[&tls_utils::TLS13]);
        let provider = builder.crypto_provider().clone();

        // Use NoVerification verifier wrapped with capturing
        let no_verification = NoVerification { provider };

        let capturing_verifier = CapturingVerifier {
            inner: Arc::new(no_verification),
            captured_certs: captured_certs.clone(),
        };

        let mut tls_config = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(capturing_verifier))
            .with_no_client_auth();

        if let Some(kl) = key_log {
            tls_config.key_log = kl;
        }

        Ok((tls_config, captured_certs))
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
    certificate: Option<CertificateInfo>,
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

    debug!("Extracted {} cookies from NTS-KE", cookies.len());

    // Extract the ciphers from SourceNtsData using get_keys()
    // This consumes the SourceNtsData and returns (c2s, s2c) ciphers
    let (c2s, s2c) = result.nts.get_keys();

    debug!("Extracted NTS ciphers for authenticated NTP");

    // Use "AEAD_AES_SIV_CMAC_256" as default since it's the most common negotiated algorithm
    let aead_algorithm = "AEAD_AES_SIV_CMAC_256".to_string();

    Ok(NtsKeResult::new(
        ntp_server,
        aead_algorithm,
        cookies,
        ke_duration,
        c2s,
        s2c,
        certificate,
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

/// KeyLog handler for writing TLS secrets to file (for Wireshark decryption)
#[derive(Debug)]
struct KeyLogFile(Mutex<std::fs::File>);

impl rustls::KeyLog for KeyLogFile {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if let Ok(mut file) = self.0.lock() {
            let _ = writeln!(
                file,
                "{} {} {}",
                label,
                to_hex(client_random),
                to_hex(secret)
            );
            let _ = file.flush();
        }
    }
}

/// Encode bytes to hexadecimal string
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
