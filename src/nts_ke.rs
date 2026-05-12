//! NTS Key Exchange (NTS-KE) implementation (RFC 8915 §4).
//!
//! This module implements the NTS-KE handshake directly over TLS 1.3 with
//! the `"ntske/1"` ALPN identifier.  Keys are derived from the TLS session
//! via RFC 5705 keying-material export.

#[cfg(feature = "tls-keylog")]
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, ServerName as RustlsServerName, UnixTime};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use x509_parser::prelude::*;
use zeroize::Zeroizing;

use crate::cipher::{AeadCipher, AEAD_AES_SIV_CMAC_256, AEAD_AES_SIV_CMAC_512};
use crate::config::NtsClientConfig;
use crate::error::{Error, Result};
use crate::types::{CertificateInfo, NtsKeResult};

const NTPV4_PROTOCOL_ID: u16 = 0;
const NTS_KE_MAX_RECORDS: usize = 1024;
const NTS_KE_MAX_COOKIE_BYTES: usize = 64 * 1024;
const NTS_KE_MAX_RESPONSE_BYTES: usize = 128 * 1024;

#[derive(Debug, Default)]
struct NtsKeParseState {
    negotiated_protocol: bool,
    aead_alg: Option<u16>,
    cookies: Vec<Vec<u8>>,
    cookie_bytes: usize,
    ntp_server: Option<String>,
    ntp_port: Option<u16>,
}

/// Perform the NTS Key Exchange handshake (RFC 8915 §4).
///
/// Opens a TLS 1.3 connection to the NTS-KE server with ALPN `"ntske/1"`,
/// exchanges NTS-KE records, and derives the c2s/s2c cipher keys from the
/// TLS session via RFC 5705 keying material export.
pub(crate) async fn perform_nts_ke(config: &NtsClientConfig) -> Result<NtsKeResult> {
    let ke_start = std::time::Instant::now();

    info!(
        "Starting NTS-KE with {}:{}",
        config.nts_ke_server, config.nts_ke_port
    );

    let server_addrs =
        resolve_server(&config.nts_ke_server, config.nts_ke_port, config.timeout).await?;
    debug!("Resolved NTS-KE server addresses: {server_addrs:?}");

    let (tls_config, captured_certs) = build_tls_config(config)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let mut last_connect_error = None;
    let mut tcp_stream = None;
    for server_addr in &server_addrs {
        match tokio::time::timeout(config.timeout, tokio::net::TcpStream::connect(server_addr))
            .await
        {
            Ok(Ok(stream)) => {
                tcp_stream = Some(stream);
                break;
            }
            Ok(Err(err)) => last_connect_error = Some(err.to_string()),
            Err(_) => last_connect_error = Some(format!("timed out connecting to {server_addr}")),
        }
    }
    let tcp_stream = tcp_stream.ok_or_else(|| {
        Error::ServerUnavailable(
            last_connect_error
                .unwrap_or_else(|| "unable to connect to any resolved address".to_string()),
        )
    })?;

    let server_name = rustls::pki_types::ServerName::try_from(config.nts_ke_server.as_str())
        .map_err(|e| {
            Error::Tls(format!(
                "Invalid server name '{}': {e}",
                config.nts_ke_server
            ))
        })?
        .to_owned();

    let mut tls_stream =
        tokio::time::timeout(config.timeout, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::Tls(format!("TLS handshake failed: {e}")))?;

    debug!("TLS handshake complete");

    let negotiated_alpn = tls_stream.get_ref().1.alpn_protocol();
    if negotiated_alpn != Some(b"ntske/1".as_slice()) {
        return Err(Error::Tls(format!(
            "server did not negotiate ALPN ntske/1 (got {:?})",
            negotiated_alpn.map(String::from_utf8_lossy)
        )));
    }

    {
        use tokio::io::AsyncWriteExt;

        // NTS Next Protocol Negotiation (type 1, critical, RFC 8915 §4.1.2).
        // Body: list of 2-byte protocol IDs. NTPv4 = 0x0000.
        tokio::time::timeout(
            config.timeout,
            write_record(&mut tls_stream, true, 1, &[0x00, 0x00]),
        )
        .await
        .map_err(|_| Error::Timeout)??;

        // AEAD Algorithm Negotiation (type 4, critical).
        // Offer AEAD_AES_SIV_CMAC_256 (15) then AEAD_AES_SIV_CMAC_512 (17).
        tokio::time::timeout(
            config.timeout,
            write_record(&mut tls_stream, true, 4, &[0x00, 0x0F, 0x00, 0x11]),
        )
        .await
        .map_err(|_| Error::Timeout)??;

        // End of Message (type 0, critical).
        tokio::time::timeout(config.timeout, write_record(&mut tls_stream, true, 0, &[]))
            .await
            .map_err(|_| Error::Timeout)??;

        tokio::time::timeout(config.timeout, tls_stream.flush())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;
    }

    // Read server records until End of Message.
    let mut state = NtsKeParseState::default();
    let mut record_count = 0usize;
    let mut response_bytes = 0usize;

    loop {
        let (critical, type_id, body) =
            tokio::time::timeout(config.timeout, read_record(&mut tls_stream))
                .await
                .map_err(|_| Error::Timeout)??;
        record_count += 1;
        response_bytes = response_bytes.saturating_add(4 + body.len());
        if record_count > NTS_KE_MAX_RECORDS {
            return Err(Error::KeyExchange(
                "NTS-KE response exceeded record limit".to_string(),
            ));
        }
        if response_bytes > NTS_KE_MAX_RESPONSE_BYTES {
            return Err(Error::KeyExchange(
                "NTS-KE response exceeded size limit".to_string(),
            ));
        }

        match type_id {
            // End of Message
            0 => {
                debug!("Received NTS-KE End of Message");
                break;
            }
            // NTS Next Protocol Negotiation — server echoes confirmed protocol(s).
            1 => {
                if state.negotiated_protocol {
                    return Err(Error::KeyExchange(
                        "received duplicate NTS Next Protocol Negotiation record".to_string(),
                    ));
                }
                let protocols = parse_u16_list(&body, "NTS Next Protocol Negotiation")?;
                state.negotiated_protocol = protocols.contains(&NTPV4_PROTOCOL_ID);
                if !state.negotiated_protocol {
                    return Err(Error::KeyExchange(
                        "server did not negotiate NTPv4 in NTS Next Protocol Negotiation"
                            .to_string(),
                    ));
                }
            }
            // AEAD Algorithm Negotiation
            4 => {
                if state.aead_alg.is_some() {
                    return Err(Error::KeyExchange(
                        "received duplicate AEAD Algorithm Negotiation record".to_string(),
                    ));
                }
                let algorithms = parse_u16_list(&body, "AEAD Algorithm Negotiation")?;
                for alg in algorithms {
                    if AeadCipher::key_len(alg).is_some() {
                        state.aead_alg = Some(alg);
                        debug!("Negotiated AEAD algorithm: {alg}");
                        break;
                    }
                }
                if state.aead_alg.is_none() {
                    return Err(Error::KeyExchange(
                        "server did not offer a supported AEAD algorithm".to_string(),
                    ));
                }
            }
            // New Cookie for NTPv4
            5 => {
                if body.is_empty() {
                    return Err(Error::KeyExchange(
                        "server returned empty NTS cookie".to_string(),
                    ));
                }
                state.cookie_bytes = state.cookie_bytes.saturating_add(body.len());
                if state.cookie_bytes > NTS_KE_MAX_COOKIE_BYTES {
                    return Err(Error::KeyExchange(
                        "server returned too much cookie data".to_string(),
                    ));
                }
                debug!("Received cookie ({} bytes)", body.len());
                state.cookies.push(body);
            }
            // NTPv4 Server Negotiation
            6 => {
                if state.ntp_server.is_some() {
                    return Err(Error::KeyExchange(
                        "received duplicate NTPv4 Server Negotiation record".to_string(),
                    ));
                }
                let name = String::from_utf8(body).map_err(|_| {
                    Error::KeyExchange("NTPv4 Server Negotiation is not valid UTF-8".to_string())
                })?;
                if name.is_empty() {
                    return Err(Error::KeyExchange(
                        "NTPv4 Server Negotiation is empty".to_string(),
                    ));
                }
                debug!("NTS-KE negotiated NTP server: {name}");
                state.ntp_server = Some(name);
            }
            // NTPv4 Port Negotiation
            7 => {
                if state.ntp_port.is_some() {
                    return Err(Error::KeyExchange(
                        "received duplicate NTPv4 Port Negotiation record".to_string(),
                    ));
                }
                let ports = parse_u16_list(&body, "NTPv4 Port Negotiation")?;
                if ports.len() != 1 {
                    return Err(Error::KeyExchange(
                        "NTPv4 Port Negotiation must contain exactly one port".to_string(),
                    ));
                }
                let port = ports[0];
                debug!("NTS-KE negotiated NTP port: {port}");
                state.ntp_port = Some(port);
            }
            2 => {
                let errors = parse_u16_list(&body, "Error")?;
                let code = errors.first().copied().unwrap_or_default();
                return Err(Error::KeyExchange(format!(
                    "server returned NTS-KE error code {code}"
                )));
            }
            3 => {
                // RFC 8915: Warning records are advisory; do not abort the exchange.
                let warnings = parse_u16_list(&body, "Warning")?;
                let code = warnings.first().copied().unwrap_or_default();
                warn!("NTS-KE server advisory warning code {code}; continuing");
            }
            _ if critical => {
                return Err(Error::KeyExchange(format!(
                    "Received unknown critical NTS-KE record (type {type_id})"
                )));
            }
            _ => {
                debug!("Ignoring unknown non-critical NTS-KE record (type {type_id})");
            }
        }
    }

    {
        use tokio::io::AsyncWriteExt;
        let _ = tokio::time::timeout(config.timeout, tls_stream.shutdown()).await;
    }

    // Validate the exchange result.
    if !state.negotiated_protocol {
        return Err(Error::KeyExchange(
            "server did not negotiate an NTP next protocol".to_string(),
        ));
    }
    let alg_id = state.aead_alg.ok_or_else(|| {
        Error::KeyExchange("Server did not negotiate an AEAD algorithm".to_string())
    })?;
    if state.cookies.is_empty() {
        return Err(Error::KeyExchange(
            "Server did not provide any NTS cookies".to_string(),
        ));
    }

    // Derive c2s and s2c keys via TLS keying material export (RFC 5705 /
    // RFC 8446 §7.5, label "EXPORTER-network-time-security").
    //
    // Context: [protocol_id_hi, protocol_id_lo, alg_id_hi, alg_id_lo, direction]
    // For NTPv4, protocol ID is 0x0000.
    //   direction 0x00 = client-to-server
    //   direction 0x01 = server-to-client
    let key_len = AeadCipher::key_len(alg_id).unwrap(); // validated above
    let protocol_id = 0u16.to_be_bytes();
    let alg_bytes = alg_id.to_be_bytes();
    let mut c2s_key = Zeroizing::new(vec![0u8; key_len]);
    let mut s2c_key = Zeroizing::new(vec![0u8; key_len]);

    {
        let (_, tls_conn) = tls_stream.get_ref();
        tls_conn
            .export_keying_material(
                c2s_key.as_mut_slice(),
                b"EXPORTER-network-time-security",
                Some(&[
                    protocol_id[0],
                    protocol_id[1],
                    alg_bytes[0],
                    alg_bytes[1],
                    0x00,
                ]),
            )
            .map_err(|e| Error::Tls(format!("TLS key export failed: {e}")))?;
        tls_conn
            .export_keying_material(
                s2c_key.as_mut_slice(),
                b"EXPORTER-network-time-security",
                Some(&[
                    protocol_id[0],
                    protocol_id[1],
                    alg_bytes[0],
                    alg_bytes[1],
                    0x01,
                ]),
            )
            .map_err(|e| Error::Tls(format!("TLS key export failed: {e}")))?;
    }

    let c2s = AeadCipher::from_key_bytes(alg_id, c2s_key.as_slice())?;
    let s2c = AeadCipher::from_key_bytes(alg_id, s2c_key.as_slice())?;

    let ke_duration = ke_start.elapsed();
    debug!("NTS-KE completed in {ke_duration:?}");

    // Extract certificate information captured during the TLS handshake.
    let certificate = {
        let certs = captured_certs.lock().unwrap_or_else(|e| e.into_inner());
        if certs.is_empty() {
            None
        } else {
            extract_certificate_info(&certs)
        }
    };

    // Determine the NTP server and port to use.
    let (ntp_server_addr, ntp_server_addrs) = if let Some(addr) = config.ntp_server {
        (addr, vec![addr])
    } else {
        let ntp_host = state
            .ntp_server
            .clone()
            .unwrap_or_else(|| config.nts_ke_server.clone());
        let ntp_port = state.ntp_port.unwrap_or(123);
        let addrs = resolve_server(&ntp_host, ntp_port, config.timeout).await?;
        let primary = *addrs.first().ok_or_else(|| {
            Error::ServerUnavailable("No NTP server addresses resolved".to_string())
        })?;
        (primary, addrs)
    };

    let aead_algorithm = match alg_id {
        AEAD_AES_SIV_CMAC_256 => "AEAD_AES_SIV_CMAC_256".to_string(),
        AEAD_AES_SIV_CMAC_512 => "AEAD_AES_SIV_CMAC_512".to_string(),
        _ => format!("UNKNOWN_{alg_id}"),
    };

    info!(
        "NTS-KE successful. NTP server: {ntp_server_addr}, algorithm: {aead_algorithm}, cookies: {}",
        state.cookies.len()
    );

    Ok(NtsKeResult {
        ntp_server: ntp_server_addr,
        ntp_server_addrs,
        aead_algorithm,
        cookies: state.cookies,
        ke_duration,
        c2s,
        s2c,
        certificate,
    })
}

fn asn1_time_to_rfc3339(t: x509_parser::time::ASN1Time) -> String {
    use chrono::{DateTime, Utc};
    DateTime::from_timestamp(t.timestamp(), 0)
        .map(|dt: DateTime<Utc>| dt.to_rfc3339())
        .unwrap_or_else(|| format!("{t}"))
}

fn parse_u16_list(body: &[u8], record_name: &str) -> Result<Vec<u16>> {
    if body.is_empty() {
        return Ok(Vec::new());
    }
    if body.len() % 2 != 0 {
        return Err(Error::KeyExchange(format!(
            "{record_name} record has invalid body length {}",
            body.len()
        )));
    }
    Ok(body
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect())
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

    // Extract validity period in RFC3339 format via Unix timestamp.
    let valid_from = asn1_time_to_rfc3339(cert.validity().not_before);
    let valid_until = asn1_time_to_rfc3339(cert.validity().not_after);

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
        let mut certs = self
            .captured_certs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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

/// Build a `rustls::ClientConfig` for NTS-KE.
///
/// The configuration enforces TLS 1.3 and sets the ALPN protocol to
/// `"ntske/1"` as required by RFC 8915 §4. A [`CapturingVerifier`] is
/// layered on top of the real verifier so that the peer certificate chain
/// can be surfaced in [`NtsKeResult`].
fn build_tls_config(
    config: &NtsClientConfig,
) -> Result<(
    rustls::ClientConfig,
    Arc<Mutex<Vec<CertificateDer<'static>>>>,
)> {
    // Ensure the ring crypto provider is installed (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let captured_certs = Arc::new(Mutex::new(Vec::new()));

    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = if config.verify_tls_cert {
        let roots = load_root_certs();
        let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| Error::Tls(format!("Failed to build TLS verifier: {e}")))?;
        Arc::new(CapturingVerifier {
            inner,
            captured_certs: captured_certs.clone(),
        })
    } else {
        warn!("TLS certificate verification is disabled!");
        Arc::new(CapturingVerifier {
            inner: Arc::new(NoVerification {
                provider: rustls::crypto::ring::default_provider().into(),
            }),
            captured_certs: captured_certs.clone(),
        })
    };

    let mut tls_config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

    // RFC 8915 §4 requires the "ntske/1" ALPN protocol identifier.
    tls_config.alpn_protocols = vec![b"ntske/1".to_vec()];

    // Enable TLS key logging if SSLKEYLOGFILE is set (for Wireshark).
    if let Some(kl) = make_key_log() {
        tls_config.key_log = kl;
    }

    Ok((tls_config, captured_certs))
}

/// Load root certificates from the OS trust store, supplemented by the
/// embedded Mozilla root set from `webpki-roots`.
fn load_root_certs() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();

    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        if let Err(e) = roots.add(cert) {
            debug!("Skipping native CA cert: {e}");
        }
    }
    for err in native.errors {
        debug!("Native cert load warning: {err}");
    }

    // Add the Mozilla root set as a fallback (covers cases where the OS
    // trust store is empty or unavailable).
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    roots
}

/// Build a TLS key-log sink from the `SSLKEYLOGFILE` environment variable.
///
/// Returns `None` if the variable is unset or if the file cannot be opened.
fn make_key_log() -> Option<Arc<dyn rustls::KeyLog>> {
    #[cfg(not(feature = "tls-keylog"))]
    {
        if std::env::var("SSLKEYLOGFILE").is_ok() {
            warn!("SSLKEYLOGFILE is ignored unless the tls-keylog feature is enabled");
        }
        None
    }

    #[cfg(feature = "tls-keylog")]
    std::env::var("SSLKEYLOGFILE")
        .ok()
        .and_then(|path| {
            debug!("Enabling TLS key log: {path}");
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| warn!("Failed to open SSLKEYLOGFILE '{}': {e}", path))
                .ok()
        })
        .map(|file| Arc::new(KeyLogFile(Mutex::new(file))) as Arc<dyn rustls::KeyLog>)
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
async fn resolve_server(
    server: &str,
    port: u16,
    timeout: std::time::Duration,
) -> Result<Vec<SocketAddr>> {
    if let Ok(addr) = format!("{server}:{port}").parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }

    let addrs = tokio::time::timeout(timeout, tokio::net::lookup_host((server, port)))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::ServerUnavailable(format!("DNS resolution failed: {e}")))?;

    let mut resolved: Vec<_> = addrs.collect();
    resolved.sort_unstable();
    resolved.dedup();
    if resolved.is_empty() {
        return Err(Error::ServerUnavailable(
            "No addresses resolved".to_string(),
        ));
    }
    Ok(resolved)
}

/// KeyLog handler for writing TLS secrets to file (for Wireshark decryption)
#[cfg(feature = "tls-keylog")]
#[derive(Debug)]
struct KeyLogFile(Mutex<std::fs::File>);

#[cfg(feature = "tls-keylog")]
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
#[cfg(feature = "tls-keylog")]
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Write a single NTS-KE record to an async writer.
///
/// Wire format (RFC 8915 §4.1):
///
/// ```text
/// +--------+--------+--------+--------+
/// |C| type (15 bits)|  body length    |
/// +--------+--------+--------+--------+
/// |            body (variable)         |
/// ```
///
/// The critical bit (C) is the MSB of the first octet. The 15-bit record
/// type and 16-bit body length are in network byte order.
async fn write_record<W>(writer: &mut W, critical: bool, type_id: u16, body: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let body_len = u16::try_from(body.len())
        .map_err(|_| Error::Protocol("NTS-KE record body exceeds 65535 bytes".to_string()))?;
    let type_bytes = type_id.to_be_bytes();
    let len_bytes = body_len.to_be_bytes();
    let critical_bit: u8 = if critical { 0x80 } else { 0x00 };

    let header = [
        critical_bit | (type_bytes[0] & 0x7F),
        type_bytes[1],
        len_bytes[0],
        len_bytes[1],
    ];
    writer.write_all(&header).await.map_err(Error::Io)?;
    writer.write_all(body).await.map_err(Error::Io)?;
    Ok(())
}

/// Read a single NTS-KE record from an async reader.
///
/// Returns `(critical, type_id, body)`. See [`write_record`] for the wire format.
async fn read_record<R>(reader: &mut R) -> Result<(bool, u16, Vec<u8>)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await.map_err(Error::Io)?;

    let critical = (header[0] & 0x80) != 0;
    let type_id = u16::from_be_bytes([header[0] & 0x7F, header[1]]);
    let body_len = u16::from_be_bytes([header[2], header[3]]) as usize;

    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await.map_err(Error::Io)?;

    Ok((critical, type_id, body))
}

#[cfg(test)]
mod record_tests {
    use super::{read_record, write_record};
    use std::io::Cursor;

    #[tokio::test]
    async fn test_end_of_message_roundtrip() {
        let mut buf = Vec::new();
        write_record(&mut buf, true, 0, &[]).await.unwrap();
        // Critical flag set, type 0, length 0 → [0x80, 0x00, 0x00, 0x00]
        assert_eq!(buf, [0x80, 0x00, 0x00, 0x00]);
        let mut cursor = Cursor::new(buf.as_slice());
        let (critical, type_id, body) = read_record(&mut cursor).await.unwrap();
        assert!(critical);
        assert_eq!(type_id, 0);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_cookie_record_roundtrip() {
        let cookie = b"hello_cookie_bytes";
        let mut buf = Vec::new();
        write_record(&mut buf, false, 5, cookie).await.unwrap();
        let mut cursor = Cursor::new(buf.as_slice());
        let (critical, type_id, body) = read_record(&mut cursor).await.unwrap();
        assert!(!critical);
        assert_eq!(type_id, 5);
        assert_eq!(body, cookie);
    }

    #[tokio::test]
    async fn test_aead_algorithm_record_roundtrip() {
        // Type 4, body = algorithm ID 15 as big-endian u16
        let body = 15u16.to_be_bytes();
        let mut buf = Vec::new();
        write_record(&mut buf, true, 4, &body).await.unwrap();
        let mut cursor = Cursor::new(buf.as_slice());
        let (critical, type_id, record_body) = read_record(&mut cursor).await.unwrap();
        assert!(critical);
        assert_eq!(type_id, 4);
        assert_eq!(record_body, body);
    }

    #[tokio::test]
    async fn test_critical_flag_encoding() {
        let mut buf = Vec::new();
        write_record(&mut buf, true, 0x1234, &[]).await.unwrap();
        // Critical bit set: first byte = 0x80 | (0x12 & 0x7F) = 0x80 | 0x12 = 0x92
        assert_eq!(buf[0], 0x92);
        assert_eq!(buf[1], 0x34);
    }
}
