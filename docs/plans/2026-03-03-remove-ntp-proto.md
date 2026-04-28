# Remove `ntp-proto` Dependency Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate the `ntp-proto` crate and its `__internal-test` unstable feature flag by implementing NTS-KE and NTP packet handling directly.

**Architecture:** Approach A (incremental, file-by-file). A new `src/cipher.rs` module provides the `AeadCipher` abstraction. `src/nts_ke.rs` is rewritten to use `tokio-rustls` for async NTS-KE with direct RFC 8915 §4 record I/O. `src/nts_ntp.rs` is rewritten to build and parse NTP packets from raw bytes. The crate compiles cleanly at the end of each file change; `ntp-proto` is removed from `Cargo.toml` only after all files are migrated.

**Tech Stack:** `aes-siv 0.7` (`siv::Aes128Siv`, `siv::Aes256Siv`), `tokio-rustls 0.26`, `rustls 0.23`, `rustls-native-certs 0.8`, `webpki-roots 1.0`, `rand 0.8`.

**Design doc:** `docs/plans/2026-03-03-remove-ntp-proto-design.md`

---

## Task 1: Add new dependencies to Cargo.toml

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add `aes-siv` and `rand` as direct dependencies**

In `Cargo.toml`, add under `[dependencies]` (keep `ntp-proto` for now — it will be removed in Task 12):

```toml
aes-siv = "0.7"
rand = "0.8"
```

Also remove the comment block above `ntp-proto` that starts with `# Note: Using __internal-test feature temporarily...` — we are about to make it obsolete. Leave the `ntp-proto` line itself for now.

**Step 2: Verify the crate still compiles**

```bash
cargo check
```

Expected: no errors.

**Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore(deps): add aes-siv and rand as direct dependencies"
```

---

## Task 2: Create `src/cipher.rs`

This module provides the `AeadCipher` enum used internally by `nts_ke.rs` and `nts_ntp.rs`. It wraps `aes_siv::siv::Aes128Siv` (32-byte key, AEAD_AES_SIV_CMAC_256) and `aes_siv::siv::Aes256Siv` (64-byte key, AEAD_AES_SIV_CMAC_512).

**Files:**
- Create: `src/cipher.rs`

**Step 1: Write the failing tests**

Write the full test module at the bottom of `src/cipher.rs` first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmac256_roundtrip() {
        let key = [0u8; 32];
        let cipher = AeadCipher::from_key_bytes(15, &key).unwrap();
        let ad0 = b"ntp header bytes";
        let ad1 = b"nonce";
        let plaintext = b"cookie payload";
        let ct = cipher.encrypt_siv(&[ad0, ad1], plaintext).unwrap();
        let pt = cipher.decrypt_siv(&[ad0, ad1], &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_cmac512_roundtrip() {
        let key = [0u8; 64];
        let cipher = AeadCipher::from_key_bytes(17, &key).unwrap();
        let ad0 = b"header";
        let ad1 = b"nonce16byteshere";
        let plaintext = b"another cookie";
        let ct = cipher.encrypt_siv(&[ad0, ad1], plaintext).unwrap();
        let pt = cipher.decrypt_siv(&[ad0, ad1], &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_auth_only_empty_plaintext() {
        // Client NTP requests encrypt empty plaintext — result is only the 16-byte SIV tag.
        let key = [1u8; 32];
        let cipher = AeadCipher::from_key_bytes(15, &key).unwrap();
        let ct = cipher.encrypt_siv(&[b"aad"], &[]).unwrap();
        assert_eq!(ct.len(), 16, "SIV tag must be exactly 16 bytes for empty plaintext");
        let pt = cipher.decrypt_siv(&[b"aad"], &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_tampered_ciphertext_is_rejected() {
        let key = [2u8; 32];
        let cipher = AeadCipher::from_key_bytes(15, &key).unwrap();
        let mut ct = cipher.encrypt_siv(&[b"aad"], b"secret").unwrap();
        ct[0] ^= 0xff;
        assert!(cipher.decrypt_siv(&[b"aad"], &ct).is_err());
    }

    #[test]
    fn test_wrong_aad_is_rejected() {
        let key = [3u8; 32];
        let cipher = AeadCipher::from_key_bytes(15, &key).unwrap();
        let ct = cipher.encrypt_siv(&[b"correct"], b"data").unwrap();
        assert!(cipher.decrypt_siv(&[b"wrong"], &ct).is_err());
    }

    #[test]
    fn test_invalid_key_length_is_error() {
        // alg 15 expects 32-byte key
        assert!(AeadCipher::from_key_bytes(15, &[0u8; 16]).is_err());
        // alg 17 expects 64-byte key
        assert!(AeadCipher::from_key_bytes(17, &[0u8; 32]).is_err());
    }

    #[test]
    fn test_unknown_algorithm_is_error() {
        assert!(AeadCipher::from_key_bytes(0, &[0u8; 32]).is_err());
        assert!(AeadCipher::from_key_bytes(99, &[0u8; 32]).is_err());
    }

    #[test]
    fn test_key_len() {
        assert_eq!(AeadCipher::key_len(15), Some(32));
        assert_eq!(AeadCipher::key_len(17), Some(64));
        assert_eq!(AeadCipher::key_len(0), None);
    }
}
```

**Step 2: Run the tests — they must fail to compile (module doesn't exist yet)**

```bash
cargo test --lib cipher
```

Expected: compile error — `src/cipher.rs` doesn't exist yet.

**Step 3: Implement `src/cipher.rs`**

```rust
//! AEAD cipher abstraction for NTS-protected NTP.
//!
//! Provides [`AeadCipher`], an internal enum that wraps AES-SIV-CMAC-256 and
//! AES-SIV-CMAC-512 as defined in RFC 5297 and required by RFC 8915.

use aes_siv::{KeyInit, siv::Aes128Siv, siv::Aes256Siv};

use crate::error::{Error, Result};

/// AEAD algorithm IDs as defined in RFC 8915 §7.1.
pub(crate) const AEAD_AES_SIV_CMAC_256: u16 = 15;
pub(crate) const AEAD_AES_SIV_CMAC_512: u16 = 17;

/// AES-SIV-CMAC cipher for NTS authenticated encryption.
///
/// Supports AEAD_AES_SIV_CMAC_256 (32-byte key) and AEAD_AES_SIV_CMAC_512
/// (64-byte key) as specified in RFC 8915 §4 and RFC 5297.
///
/// Both `encrypt_siv` and `decrypt_siv` accept multiple associated-data
/// components (`ad: &[&[u8]]`), which map directly to the multi-component
/// S2V function defined in RFC 5297 §2.4.
#[derive(Debug)]
pub(crate) enum AeadCipher {
    /// AEAD_AES_SIV_CMAC_256 — AES-SIV with a 32-byte key.
    SivCmac256(Box<[u8; 32]>),
    /// AEAD_AES_SIV_CMAC_512 — AES-SIV with a 64-byte key.
    SivCmac512(Box<[u8; 64]>),
}

impl AeadCipher {
    /// Construct an [`AeadCipher`] from a raw key slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyExchange`] if `alg_id` is unsupported or `key`
    /// does not have the correct length for the algorithm.
    pub(crate) fn from_key_bytes(alg_id: u16, key: &[u8]) -> Result<Self> {
        match alg_id {
            AEAD_AES_SIV_CMAC_256 => {
                let bytes: [u8; 32] = key.try_into().map_err(|_| {
                    Error::KeyExchange(format!(
                        "AEAD_AES_SIV_CMAC_256 requires a 32-byte key, got {} bytes",
                        key.len()
                    ))
                })?;
                Ok(AeadCipher::SivCmac256(Box::new(bytes)))
            }
            AEAD_AES_SIV_CMAC_512 => {
                let bytes: [u8; 64] = key.try_into().map_err(|_| {
                    Error::KeyExchange(format!(
                        "AEAD_AES_SIV_CMAC_512 requires a 64-byte key, got {} bytes",
                        key.len()
                    ))
                })?;
                Ok(AeadCipher::SivCmac512(Box::new(bytes)))
            }
            _ => Err(Error::KeyExchange(format!(
                "Unsupported AEAD algorithm ID: {}",
                alg_id
            ))),
        }
    }

    /// Returns the required key length in bytes for the given algorithm ID,
    /// or `None` if the algorithm is not supported.
    pub(crate) fn key_len(alg_id: u16) -> Option<usize> {
        match alg_id {
            AEAD_AES_SIV_CMAC_256 => Some(32),
            AEAD_AES_SIV_CMAC_512 => Some(64),
            _ => None,
        }
    }

    /// Encrypt `plaintext` with the provided associated-data components.
    ///
    /// Returns the SIV tag prepended to the encrypted ciphertext. For an
    /// empty plaintext the return value is exactly 16 bytes (the SIV tag
    /// only), which is the format used for client NTP requests.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AeadVerificationFailed`] if the underlying AES-SIV
    /// operation fails (should not occur for well-formed inputs).
    pub(crate) fn encrypt_siv(&self, ad: &[&[u8]], plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            AeadCipher::SivCmac256(key) => {
                let mut siv = Aes128Siv::new_from_slice(key.as_ref())
                    .map_err(|_| Error::KeyExchange("Invalid AES-SIV-256 key".to_string()))?;
                siv.encrypt(ad, plaintext)
                    .map_err(|_| Error::AeadVerificationFailed("AES-SIV-256 encrypt failed".to_string()))
            }
            AeadCipher::SivCmac512(key) => {
                let mut siv = Aes256Siv::new_from_slice(key.as_ref())
                    .map_err(|_| Error::KeyExchange("Invalid AES-SIV-512 key".to_string()))?;
                siv.encrypt(ad, plaintext)
                    .map_err(|_| Error::AeadVerificationFailed("AES-SIV-512 encrypt failed".to_string()))
            }
        }
    }

    /// Decrypt and authenticate `ciphertext` with the provided
    /// associated-data components.
    ///
    /// The `ciphertext` must be the value returned by [`encrypt_siv`]:
    /// a 16-byte SIV tag followed by the encrypted payload.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AeadVerificationFailed`] if authentication fails,
    /// indicating that the data has been tampered with or the wrong key
    /// or associated data was used.
    pub(crate) fn decrypt_siv(&self, ad: &[&[u8]], ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            AeadCipher::SivCmac256(key) => {
                let mut siv = Aes128Siv::new_from_slice(key.as_ref())
                    .map_err(|_| Error::KeyExchange("Invalid AES-SIV-256 key".to_string()))?;
                siv.decrypt(ad, ciphertext)
                    .map_err(|_| Error::AeadVerificationFailed("AES-SIV-256 authentication failed".to_string()))
            }
            AeadCipher::SivCmac512(key) => {
                let mut siv = Aes256Siv::new_from_slice(key.as_ref())
                    .map_err(|_| Error::KeyExchange("Invalid AES-SIV-512 key".to_string()))?;
                siv.decrypt(ad, ciphertext)
                    .map_err(|_| Error::AeadVerificationFailed("AES-SIV-512 authentication failed".to_string()))
            }
        }
    }
}
```

**Step 4: Register the module in `src/lib.rs`**

Add `mod cipher;` after the existing `mod` declarations (keep it `mod`, not `pub mod` — it is internal):

```rust
mod cipher;
```

**Step 5: Run tests — they must pass**

```bash
cargo test --lib cipher
```

Expected: all 8 tests pass.

**Step 6: Commit**

```bash
git add src/cipher.rs src/lib.rs
git commit -m "feat: add AeadCipher abstraction (AES-SIV-CMAC-256/512)"
```

---

## Task 3: Rewrite `src/nts_ke.rs` — NTS-KE record I/O helpers

These are the low-level async helpers that read and write NTS-KE records
(RFC 8915 §4.1). Tested in isolation before wiring up the full handshake.

**Files:**
- Modify: `src/nts_ke.rs` (add helpers to bottom; rest of file unchanged for now)

**NTS-KE record wire format (RFC 8915 §4.1):**
```
 Bit 0    : Critical flag (1 = unknown record is fatal to the exchange)
 Bits 1-15: Record type (15-bit unsigned big-endian)
 Bits 16-31: Body length (16-bit unsigned big-endian)
 Bytes 4+  : Body (variable length)
```

**Step 1: Write failing tests**

Add to the bottom of `src/nts_ke.rs`:

```rust
#[cfg(test)]
mod record_tests {
    use super::{read_record, write_record};
    use std::io::Cursor;

    #[tokio::test]
    async fn test_end_of_message_roundtrip() {
        let mut buf = Vec::new();
        write_record(&mut buf, true, 0, &[]).await.unwrap();
        // header: [0x80, 0x00, 0x00, 0x00]
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
```

**Step 2: Run to confirm they fail**

```bash
cargo test --lib record_tests
```

Expected: compile error — `read_record` and `write_record` not found.

**Step 3: Add the helpers to `src/nts_ke.rs`**

Insert before the `#[cfg(test)]` block (or at the end of the file before it):

```rust
/// Write a single NTS-KE record to an async writer.
///
/// The record wire format is: `[C|type_high_7][type_low_8][len_high_8][len_low_8][body...]`
/// where `C` is the critical flag (bit 7 of the first byte).
async fn write_record<W>(writer: &mut W, critical: bool, type_id: u16, body: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let type_bytes = type_id.to_be_bytes();
    let len_bytes = (body.len() as u16).to_be_bytes();
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
/// Returns `(critical, type_id, body)`.
async fn read_record<R>(reader: &mut R) -> Result<(bool, u16, Vec<u8>)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .await
        .map_err(Error::Io)?;

    let critical = (header[0] & 0x80) != 0;
    let type_id = u16::from_be_bytes([header[0] & 0x7F, header[1]]);
    let body_len = u16::from_be_bytes([header[2], header[3]]) as usize;

    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await.map_err(Error::Io)?;

    Ok((critical, type_id, body))
}
```

**Step 4: Run the tests — they must pass**

```bash
cargo test --lib record_tests
```

Expected: 4 tests pass.

**Step 5: Verify the full crate still compiles**

```bash
cargo check
```

Expected: no errors.

**Step 6: Commit**

```bash
git add src/nts_ke.rs
git commit -m "feat(nts-ke): add async NTS-KE record read/write helpers (RFC 8915 §4.1)"
```

---

## Task 4: Rewrite `src/nts_ke.rs` — TLS config builder

Replace `build_tls_config` (which uses `ntp_proto::tls_utils`) with a direct `rustls` implementation. The `CapturingVerifier` struct and all TLS certificate-capture logic are **kept exactly as-is** — only the verifier construction changes.

**Files:**
- Modify: `src/nts_ke.rs`

**Step 1: Replace the `build_tls_config` function**

The new function builds a `rustls::ClientConfig` directly. It must:
1. Load system CAs via `rustls_native_certs`
2. Merge `webpki_roots` as a fallback
3. Build a `WebPkiServerVerifier` (or `NoVerification` verifier)
4. Wrap with the existing `CapturingVerifier`
5. Set ALPN to `"ntske/1"` — **this is critical and was previously set internally by `KeyExchangeClient`**

Find and **replace** the existing `build_tls_config` function and its `use ntp_proto::tls_utils::{self};` line with:

```rust
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

    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
        if config.verify_tls_cert {
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
/// Returns `None` if the variable is unset.
fn make_key_log() -> Option<Arc<dyn rustls::KeyLog>> {
    std::env::var("SSLKEYLOGFILE")
        .ok()
        .and_then(|path| {
            debug!("Enabling TLS key log: {path}");
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .ok()
        })
        .map(|file| Arc::new(KeyLogFile(Mutex::new(file))) as Arc<dyn rustls::KeyLog>)
}
```

Also update the imports at the top of `src/nts_ke.rs`. **Remove** the `ntp_proto` import line for `tls_utils` and adjust remaining imports:

Remove:
```rust
use ntp_proto::{KeyExchangeClient, KeyExchangeError, KeyExchangeResult, ProtocolVersion};
```
and:
```rust
use ntp_proto::tls_utils::{self};
```

Add (only if not already present):
```rust
use rustls_native_certs;
```

**Step 2: Verify compilation**

```bash
cargo check
```

Expected: no errors. The `perform_nts_ke_blocking` function and `convert_ke_result` still reference `ntp-proto` types — that is expected at this stage; they will be replaced in Task 5.

**Step 3: Commit**

```bash
git add src/nts_ke.rs
git commit -m "refactor(nts-ke): replace ntp-proto TLS config builder with direct rustls"
```

---

## Task 5: Rewrite `src/nts_ke.rs` — complete async NTS-KE handshake

Replace `perform_nts_ke_blocking`, `perform_nts_ke`, and `convert_ke_result` with a
single clean async function. The `CapturingVerifier`, `NoVerification`, `KeyLogFile`,
and `extract_certificate_info` helpers are **unchanged** — keep them verbatim.

**Files:**
- Modify: `src/nts_ke.rs`

**Step 1: Replace the handshake logic**

Delete `perform_nts_ke_blocking`, the `use ntp_proto::{...}` import, and `convert_ke_result`. Delete the `From<KeyExchangeError>` impl block. Replace `perform_nts_ke` with:

```rust
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

    let server_addr = resolve_server(&config.nts_ke_server, config.nts_ke_port).await?;
    debug!("Resolved NTS-KE server: {server_addr}");

    let (tls_config, captured_certs) = build_tls_config(config)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let tcp_stream = tokio::time::timeout(
        config.timeout,
        tokio::net::TcpStream::connect(server_addr),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(Error::Io)?;

    let server_name = rustls::pki_types::ServerName::try_from(config.nts_ke_server.as_str())
        .map_err(|e| Error::Tls(format!("Invalid server name '{}': {e}", config.nts_ke_server)))?
        .to_owned();

    let mut tls_stream = tokio::time::timeout(config.timeout, connector.connect(server_name, tcp_stream))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Tls(format!("TLS handshake failed: {e}")))?;

    debug!("TLS handshake complete");

    // Send End of Message record (critical, type 0, empty body).
    write_record(&mut tls_stream, true, 0, &[]).await?;
    {
        use tokio::io::AsyncWriteExt;
        tls_stream.flush().await.map_err(Error::Io)?;
    }

    // Read server records until End of Message.
    let mut aead_alg: Option<u16> = None;
    let mut cookies: Vec<Vec<u8>> = Vec::new();
    let mut ntp_server: Option<String> = None;
    let mut ntp_port: Option<u16> = None;

    loop {
        let (critical, type_id, body) = read_record(&mut tls_stream).await?;

        match type_id {
            // End of Message
            0 => {
                debug!("Received NTS-KE End of Message");
                break;
            }
            // AEAD Algorithm Negotiation
            4 => {
                if body.len() == 2 {
                    let alg = u16::from_be_bytes([body[0], body[1]]);
                    if AeadCipher::key_len(alg).is_some() {
                        aead_alg = Some(alg);
                        debug!("Negotiated AEAD algorithm: {alg}");
                    } else {
                        debug!("Skipping unsupported AEAD algorithm: {alg}");
                    }
                }
            }
            // New Cookie for NTPv4
            5 => {
                debug!("Received cookie ({} bytes)", body.len());
                cookies.push(body);
            }
            // NTPv4 Server Negotiation
            6 => {
                if let Ok(name) = String::from_utf8(body) {
                    debug!("NTS-KE negotiated NTP server: {name}");
                    ntp_server = Some(name);
                }
            }
            // NTPv4 Port Negotiation
            7 => {
                if body.len() == 2 {
                    let port = u16::from_be_bytes([body[0], body[1]]);
                    debug!("NTS-KE negotiated NTP port: {port}");
                    ntp_port = Some(port);
                }
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

    // Validate the exchange result.
    let alg_id = aead_alg.ok_or_else(|| {
        Error::KeyExchange("Server did not negotiate an AEAD algorithm".to_string())
    })?;
    if cookies.is_empty() {
        return Err(Error::KeyExchange(
            "Server did not provide any NTS cookies".to_string(),
        ));
    }

    // Derive c2s and s2c keys via TLS keying material export (RFC 5705 /
    // RFC 8446 §7.5, label "EXPORTER-network-time-security").
    //
    // Context: [alg_id_hi, alg_id_lo, direction]
    //   direction 0x00 = client-to-server
    //   direction 0x01 = server-to-client
    let key_len = AeadCipher::key_len(alg_id).unwrap(); // validated above
    let alg_bytes = alg_id.to_be_bytes();
    let mut c2s_key = vec![0u8; key_len];
    let mut s2c_key = vec![0u8; key_len];

    {
        let (_, tls_conn) = tls_stream.get_ref();
        tls_conn
            .export_keying_material(
                &mut c2s_key,
                b"EXPORTER-network-time-security",
                Some(&[alg_bytes[0], alg_bytes[1], 0x00]),
            )
            .map_err(|e| Error::Tls(format!("TLS key export failed: {e}")))?;
        tls_conn
            .export_keying_material(
                &mut s2c_key,
                b"EXPORTER-network-time-security",
                Some(&[alg_bytes[0], alg_bytes[1], 0x01]),
            )
            .map_err(|e| Error::Tls(format!("TLS key export failed: {e}")))?;
    }

    let c2s = AeadCipher::from_key_bytes(alg_id, &c2s_key)?;
    let s2c = AeadCipher::from_key_bytes(alg_id, &s2c_key)?;

    let ke_duration = ke_start.elapsed();
    debug!("NTS-KE completed in {ke_duration:?}");

    // Extract certificate information captured during the TLS handshake.
    let certificate = {
        let certs = captured_certs.lock().unwrap();
        if certs.is_empty() {
            None
        } else {
            extract_certificate_info(&certs)
        }
    };

    // Determine the NTP server and port to use.
    let ntp_host = ntp_server.unwrap_or_else(|| config.nts_ke_server.clone());
    let ntp_port = ntp_port.unwrap_or(123);
    let ntp_server_addr = resolve_server(&ntp_host, ntp_port).await?;

    let aead_algorithm = match alg_id {
        AEAD_AES_SIV_CMAC_256 => "AEAD_AES_SIV_CMAC_256".to_string(),
        AEAD_AES_SIV_CMAC_512 => "AEAD_AES_SIV_CMAC_512".to_string(),
        _ => format!("UNKNOWN_{alg_id}"),
    };

    info!(
        "NTS-KE successful. NTP server: {ntp_server_addr}, algorithm: {aead_algorithm}, cookies: {}",
        cookies.len()
    );

    Ok(NtsKeResult::new(
        ntp_server_addr,
        aead_algorithm,
        cookies,
        ke_duration,
        c2s,
        s2c,
        certificate,
    ))
}
```

**Step 2: Update the imports at the top of `src/nts_ke.rs`**

Replace all existing `use` statements with:

```rust
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName as RustlsServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use x509_parser::prelude::*;

use crate::cipher::{AeadCipher, AEAD_AES_SIV_CMAC_256, AEAD_AES_SIV_CMAC_512};
use crate::config::NtsClientConfig;
use crate::error::{Error, Result};
use crate::types::{CertificateInfo, NtsKeResult};
```

**Step 3: Verify compilation**

```bash
cargo check
```

Expected: no errors. At this point `src/nts_ke.rs` no longer imports `ntp-proto` at all.

**Step 4: Commit**

```bash
git add src/nts_ke.rs
git commit -m "feat(nts-ke): rewrite as direct async RFC 8915 implementation, remove ntp-proto"
```

---

## Task 6: Rewrite `src/nts_ntp.rs` — NTP header helpers and types

Replace the `ntp_proto` types used for time, leap indicator, and packet header access with pure byte-level operations. Tests first.

**Files:**
- Modify: `src/nts_ntp.rs`

**Step 1: Write failing tests**

Add at the bottom of the existing `#[cfg(test)]` block in `src/nts_ntp.rs` (or create a new one):

```rust
#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn test_ntp_header_first_byte() {
        // LI=0 (no warning), VN=4, Mode=3 (client) → 0b00_100_011 = 0x23
        let header = build_ntp_header(6, &[0u8; 8]);
        assert_eq!(header[0], 0x23);
    }

    #[test]
    fn test_ntp_header_poll_and_precision() {
        let header = build_ntp_header(6, &[0u8; 8]);
        assert_eq!(header[2], 6); // poll exponent
        assert_eq!(header[3], (-20i8) as u8); // precision
    }

    #[test]
    fn test_ntp_header_transmit_timestamp() {
        let ts = [1, 2, 3, 4, 5, 6, 7, 8];
        let header = build_ntp_header(6, &ts);
        assert_eq!(&header[40..48], &ts);
    }

    #[test]
    fn test_kiss_code_ntsn() {
        let mut pkt = [0u8; 48];
        pkt[1] = 0; // stratum 0
        pkt[12..16].copy_from_slice(b"NTSN");
        assert!(is_kiss_ntsn(&pkt));
        assert!(!is_kiss_deny(&pkt));
        assert!(!is_kiss_rate(&pkt));
    }

    #[test]
    fn test_kiss_code_deny() {
        let mut pkt = [0u8; 48];
        pkt[1] = 0;
        pkt[12..16].copy_from_slice(b"DENY");
        assert!(is_kiss_deny(&pkt));
    }

    #[test]
    fn test_kiss_code_rate() {
        let mut pkt = [0u8; 48];
        pkt[1] = 0;
        pkt[12..16].copy_from_slice(b"RATE");
        assert!(is_kiss_rate(&pkt));
    }

    #[test]
    fn test_not_kiss_when_stratum_nonzero() {
        let mut pkt = [0u8; 48];
        pkt[1] = 2; // stratum 2 → not a kiss packet
        pkt[12..16].copy_from_slice(b"NTSN");
        assert!(!is_kiss_ntsn(&pkt));
    }

    #[test]
    fn test_ntp_timestamp_unix_epoch() {
        // NTP seconds for Unix epoch = 2_208_988_800, fraction = 0 → SystemTime = UNIX_EPOCH
        const OFFSET: u32 = 2_208_988_800;
        let mut ts = [0u8; 8];
        ts[..4].copy_from_slice(&OFFSET.to_be_bytes());
        let st = ntp_bytes_to_system_time(&ts);
        assert_eq!(
            st.duration_since(std::time::UNIX_EPOCH).unwrap(),
            Duration::ZERO
        );
    }

    #[test]
    fn test_ntp_timestamp_10_seconds_after_epoch() {
        const OFFSET: u32 = 2_208_988_800;
        let mut ts = [0u8; 8];
        ts[..4].copy_from_slice(&(OFFSET + 10).to_be_bytes());
        let st = ntp_bytes_to_system_time(&ts);
        assert_eq!(
            st.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            10
        );
    }

    #[test]
    fn test_leap_indicator_from_byte() {
        assert_eq!(NtpLeapIndicator::from(0x00u8), NtpLeapIndicator::NoWarning);
        assert_eq!(NtpLeapIndicator::from(0x40u8), NtpLeapIndicator::LastMinute61);
        assert_eq!(NtpLeapIndicator::from(0x80u8), NtpLeapIndicator::LastMinute59);
        assert_eq!(NtpLeapIndicator::from(0xC0u8), NtpLeapIndicator::Unknown);
    }
}
```

**Step 2: Run to confirm they fail**

```bash
cargo test --lib header_tests
```

Expected: compile errors — functions not yet defined.

**Step 3: Add the helper functions and `NtpLeapIndicator` to `src/nts_ntp.rs`**

Replace the existing `ntp_timestamp_to_system_time` function and add the new helpers and type. Also remove the import `use ntp_proto::{..., NtpLeapIndicator, NtpTimestamp, ...}` from these items specifically (leave the rest of the `ntp_proto` import line for now — it will be removed in Task 8 when the full file is rewritten):

```rust
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

/// NTP poll exponent used in outgoing client requests.
///
/// This is log₂(poll interval in seconds). A value of 6 gives a 64-second
/// poll interval, which is the default for a one-shot NTS client.
const NTP_POLL_EXPONENT: u8 = 6;

/// The NTP epoch starts 70 years before the Unix epoch (1900 vs 1970).
const NTP_UNIX_OFFSET_SECS: u32 = 2_208_988_800;

/// Build a 48-byte NTP client request header.
///
/// Sets LI=0, VN=4, Mode=3 (client), the given poll exponent, precision −20,
/// and places `transmit_ts` at bytes 40–47 for origin-timestamp matching on
/// the response. All other fields are zero.
fn build_ntp_header(poll_exponent: u8, transmit_ts: &[u8; 8]) -> [u8; 48] {
    let mut header = [0u8; 48];
    // LI=0b00, VN=0b100 (4), Mode=0b011 (client) → 0b00_100_011 = 0x23
    header[0] = 0x23;
    header[2] = poll_exponent;
    header[3] = (-20i8) as u8;
    header[40..48].copy_from_slice(transmit_ts);
    header
}

/// Return `true` if `packet` is a kiss-o'-death NTSN packet.
///
/// NTSN (NTS Not Applicable) indicates that the server requires a fresh
/// NTS-KE handshake before accepting authenticated NTP queries.
fn is_kiss_ntsn(packet: &[u8]) -> bool {
    packet.len() >= 16 && packet[1] == 0 && &packet[12..16] == b"NTSN"
}

/// Return `true` if `packet` is a kiss-o'-death DENY packet.
fn is_kiss_deny(packet: &[u8]) -> bool {
    packet.len() >= 16 && packet[1] == 0 && &packet[12..16] == b"DENY"
}

/// Return `true` if `packet` is a kiss-o'-death RATE packet.
fn is_kiss_rate(packet: &[u8]) -> bool {
    packet.len() >= 16 && packet[1] == 0 && &packet[12..16] == b"RATE"
}

/// Convert an 8-byte NTP timestamp (big-endian seconds + fraction) to a
/// [`SystemTime`].
///
/// NTP timestamps count seconds since 1900-01-01 00:00:00 UTC. The fractional
/// part is a 32-bit fixed-point fraction of a second.
fn ntp_bytes_to_system_time(ts: &[u8; 8]) -> SystemTime {
    let secs = u32::from_be_bytes([ts[0], ts[1], ts[2], ts[3]]);
    let frac = u32::from_be_bytes([ts[4], ts[5], ts[6], ts[7]]);

    // Convert NTP seconds to Unix seconds (signed to handle pre-epoch edge cases).
    let unix_secs = (secs as i64) - (NTP_UNIX_OFFSET_SECS as i64);

    // Convert the 32-bit fixed-point fraction to nanoseconds.
    let nanos = ((frac as u64) * 1_000_000_000) >> 32;

    if unix_secs >= 0 {
        UNIX_EPOCH
            + Duration::from_secs(unix_secs as u64)
            + Duration::from_nanos(nanos)
    } else {
        let abs = (-unix_secs) as u64;
        UNIX_EPOCH - Duration::from_secs(abs)
    }
}
```

Also update the `NtsResponse` struct to use the new `NtpLeapIndicator`:

Find:
```rust
    pub leap: ntp_proto::NtpLeapIndicator,
```
Replace with:
```rust
    pub leap: NtpLeapIndicator,
```

And in the test that creates `NtsResponse` directly, replace `ntp_proto::NtpLeapIndicator::NoWarning` with `NtpLeapIndicator::NoWarning`.

**Step 4: Run the tests**

```bash
cargo test --lib header_tests
cargo test --lib
```

Expected: `header_tests` all pass; the rest of the existing tests also pass.

**Step 5: Verify compilation**

```bash
cargo check
```

Expected: no errors.

**Step 6: Commit**

```bash
git add src/nts_ntp.rs
git commit -m "feat(nts-ntp): add NtpLeapIndicator, header builder, timestamp converter (RFC 5905)"
```

---

## Task 7: Rewrite `src/nts_ntp.rs` — NTS request builder

Replace `NtpPacket::nts_poll_message` and `packet.serialize` with direct byte construction and AES-SIV encryption. Tests first.

**Files:**
- Modify: `src/nts_ntp.rs`

**Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod request_tests {
    use super::*;
    use crate::cipher::AeadCipher;

    fn make_cipher() -> AeadCipher {
        AeadCipher::from_key_bytes(15, &[0u8; 32]).unwrap()
    }

    #[test]
    fn test_build_nts_request_length() {
        // Minimal: header(48) + unique_id_ef(4+32=36) + cookie_ef(4+N) +
        // authenticator_ef(4+2+16+2+16=40). With an 8-byte cookie and no
        // placeholders the total is 48+36+12+40 = 136 bytes.
        let cookie = vec![0xABu8; 8];
        let cipher = make_cipher();
        let pkt = build_nts_request(&cookie, 0, &cipher).unwrap();
        // Just check it's plausibly sized and well-formed.
        assert!(pkt.len() >= 48 + 36 + 8 + 40);
        // First byte: LI=0, VN=4, Mode=3 = 0x23
        assert_eq!(pkt[0], 0x23);
    }

    #[test]
    fn test_unique_id_ef_is_present() {
        let cookie = vec![0u8; 16];
        let cipher = make_cipher();
        let pkt = build_nts_request(&cookie, 0, &cipher).unwrap();
        // Unique ID EF type = 0x0104 at offset 48
        assert_eq!(u16::from_be_bytes([pkt[48], pkt[49]]), 0x0104);
    }

    #[test]
    fn test_cookie_ef_is_present() {
        let cookie = vec![0xFFu8; 16];
        let cipher = make_cipher();
        let pkt = build_nts_request(&cookie, 0, &cipher).unwrap();
        // After the unique ID EF (type 0x0104, len 4+32=36), the cookie EF starts at 84.
        // Cookie EF type = 0x0204
        let cookie_ef_offset = 48 + 36; // header + unique_id_ef
        assert_eq!(
            u16::from_be_bytes([pkt[cookie_ef_offset], pkt[cookie_ef_offset + 1]]),
            0x0204
        );
    }

    #[test]
    fn test_authenticator_ef_type() {
        let cookie = vec![0u8; 16];
        let cipher = make_cipher();
        let pkt = build_nts_request(&cookie, 0, &cipher).unwrap();
        // The last extension field should be the NTS Authenticator (type 0x0404).
        // Find it: scan from offset 48 until we see type 0x0404.
        let mut found = false;
        let mut offset = 48;
        while offset + 4 <= pkt.len() {
            let t = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
            let l = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]) as usize;
            if t == 0x0404 {
                found = true;
                break;
            }
            offset += l.max(4);
        }
        assert!(found, "NTS Authenticator EF (0x0404) not found in request");
    }
}
```

**Step 2: Run — confirm compile error**

```bash
cargo test --lib request_tests
```

Expected: `build_nts_request` not found.

**Step 3: Add `build_nts_request` to `src/nts_ntp.rs`**

```rust
/// Serialise a complete NTS-protected NTP client request.
///
/// The packet layout is (RFC 8915 §5):
///
/// 1. 48-byte NTP header (LI=0, VN=4, Mode=3)
/// 2. Unique Identifier EF (type 0x0104, 32 random bytes)
/// 3. NTS Cookie EF (type 0x0204, the consumed cookie)
/// 4. NTS Cookie Placeholder EF × `extra_cookies` (type 0x0304)
/// 5. NTS Authenticator EF (type 0x0404, nonce + AES-SIV tag)
///
/// The AES-SIV encryption uses two associated-data components:
///   - S₁ = NTP header (bytes 0–47) ‖ all preceding EFs
///   - S₂ = the 16-byte nonce
///
/// The plaintext is empty for client requests; the SIV output is therefore
/// exactly 16 bytes (the authentication tag only).
fn build_nts_request(
    cookie: &[u8],
    extra_cookies: u8,
    c2s: &AeadCipher,
) -> Result<Vec<u8>> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    // Generate a random 8-byte transmit timestamp used for origin matching.
    let mut transmit_ts = [0u8; 8];
    rng.fill_bytes(&mut transmit_ts);

    let header = build_ntp_header(NTP_POLL_EXPONENT, &transmit_ts);

    // -- Unique Identifier EF (type 0x0104) --
    // 32 random bytes provide anti-replay protection.
    let mut unique_id = [0u8; 32];
    rng.fill_bytes(&mut unique_id);
    let uid_ef = build_ef(0x0104, &unique_id);

    // -- NTS Cookie EF (type 0x0204) --
    let cookie_ef = build_ef(0x0204, cookie);

    // -- NTS Cookie Placeholder EFs (type 0x0304) --
    // Each placeholder has the same length as the cookie body, filled with zeros.
    let placeholder_body = vec![0u8; cookie.len()];
    let mut placeholder_efs = Vec::new();
    for _ in 0..extra_cookies {
        placeholder_efs.extend_from_slice(&build_ef(0x0304, &placeholder_body));
    }

    // -- NTS Authenticator EF (type 0x0404) --
    // Generate a 16-byte nonce.
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);

    // AD = NTP header ‖ all preceding EFs (RFC 8915 §5.7, two S inputs).
    let mut preceding: Vec<u8> = Vec::new();
    preceding.extend_from_slice(&header);
    preceding.extend_from_slice(&uid_ef);
    preceding.extend_from_slice(&cookie_ef);
    preceding.extend_from_slice(&placeholder_efs);

    // Encrypt empty plaintext — result is the 16-byte SIV authentication tag.
    let siv_tag = c2s.encrypt_siv(&[&preceding, &nonce], &[])?;

    // Authenticator EF body: nonce_len(2) | nonce(16) | ciphertext_len(2) | tag(16)
    let mut auth_body = Vec::with_capacity(2 + 16 + 2 + 16);
    auth_body.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    auth_body.extend_from_slice(&nonce);
    auth_body.extend_from_slice(&(siv_tag.len() as u16).to_be_bytes());
    auth_body.extend_from_slice(&siv_tag);
    let auth_ef = build_ef(0x0404, &auth_body);

    // Assemble the final packet.
    let mut packet = Vec::with_capacity(48 + uid_ef.len() + cookie_ef.len() + placeholder_efs.len() + auth_ef.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&uid_ef);
    packet.extend_from_slice(&cookie_ef);
    packet.extend_from_slice(&placeholder_efs);
    packet.extend_from_slice(&auth_ef);

    Ok(packet)
}

/// Serialise an NTP extension field: type(2) | length(2) | body.
///
/// The length field includes the 4-byte header. If the body is not already
/// 4-byte aligned it is padded with zeros.
fn build_ef(type_id: u16, body: &[u8]) -> Vec<u8> {
    let padded_body_len = (body.len() + 3) & !3; // round up to 4-byte boundary
    let total_len = 4 + padded_body_len;
    let mut ef = vec![0u8; total_len];
    ef[0..2].copy_from_slice(&type_id.to_be_bytes());
    ef[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    ef[4..4 + body.len()].copy_from_slice(body);
    ef
}
```

**Step 4: Run tests**

```bash
cargo test --lib request_tests
```

Expected: all pass.

**Step 5: Commit**

```bash
git add src/nts_ntp.rs
git commit -m "feat(nts-ntp): add NTS request builder (RFC 8915 §5)"
```

---

## Task 8: Rewrite `src/nts_ntp.rs` — response parsing/decryption and full NtsState

Replace `NtpPacket::deserialize` and all remaining `ntp_proto` usages in the file. Then replace `NtsState::create_request` and `NtsState::parse_response` to use the new helpers.

**Files:**
- Modify: `src/nts_ntp.rs`

**Step 1: Write failing tests for response decryption**

```rust
#[cfg(test)]
mod response_tests {
    use super::*;
    use crate::cipher::AeadCipher;

    /// Build a valid NTS-protected request and then verify the authenticator
    /// against the same key — this simulates what the server does.
    #[test]
    fn test_find_authenticator_ef() {
        let cookie = vec![0u8; 16];
        let c2s = AeadCipher::from_key_bytes(15, &[0u8; 32]).unwrap();
        let pkt = build_nts_request(&cookie, 0, &c2s).unwrap();
        let auth = find_authenticator_ef(&pkt).unwrap();
        assert!(auth.is_some(), "Authenticator EF must be present");
        let (offset, nonce, ciphertext) = auth.unwrap();
        assert!(offset >= 48, "Authenticator must be after NTP header");
        assert_eq!(nonce.len(), 16);
        assert_eq!(ciphertext.len(), 16, "Empty-plaintext tag is 16 bytes");
    }

    #[test]
    fn test_extract_new_cookies_from_plaintext() {
        // Build a fake decrypted payload containing two NTS Cookie EFs.
        let cookie1 = build_ef(0x0204, b"cookie_one");
        let cookie2 = build_ef(0x0204, b"cookie_two");
        let mut payload = Vec::new();
        payload.extend_from_slice(&cookie1);
        payload.extend_from_slice(&cookie2);
        let cookies = extract_new_cookies(&payload).unwrap();
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0], b"cookie_one");
        assert_eq!(cookies[1], b"cookie_two");
    }
}
```

**Step 2: Run to confirm they fail**

```bash
cargo test --lib response_tests
```

Expected: compile errors.

**Step 3: Add `find_authenticator_ef` and `extract_new_cookies`**

```rust
/// Locate the NTS Authenticator EF (type 0x0404) in a raw NTP packet.
///
/// Returns `Some((ef_offset, nonce, ciphertext))` where `ef_offset` is the
/// byte offset of the EF header within `data`. `ef_offset` is used to
/// determine the associated-data boundary for AES-SIV.
///
/// Returns `None` if no authenticator EF is present.
fn find_authenticator_ef(data: &[u8]) -> Result<Option<(usize, Vec<u8>, Vec<u8>)>> {
    if data.len() < NTP_HEADER_LEN {
        return Err(Error::MalformedNtsExtension("Packet too short for NTP header".to_string()));
    }
    let mut offset = NTP_HEADER_LEN;
    while offset + 4 <= data.len() {
        let type_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ef_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if ef_len < 4 || ef_len % 4 != 0 {
            return Err(Error::MalformedNtsExtension(format!(
                "Invalid extension field length {ef_len} at offset {offset}"
            )));
        }
        if offset + ef_len > data.len() {
            return Err(Error::MalformedNtsExtension(
                "Extension field overruns packet boundary".to_string(),
            ));
        }

        if type_id == 0x0404 {
            let body = &data[offset + 4..offset + ef_len];
            if body.len() < 4 {
                return Err(Error::MalformedNtsExtension(
                    "NTS Authenticator EF body is too short".to_string(),
                ));
            }
            let nonce_len = u16::from_be_bytes([body[0], body[1]]) as usize;
            if body.len() < 2 + nonce_len + 2 {
                return Err(Error::MalformedNtsExtension(
                    "NTS Authenticator EF: nonce overruns body".to_string(),
                ));
            }
            let nonce = body[2..2 + nonce_len].to_vec();
            let ct_start = 2 + nonce_len;
            let ct_len = u16::from_be_bytes([body[ct_start], body[ct_start + 1]]) as usize;
            if body.len() < ct_start + 2 + ct_len {
                return Err(Error::MalformedNtsExtension(
                    "NTS Authenticator EF: ciphertext overruns body".to_string(),
                ));
            }
            let ciphertext = body[ct_start + 2..ct_start + 2 + ct_len].to_vec();
            return Ok(Some((offset, nonce, ciphertext)));
        }

        offset += ef_len;
    }
    Ok(None)
}

/// Parse a decrypted NTS payload and collect any NTS Cookie EFs (type 0x0204).
fn extract_new_cookies(plaintext: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut cookies = Vec::new();
    let mut offset = 0;
    while offset + 4 <= plaintext.len() {
        let type_id = u16::from_be_bytes([plaintext[offset], plaintext[offset + 1]]);
        let ef_len = u16::from_be_bytes([plaintext[offset + 2], plaintext[offset + 3]]) as usize;
        if ef_len < 4 || offset + ef_len > plaintext.len() {
            break;
        }
        if type_id == 0x0204 {
            cookies.push(plaintext[offset + 4..offset + ef_len].to_vec());
        }
        offset += ef_len;
    }
    Ok(cookies)
}
```

**Step 4: Run tests**

```bash
cargo test --lib response_tests
```

Expected: all pass.

**Step 5: Replace `NtsState::create_request` and `NtsState::parse_response`**

Update `NtsState` to use `AeadCipher` instead of `Box<dyn ntp_proto::Cipher>`, and rewire `create_request` and `parse_response` to use the new helpers.

Replace the struct definition:

```rust
pub struct NtsState {
    c2s: AeadCipher,
    s2c: AeadCipher,
    cookies: Vec<Vec<u8>>,
    send_time: Option<SystemTime>,
    last_request: Option<RequestValidation>,
}
```

Replace `NtsState::new`:

```rust
pub fn new(c2s: AeadCipher, s2c: AeadCipher, cookies: Vec<Vec<u8>>) -> Self {
    debug!("Creating NtsState with {} cookies", cookies.len());
    Self { c2s, s2c, cookies, send_time: None, last_request: None }
}
```

Replace `create_request` (remove `poll_interval` parameter entirely):

```rust
pub fn create_request(&mut self) -> Result<Vec<u8>> {
    let cookie = self.cookies.pop().ok_or(Error::MissingNtsCookie)?;
    debug!(
        "Creating NTS request with cookie ({} bytes), {} remaining",
        cookie.len(),
        self.cookies.len()
    );

    let extra = if self.needs_more_cookies() {
        let max = ((NTS_PACKET_BUFFER_SIZE - 300) / cookie.len().max(1)).min(255) as u8;
        max.min(COOKIES_TO_REQUEST)
    } else {
        1
    };

    let packet = build_nts_request(&cookie, extra, &self.c2s).map_err(|e| {
        self.cookies.push(cookie.clone());
        e
    })?;

    self.send_time = Some(SystemTime::now());

    let request_validation = match extract_request_validation(&packet, extra) {
        Ok(v) => v,
        Err(e) => {
            self.cookies.push(cookie);
            return Err(e);
        }
    };
    self.last_request = Some(request_validation);

    debug!("Created NTS request: {} bytes", packet.len());
    Ok(packet)
}
```

Replace `parse_response` to use `find_authenticator_ef`, `extract_new_cookies`, and `ntp_bytes_to_system_time`:

```rust
pub fn parse_response(&mut self, data: &[u8]) -> Result<NtsResponse> {
    let send_time = self.send_time.take().unwrap_or_else(SystemTime::now);

    debug!("Parsing NTS response: {} bytes", data.len());

    if data.len() < NTP_HEADER_LEN {
        return Err(Error::MalformedNtsExtension("Response too short".to_string()));
    }

    if is_kiss_ntsn(data) {
        return Err(Error::AuthenticationFailed(
            "Server responded with NTS-NAK (re-key required)".to_string(),
        ));
    }
    if is_kiss_deny(data) {
        return Err(Error::AuthenticationFailed("Server denied service".to_string()));
    }
    if is_kiss_rate(data) {
        return Err(Error::Protocol("Server requested rate limiting".to_string()));
    }

    // Locate and verify the NTS Authenticator EF.
    let (auth_offset, nonce, ciphertext) = find_authenticator_ef(data)?
        .ok_or(Error::MissingAuthenticator)?;

    // AD = all bytes before the authenticator EF (header + preceding EFs).
    let preceding = &data[..auth_offset];
    let decrypted = self
        .s2c
        .decrypt_siv(&[preceding, &nonce], &ciphertext)
        .map_err(|_| {
            warn!("NTS AEAD verification failed");
            Error::AeadVerificationFailed("NTS response authentication failed".to_string())
        })?;

    // Validate request/response correlation.
    let validation = self.last_request.take().ok_or_else(|| {
        Error::InvalidResponse("No matching request context".to_string())
    })?;
    let response_validation = parse_response_validation(data)?;

    if !response_validation.has_nts_encrypted {
        return Err(Error::MissingAuthenticator);
    }
    if response_validation.unique_id != validation.unique_id {
        return Err(Error::InvalidResponse(
            "Unique Identifier mismatch".to_string(),
        ));
    }
    if response_validation.origin_timestamp != validation.expected_origin {
        return Err(Error::InvalidResponse(
            "Origin timestamp mismatch".to_string(),
        ));
    }

    // Extract new cookies from the decrypted payload.
    let new_cookies = extract_new_cookies(&decrypted)?;
    debug!("Received {} new cookies", new_cookies.len());

    if validation.requested_cookies > 1 && new_cookies.is_empty() {
        return Err(Error::NoCookiesReturned);
    }
    for c in new_cookies {
        self.store_cookie(c);
    }

    let recv_time = SystemTime::now();
    let round_trip_delay = recv_time.duration_since(send_time).unwrap_or(Duration::ZERO);

    // Read header fields from fixed byte offsets.
    let ts_bytes: [u8; 8] = data[40..48].try_into().unwrap();
    let network_time = ntp_bytes_to_system_time(&ts_bytes);

    let response = NtsResponse {
        network_time,
        system_time: recv_time,
        round_trip_delay,
        stratum: data[1],
        precision: data[3] as i8,
        leap: NtpLeapIndicator::from(data[0]),
        authenticated: true,
    };

    debug!(
        "NTS response verified. Stratum: {}, cookies remaining: {}",
        response.stratum,
        self.cookies.len()
    );
    Ok(response)
}
```

**Step 6: Remove all remaining `ntp_proto` imports from `src/nts_ntp.rs`**

Replace the top-of-file imports with:

```rust
//! NTS-aware NTP packet handling (RFC 8915 §5).
//!
//! Builds authenticated NTP requests and verifies authenticated responses
//! using AES-SIV-CMAC encryption as negotiated during NTS-KE.

use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, trace, warn};

use crate::cipher::AeadCipher;
use crate::error::{Error, Result};
```

Remove the `ntp_timestamp_to_system_time` function (replaced by `ntp_bytes_to_system_time`).

Also remove the `use ntp_proto::{...}` line from `src/nts_ntp.rs` entirely.

**Step 7: Run all tests**

```bash
cargo test --lib
```

Expected: all tests pass (including the existing ones in `nts_ntp.rs`).

**Step 8: Commit**

```bash
git add src/nts_ntp.rs
git commit -m "feat(nts-ntp): rewrite NTS request/response handling, remove ntp-proto"
```

---

## Task 9: Update `src/types.rs` and `src/client.rs`

Remove `Box<dyn ntp_proto::Cipher>` from `NtsKeResult` and remove `PollInterval` from `client.rs`.

**Files:**
- Modify: `src/types.rs`
- Modify: `src/client.rs`

**Step 1: Update `src/types.rs`**

Replace:
```rust
use ntp_proto::Cipher;
```
With:
```rust
use crate::cipher::AeadCipher;
```

Replace the two cipher fields in `NtsKeResult`:
```rust
    pub(crate) c2s: Box<dyn Cipher>,
    pub(crate) s2c: Box<dyn Cipher>,
```
With:
```rust
    pub(crate) c2s: AeadCipher,
    pub(crate) s2c: AeadCipher,
```

Update the `NtsKeResult::new` signature to match:
```rust
    pub(crate) fn new(
        ntp_server: std::net::SocketAddr,
        aead_algorithm: String,
        cookies: Vec<Vec<u8>>,
        ke_duration: std::time::Duration,
        c2s: AeadCipher,
        s2c: AeadCipher,
        certificate: Option<CertificateInfo>,
    ) -> Self {
```

Remove the manual `Debug` impl for `NtsKeResult` (it was needed because `Box<dyn Cipher>` didn't impl `Debug`; `AeadCipher` derives `Debug`).

Update `into_nts_state` to no longer dereference boxes:
```rust
    pub(crate) fn into_nts_state(self) -> crate::nts_ntp::NtsState {
        crate::nts_ntp::NtsState::new(self.c2s, self.s2c, self.cookies)
    }
```

**Step 2: Update `src/client.rs`**

Remove:
```rust
use ntp_proto::PollInterval;
```

In `get_time`, change:
```rust
        let poll_interval = PollInterval::default();
        let request = nts_state.create_request(poll_interval)?;
```
To:
```rust
        let request = nts_state.create_request()?;
```

**Step 3: Verify compilation**

```bash
cargo check
```

Expected: no errors.

**Step 4: Run all tests**

```bash
cargo test --lib
```

Expected: all pass.

**Step 5: Commit**

```bash
git add src/types.rs src/client.rs
git commit -m "refactor: replace Box<dyn Cipher> with AeadCipher, remove PollInterval"
```

---

## Task 10: Remove `ntp-proto` from `Cargo.toml`

**Files:**
- Modify: `Cargo.toml`

**Step 1: Delete the `ntp-proto` dependency line**

Remove from `[dependencies]`:
```toml
ntp-proto = { version = "1.6.2", features = ["__internal-test"] }
```

**Step 2: Verify compilation**

```bash
cargo check
```

Expected: no errors. If any `ntp_proto` import was missed, the error message will point you directly to it — fix it before proceeding.

**Step 3: Run the full test suite**

```bash
cargo test
```

Expected: all tests pass.

**Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore(deps): remove ntp-proto dependency"
```

---

## Task 11: Update docs and CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `src/lib.rs`
- Modify: `Cargo.toml` (description field)

**Step 1: Update `CHANGELOG.md`**

Add a new entry **above** the existing `## [Unreleased]` block:

```markdown
## [0.5.0] - unreleased

### Changed

- Removed dependency on `ntp-proto` and its `__internal-test` unstable internal
  feature. NTS-KE (RFC 8915 §4) and NTP packet handling (RFC 8915 §5) are now
  implemented directly, eliminating the dependency on ntpd-rs internals.
- NTS-KE is now fully asynchronous using `tokio-rustls` directly; the previous
  `spawn_blocking` workaround is gone.
- System CA certificates are loaded via `rustls-native-certs`, supplemented by
  the `webpki-roots` Mozilla root set as a fallback.

### Added

- `aes-siv` and `rand` as direct dependencies (previously indirect via `ntp-proto`).

### Removed

- `ntp-proto` dependency.
- `rustls-platform-verifier` indirect dependency (was pulled in by `ntp-proto`).
```

**Step 2: Update `Cargo.toml` description**

Replace:
```toml
description = "High-level NTS (Network Time Security) Client library based on ntpd-rs"
```
With:
```toml
description = "High-level NTS (Network Time Security) Client library — RFC 8915 implementation"
```

**Step 3: Update `src/lib.rs`**

- Remove "Based on ntpd-rs" from the crate-level `//!` doc comment (line ~20 area).
- Replace it with a note about the self-contained implementation:
  ```
  //! All cryptographic operations are performed directly using `aes-siv` (RFC 5297)
  //! and `rustls` (TLS 1.3). No unstable internal dependencies are required.
  ```

**Step 4: Update `README.md`**

- Find and remove the phrase "based on ntpd-rs" or references to the Pendulum Project as a runtime dependency.
- In the feature list, replace "Based on ntpd-rs: Built on the battle-tested ntpd-rs implementation" with "Self-contained RFC 8915: NTS-KE and NTS-NTP implemented directly — no unstable internal dependencies".
- In the security section (if it mentions ntpd-rs), update accordingly.

**Step 5: Run `cargo doc` to verify docs are clean**

```bash
cargo doc --no-deps 2>&1 | grep -E "warning|error"
```

Expected: no warnings or errors.

**Step 6: Commit**

```bash
git add CHANGELOG.md README.md src/lib.rs Cargo.toml
git commit -m "docs: update CHANGELOG, README, and crate description for 0.5.0"
```

---

## Task 12: Final verification

**Step 1: Full test suite**

```bash
cargo test
```

Expected: all tests pass, zero failures.

**Step 2: Clippy — zero warnings**

```bash
cargo clippy -- -D warnings
```

Expected: clean. Fix any lint warnings before proceeding.

**Step 3: Documentation build**

```bash
cargo doc --no-deps
```

Expected: builds without warnings. Open `target/doc/rkik_nts/index.html` and spot-check that the crate root, `NtsClient`, `NtsClientConfig`, `TimeSnapshot`, and `CertificateInfo` all have rendered doc comments.

**Step 4: Check `Cargo.toml` for any leftover ntp-proto references**

```bash
grep -r "ntp.proto\|ntp_proto\|__internal" src/ Cargo.toml
```

Expected: no output.

**Step 5: Final commit**

```bash
git add -p  # review any unstaged changes
git commit -m "chore: final cleanup — cargo clippy and doc verified for 0.5.0"
```
