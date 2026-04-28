# Design: Remove `ntp-proto` dependency

**Date:** 2026-03-03
**Status:** Approved
**Target version:** 0.5.0

---

## Problem

`rkik-nts` depends on `ntp-proto` with the `__internal-test` feature:

```toml
ntp-proto = { version = "1.6.2", features = ["__internal-test"] }
```

In `ntp-proto`, all public symbols are gated behind `__internal-api` (activated by
`__internal-test`). Without this feature every export is `pub(crate)`, meaning the
entire crate API is internal-only. This creates two concrete risks:

1. **Silent breakage on upgrade.** The `KeyExchangeClient` API already changed
   incompatibly between v1.6.2 and v1.7.1 (blocking state-machine → async).
   Any patch release can change internals without a semver signal.
2. **Downstream instability.** Any crate that depends on `rkik-nts` transitively
   inherits an unstable internal API that can break without warning.

`ntp-proto` is the internal implementation crate for the `ntpd-rs` daemon and is
not designed as a public library. The dependency must be eliminated entirely.

---

## Scope

All `ntp-proto` usage in the codebase:

| File | Types used |
|------|-----------|
| `src/nts_ke.rs` | `KeyExchangeClient`, `KeyExchangeResult`, `ProtocolVersion`, `tls_utils::*`, `KeyExchangeError` |
| `src/nts_ntp.rs` | `Cipher`, `NtpPacket`, `PacketParsingError`, `PollInterval`, `NtpTimestamp`, `NtpLeapIndicator` |
| `src/types.rs` | `Cipher` (via `Box<dyn Cipher>`) |
| `src/client.rs` | `PollInterval` |

---

## Decisions

| Question | Decision |
|----------|----------|
| `NtpLeapIndicator` replacement | Define equivalent `pub(crate)` enum in `src/nts_ntp.rs` |
| AEAD algorithm support | Both AEAD_AES_SIV_CMAC_256 and AEAD_AES_SIV_CMAC_512 |
| Implementation strategy | Incremental, file-by-file (Approach A); crate compiles after each file |

---

## Design

### 1. Dependencies

**Remove:**
- `ntp-proto` (all features)

**Add:**
- `aes-siv = "0.7"` — multi-AD AES-SIV per RFC 5297, provides `Aes128Siv` (256-bit) and `Aes256Siv` (512-bit)
- `rand = "0.8"` — promoted from indirect; needed for unique IDs and nonces

**Already present, now doing more work:**
- `tokio-rustls = "0.26"` — async TLS for NTS-KE
- `rustls = "0.23"` — `ClientConfig` and `export_keying_material()`
- `rustls-native-certs = "0.8"` — system CA loading, replaces `tls_utils::PlatformVerifier`
- `webpki-roots = "1.0.4"` — fallback roots merged into the trust store

**Removed indirect dep:**
- `rustls-platform-verifier` (was pulled in by `ntp-proto`)

---

### 2. New module: `src/cipher.rs`

Provides the internal cipher abstraction used by both `nts_ke.rs` and `nts_ntp.rs`.

```rust
pub(crate) enum AeadCipher {
    SivCmac256(Box<Aes128Siv>),   // AEAD_AES_SIV_CMAC_256, 32-byte key
    SivCmac512(Box<Aes256Siv>),   // AEAD_AES_SIV_CMAC_512, 64-byte key
}
```

Key methods:
- `AeadCipher::from_key_bytes(alg_id: u16, key: &[u8]) -> Result<Self>`
- `AeadCipher::key_len(alg_id: u16) -> Option<usize>` → 32 or 64
- `AeadCipher::encrypt_siv(&self, ad: &[&[u8]], plaintext: &[u8]) -> Result<Vec<u8>>`
- `AeadCipher::decrypt_siv(&self, ad: &[&[u8]], ciphertext: &[u8]) -> Result<Vec<u8>>`

`encrypt_siv` / `decrypt_siv` accept `ad: &[&[u8]]` — a slice of byte-slice references —
which maps directly to the `aes_siv` multi-AD API, preserving RFC 5297 §2.6 correctness.
No AAD concatenation (which would produce incorrect SIV tags).

---

### 3. `src/nts_ke.rs` — async NTS-KE from scratch

Replaces the `KeyExchangeClient` blocking state-machine with a direct async
implementation. `spawn_blocking` is eliminated.

**Protocol (RFC 8915 §4):**

1. DNS-resolve server address
2. Build `rustls::ClientConfig` (TLS 1.3, ALPN `"ntske/1"`) with `CapturingVerifier`
   wrapping a `WebPkiServerVerifier` built from `rustls-native-certs` + `webpki-roots`
3. `tokio-rustls::TlsConnector::connect()` — async handshake
4. Write one NTS-KE record: End of Message (critical=1, type=0, body empty), flush
5. Read records until server End of Message:
   - Type 4 (`AeadAlgorithm`): 2-byte algorithm ID
   - Type 5 (`NewCookie`): opaque cookie bytes
   - Type 6 (`NtpServerName`): UTF-8 server hostname
   - Type 7 (`NtpPort`): 2-byte port number
   - Unknown + critical → `Error::KeyExchange`
   - Unknown + non-critical → skip
6. Validate: at least one cookie received, algorithm is 15 or 17
7. Export TLS keying material via `tls_stream.get_ref().1.export_keying_material()`:

| Algorithm | ID | Key bytes | c2s context | s2c context |
|-----------|-----|-----------|-------------|-------------|
| AES-SIV-CMAC-256 | 15 | 32 | `[0x00, 0x0F, 0x00]` | `[0x00, 0x0F, 0x01]` |
| AES-SIV-CMAC-512 | 17 | 64 | `[0x00, 0x11, 0x00]` | `[0x00, 0x11, 0x01]` |

Label: `"EXPORTER-network-time-security"`

8. Construct `AeadCipher` from exported key bytes, return `NtsKeResult`

**NTS-KE record wire format:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C|         Record Type         |          Body Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Record Body ...                         |
```
C=1: critical (unknown critical records are fatal). C=0: skip if unknown.

**Removed:** `From<KeyExchangeError>` impl (no longer needed). Error mapping
uses `Error::KeyExchange(String)`, `Error::Io`, `Error::Tls` — no new variants.

---

### 4. `src/nts_ntp.rs` — NTP packet handling from scratch

Replaces `NtpPacket`, `Cipher`, `PacketParsingError`, `PollInterval`, `NtpTimestamp`,
`NtpLeapIndicator`. The existing manual byte-parsing helpers
(`parse_extension_fields`, `extract_origin_timestamp`, `extract_transmit_timestamp`)
are retained and extended.

**`create_request` — building the NTP request:**

48-byte NTP header constructed directly:
- Byte 0: `0b_00_100_011` (LI=0 NoWarning, VN=4, Mode=3 Client)
- Byte 2: poll exponent (module constant, replaces `PollInterval` parameter)
- Byte 3: precision = `−20i8` cast to `u8`
- Bytes 40–47: 8 random bytes (transmit timestamp, used for origin matching)
- All other bytes: zero

Extension fields:
1. Unique Identifier EF (type `0x0104`): 4-byte header + 32 random bytes
2. NTS Cookie EF (type `0x0204`): 4-byte header + cookie bytes
3. NTS Cookie Placeholder EF × N (type `0x0304`): 4-byte header + N×cookie_len zero bytes
4. NTS Authenticator EF (type `0x0404`, RFC 8915 §5.7):
   - Generate 16-byte random nonce
   - AES-SIV encrypt: AD = `[header_48, preceding_EFs, nonce]`, plaintext = `[]`
   - Result: 16-byte SIV tag (authentication-only for client requests)
   - EF body: `nonce_len(2) | nonce(16) | ciphertext_len(2) | siv_tag(16)`

The unique ID and transmit timestamp are captured directly from the built buffer.
`create_request` signature becomes `fn create_request(&mut self) -> Result<Vec<u8>>`
(poll interval parameter removed; poll exponent is a constant).

**`parse_response` — verifying the NTP response:**

Kiss-code detection from raw bytes:
- Stratum = byte 1; Reference ID = bytes 12–15
- `NTSN` = `[0x4E, 0x54, 0x53, 0x4E]`, `DENY` = `[0x44, 0x45, 0x4E, 0x59]`,
  `RATE` = `[0x52, 0x41, 0x54, 0x45]`

NTS Authenticator EF decryption:
- Locate type `0x0404` via `parse_extension_fields`
- Parse body: `nonce_len(2) | nonce | ciphertext_len(2) | ciphertext`
- Identify the boundary between plain EFs and the authenticator in the raw packet
- AES-SIV decrypt: AD = `[header_48, EFs_before_authenticator, nonce]`, ciphertext
- Parse decrypted plaintext as extension fields; collect type `0x0204` bodies as new cookies

Header field reads (replacing packet accessors):
- Stratum: byte 1
- Precision: byte 3 as `i8`
- Leap: bits 6–7 of byte 0 → `NtpLeapIndicator`
- Transmit timestamp: bytes 40–47 as `(u32_be, u32_be)` → `SystemTime`

**`ntp_timestamp_to_system_time` simplified:**
```
unix_secs = ntp_seconds_be − 2_208_988_800
unix_nanos = (ntp_fraction_be as u64 × 1_000_000_000) >> 32
```

**`NtpLeapIndicator`** (defined in this file, `pub(crate)`):
```rust
pub(crate) enum NtpLeapIndicator { NoWarning, LastMinute61, LastMinute59, Unknown }
impl From<u8> for NtpLeapIndicator { … }  // maps (byte0 >> 6) & 0x3
```

---

### 5. `src/types.rs` and `src/client.rs`

**`types.rs`:**
- `use ntp_proto::Cipher` removed
- `c2s: Box<dyn Cipher>` and `s2c: Box<dyn Cipher>` become `c2s: AeadCipher` and `s2c: AeadCipher`
- No heap allocation overhead (enum, not trait object)

**`client.rs`:**
- `use ntp_proto::PollInterval` removed
- `PollInterval::default()` argument to `create_request()` removed

---

### 6. Docs, CHANGELOG, and open-source polish

**`Cargo.toml`:**
- Remove `ntp-proto` entry and its associated comment block
- Update `description` to remove "based on ntpd-rs"

**`CHANGELOG.md`:** New `0.5.0` entry documenting the dependency removal.

**`README.md`:** Remove ntpd-rs/Pendulum Project references from the dependency
description; replace with "self-contained RFC 8915 implementation".

**`src/lib.rs`:** Remove "Based on ntpd-rs" from crate doc; add `mod cipher;`.

**Code quality:**
- Every `pub` and `pub(crate)` item has a `///` doc comment
- All `pub(crate)` modules have `//!` module-level docs
- No `unwrap()` outside tests; all fallible operations use `?`
- All raw byte indexing is bounds-checked with descriptive error messages
- `cargo clippy` and `cargo doc --no-deps` pass without warnings

---

## Implementation order (Approach A — incremental)

1. Add `aes-siv` and `rand` to `Cargo.toml`; keep `ntp-proto` for now
2. Create `src/cipher.rs`
3. Rewrite `src/nts_ke.rs`; `nts_ntp.rs` / `types.rs` still use `ntp-proto` — crate compiles
4. Rewrite `src/nts_ntp.rs`
5. Update `src/types.rs` (swap `Box<dyn Cipher>` → `AeadCipher`)
6. Update `src/client.rs` (remove `PollInterval`)
7. Remove `ntp-proto` from `Cargo.toml`; `cargo check` must pass
8. Update `src/lib.rs`, `README.md`, `CHANGELOG.md`, `Cargo.toml` description
9. `cargo test`, `cargo clippy`, `cargo doc --no-deps`
