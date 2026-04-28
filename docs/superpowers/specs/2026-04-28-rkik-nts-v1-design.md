# rkik-nts v1.0.0 — Design Spec

**Date:** 2026-04-28
**Crate:** `rkik-nts` (workspace: `rkik-nts-2/`)
**Target version:** 1.0.0

---

## Context

`rkik-nts` is the NTS (Network Time Security, RFC 8915) client library used by `rkik`.
The crate was previously coupled to `ntp-proto` for NTP packet handling. That dependency
became a source of breakage. The goal of this spec is to complete the library with a
fully self-contained NTP+NTS implementation, no external packet crate required.

Current state (v0.4.0):
- NTS-KE handshake over TLS 1.3 with ALPN `ntske/1` — **complete**
- Key derivation via RFC 5705 keying material export — **complete**
- AES-SIV-CMAC-256/512 AEAD cipher — **complete**
- `NtsState::create_request()` — **stub, not implemented**
- `NtsState::parse_response()` — **stub, not implemented**

Everything in `nts_ke.rs`, `cipher.rs`, `config.rs`, `error.rs`, `types.rs` is kept as-is.

---

## Scope

Complete `rkik-nts` to version 1.0.0 by:

1. Implementing `NtsState::create_request()` and `NtsState::parse_response()` in `nts_ntp.rs`
2. Removing the `ntp-proto` dependency from `Cargo.toml`
3. Adding a comprehensive test suite (unit + network)
4. Adding a GitHub Actions CI workflow
5. Updating `CHANGELOG.md`, `README.md`, and all inline documentation

No API-breaking changes. The public interface (`NtsClient`, `NtsClientConfig`,
`TimeSnapshot`, `NtsKeInfo`, `CertificateInfo`) is frozen.

---

## Architecture

### What changes

| File | Change |
|---|---|
| `Cargo.toml` | Remove `ntp-proto`, add `network-tests` feature flag |
| `src/nts_ntp.rs` | Implement `create_request()` and `parse_response()` |
| `tests/nts_network.rs` | New: network integration tests (gated on `network-tests`) |
| `.github/workflows/ci.yml` | New: CI workflow |
| `CHANGELOG.md` | v1.0.0 entry |
| `README.md` | Update badges, usage section, tested servers list |

### What stays

`nts_ke.rs`, `cipher.rs`, `config.rs`, `error.rs`, `types.rs`, `client.rs`,
all existing examples, the `NtsState` struct layout, all public types.

---

## NTP Packet Format (RFC 5905 + RFC 8915)

### Request packet layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| LI=0 |VN=4 |Mode=3 |  Stratum=0  |  Poll=0   |  Precision=0  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Root Delay = 0                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Root Dispersion = 0                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Reference ID = 0                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Reference Timestamp (64 bits) = 0           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Origin Timestamp (64 bits) = 0             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Receive Timestamp (64 bits) = 0            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Transmit Timestamp (64 bits) = T1           |  <- saved as expected_origin
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  EF type=0x0104 (Unique ID)    |  length = 36                 |  <- 32-byte random nonce
|  unique_id[0..32]                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  EF type=0x0204 (NTS Cookie)   |  length = 4+cookie_len       |
|  cookie[...]                                                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  EF type=0x0304 (Cookie Placeholder)  |  length = 4+cookie_len|  <- repeated N times
|  zeros[cookie_len]                                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  EF type=0x0404 (NTS Authenticator)   |  length = 4+16+ct_len |
|  nonce[16] | ciphertext[...]                                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Extension field wire format (RFC 7822):**
- 2 bytes: type
- 2 bytes: total length (including the 4-byte header), padded to 4-byte boundary
- N bytes: body

### NTS Authenticator construction (field 0x0404)

Per RFC 8915 §5.5:
- AD = everything in the packet from byte 0 up to (not including) field 0x0404
- Plaintext = empty (client sends no encrypted payload in requests)
- `c2s.encrypt_siv(&[ad], &[])` → 16 bytes (SIV tag only, since plaintext is empty)
- Wire: nonce (16 bytes of the SIV output) + ciphertext (0 bytes) = 16 bytes total body

---

## create_request() Logic

```
1. Consume one cookie from the pool (error if empty)
2. Build NTP header (48 bytes):
   - byte 0: LI=0, VN=4, Mode=3  → 0x23
   - bytes 1-3: stratum=0, poll=0, precision=0
   - bytes 4-43: zeros (root delay, dispersion, ref id, ref ts, origin ts, recv ts)
   - bytes 40-47: transmit timestamp T1 = SystemTime::now() as NTP timestamp
3. Append Unique ID field (type=0x0104, body=32 random bytes)
4. Append NTS Cookie field (type=0x0204, body=consumed_cookie)
5. Compute N = max(0, MIN_COOKIE_COUNT - (cookie_pool.len()))
   Append N × Cookie Placeholder fields (type=0x0304, body=zeros of cookie.len())
6. Compute AEAD:
   ad = &packet[0..current_len]
   ct = c2s.encrypt_siv(&[ad], &[])   // 16 bytes
   Append NTS Authenticator field (type=0x0404, body=ct)
7. Save RequestValidation { expected_origin: T1_bytes, unique_id, requested_cookies: N }
8. Record send_time = Instant::now() for RTT
9. Return serialized packet
```

---

## parse_response() Logic

```
1. Check packet length >= 48
2. Verify byte 0: LI != 3 (not unsynchronized), Mode == 4 (server)
3. Verify stratum in 1..=15
4. Extract T1_received = origin timestamp (bytes 24..32)
   Verify T1_received == last_request.expected_origin (replay / mismatch guard)
5. Parse extension fields:
   a. Unique ID (0x0104): verify == last_request.unique_id
   b. NTS Authenticator (0x0404): required, parse nonce + ciphertext
6. AEAD verification:
   ad = packet bytes from 0 up to (not including) field 0x0404
   plaintext = s2c.decrypt_siv(&[ad], &authenticator_body)
   On failure → Error::AeadVerificationFailed
7. Parse plaintext for new cookies:
   Plaintext contains TLV-encoded new cookies (RFC 8915 §5.7)
   Each cookie type=0x0205 → push to self.cookies
8. Extract timestamps:
   T2 = receive timestamp (bytes 32..40) as SystemTime
   T3 = transmit timestamp (bytes 40..48) as SystemTime
   T4 = SystemTime::now()
   T1 = origin timestamp as SystemTime
   offset = ((T2 - T1) + (T3 - T4)) / 2
   rtt    = (T4 - T1) - (T3 - T2)
9. Return NtsResponse {
     network_time: T3 + (T4 - T3) / 2,  // best estimate of "now" at server
     system_time: T4,
     round_trip_delay: rtt,
     stratum, precision, leap,
     authenticated: true,
   }
```

---

## NTP Timestamp Encoding

NTP timestamps are 64-bit fixed-point seconds since 1900-01-01 00:00:00 UTC.
- Upper 32 bits: seconds
- Lower 32 bits: fraction (1/2^32 seconds)

Conversion from `SystemTime`:
```
NTP_EPOCH_OFFSET = 2_208_988_800  // seconds between 1900 and 1970
secs = unix_secs + NTP_EPOCH_OFFSET
frac = subsec_nanos * 2^32 / 1_000_000_000
```

Conversion to `SystemTime`:
```
unix_secs = ntp_secs - NTP_EPOCH_OFFSET
nanos = ntp_frac * 1_000_000_000 / 2^32
```

---

## Test Suite

### Unit tests (in `src/nts_ntp.rs`, no network)

| Test | Verifies |
|---|---|
| `build_request_packet_structure` | Header 48B + 4 extension field types present |
| `extension_field_alignment` | Every field length divisible by 4 |
| `unique_id_is_32_bytes` | Unique ID body = 32 bytes |
| `cookie_consumed_on_request` | Pool N → N-1 after `create_request()` |
| `placeholder_count_matches_deficit` | Correct number of placeholders appended |
| `aead_covers_full_preceding_packet` | AD boundary = start of field 0x0404 |
| `ntp_timestamp_roundtrip` | SystemTime → NTP u64 → SystemTime within 1µs |
| `offset_calculation_four_timestamps` | Known T1/T2/T3/T4 → known offset and RTT |
| `reject_wrong_origin_timestamp` | `parse_response()` → Error if T1 mismatch |
| `reject_wrong_unique_id` | Error if Unique ID mismatch |
| `reject_missing_authenticator` | Error if field 0x0404 absent |
| `reject_tampered_aead_tag` | Error::AeadVerificationFailed on bit flip |
| `cookies_stored_from_response` | New cookies extracted from plaintext |
| `in_memory_roundtrip` | `create_request()` → hand-crafted server reply → `parse_response()` → authenticated=true |

### Network tests (`tests/nts_network.rs`, feature = `network-tests`)

| Test | Server | Verifies |
|---|---|---|
| `test_nts_query_ntp_se` | nts.ntp.se | authenticated=true, RTT > 0 |
| `test_nts_query_cloudflare` | time.cloudflare.com | authenticated=true |
| `test_nts_query_ptbtime` | ptbtime1.ptb.de | authenticated=true (DE server diversity) |
| `test_nts_cookie_replenishment` | nts.ntp.se | 8 consecutive queries, pool stays >= 1 |
| `test_nts_reconnect_replenishes` | nts.ntp.se | `reconnect()` → cookie_count back to >= 8 |
| `test_nts_ipv6` | nts.ntp.se | IPv6 path works if available |

### CI Workflow (`.github/workflows/ci.yml`)

Calqué sur `rkik-3` CI:
- Matrix: `ubuntu-latest`, `windows-latest`, `macos-latest`, Rust stable
- Steps: `fmt --check`, `clippy -D warnings`, `build`, `test --lib`, `cargo audit`
- Separate `network-smoke` job (ubuntu only): `test --features network-tests`

---

## Documentation

All changes include:

- **Inline rustdoc**: `NtsState::create_request()` and `parse_response()` fully documented
  with parameters, errors, and packet layout description
- **`CHANGELOG.md`**: v1.0.0 entry with full list of changes
- **`README.md`**: Update "Based on ntpd-rs" references → remove, update dependency list,
  add tested NTS servers table, add CI badge
- **`docs/NTS_USAGE.md`** (mirroring rkik-3 structure): usage guide for the lib as standalone,
  including how to run network tests

---

## Dependencies after this work

```toml
aes-siv     = "0.7"
rand        = "0.8"
tokio       = { version = "1.40", features = ["net", "time", "rt-multi-thread", "macros", "io-util"] }
tokio-rustls = "0.26"
rustls      = { version = "0.23", features = ["ring"] }
rustls-native-certs = "0.8"
webpki-roots = "1.0.4"
thiserror   = "2.0"
tracing     = "0.1"
x509-parser = "0.18"
sha2        = "0.10"
chrono      = "0.4"
# ntp-proto REMOVED
```

---

## Definition of Done

- [ ] `cargo test --lib` passes with zero warnings (`-D warnings`)
- [ ] `cargo test --features network-tests` passes against real servers
- [ ] `cargo clippy -D warnings` clean
- [ ] `cargo fmt --check` clean
- [ ] `cargo audit` no unresolved vulnerabilities
- [ ] `ntp-proto` absent from `Cargo.toml` and `Cargo.lock`
- [ ] `CHANGELOG.md` updated with v1.0.0
- [ ] `README.md` accurate
- [ ] All public items have rustdoc
