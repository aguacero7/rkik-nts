# rkik-nts

[![Crates.io](https://img.shields.io/crates/v/rkik-nts.svg)](https://crates.io/crates/rkik-nts)
[![Documentation](https://docs.rs/rkik-nts/badge.svg)](https://docs.rs/rkik-nts)

A high-level **NTS (Network Time Security) client** library for Rust with a self-contained RFC 8915 implementation.

This library provides a simple, safe, and ergonomic API for querying time from NTS-secured NTP servers. It handles the complexity of NTS key exchange and authenticated time synchronization, making it easy to integrate secure time synchronization into your applications.

## Features

- **Secure**: Full NTS (Network Time Security) support for authenticated time queries
- **Certificate Diagnostics**: TLS certificate information capture for security auditing and diagnostics
- **TLS Debugging**: SSLKEYLOGFILE support for Wireshark traffic analysis
- **Simple API**: Easy-to-use client interface with sensible defaults
- **Async**: Built on Tokio for efficient async I/O
- **Configurable**: Flexible configuration options for advanced use cases
- **Self-contained**: NTS-KE and NTS-protected NTP are implemented directly in this crate
- **Integration-ready**: Designed for seamless integration with [rkik](https://github.com/aguacero7/rkik)

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
rkik-nts = "1"
tokio = { version = "1", features = ["full"] }
```

Basic usage:

```rust
use rkik_nts::{NtsClient, NtsClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client configuration
    let config = NtsClientConfig::new("time.cloudflare.com");

    // Create and connect the client
    let mut client = NtsClient::new(config);
    client.connect().await?;

    // Query the current time
    let time = client.get_time().await?;

    println!("Network time: {:?}", time.network_time);
    println!("Offset (ms): {} ms", time.offset_signed());
    println!("Authenticated: {}", time.authenticated);

    Ok(())
}
```

## Examples

### Simple Client

```bash
cargo run --example simple_client --features tracing-subscriber
```

### End-to-End NTS Validation

```bash
cargo run --example nts_end_to_end --features tracing-subscriber
```

### Certificate Information

Access TLS certificate information from the NTS-KE handshake:

```rust
use rkik_nts::{NtsClient, NtsClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = NtsClientConfig::new("time.cloudflare.com");
    let mut client = NtsClient::new(config);
    client.connect().await?;

    // Access certificate information
    if let Some(ke_result) = client.nts_ke_info() {
        if let Some(cert) = &ke_result.certificate {
            println!("Certificate Subject: {}", cert.subject);
            println!("Certificate Issuer: {}", cert.issuer);
            println!("Valid from: {} to {}", cert.valid_from, cert.valid_until);
            println!("SHA-256 Fingerprint: {}", cert.fingerprint_sha256);
            println!("Self-signed: {}", cert.is_self_signed);
        }
    }

    Ok(())
}
```

Run the certificate example:

```bash
cargo run --example test_certificate --features tracing-subscriber
```

### Custom Configuration

```rust
use rkik_nts::{NtsClient, NtsClientConfig};
use std::time::Duration;

let config = NtsClientConfig::new("time.cloudflare.com")
    .with_port(4460)
    .with_timeout(Duration::from_secs(5))
    .with_max_retries(3);

let mut client = NtsClient::new(config);
client.connect().await?;
let time = client.get_time().await?;
```

Note: retry logic is not automatic; `max_retries` is currently a reserved configuration value.

See the [examples/](examples/) directory for more detailed examples.

## Advanced Features

### TLS Traffic Analysis with SSLKEYLOGFILE

For debugging and network analysis, you can capture TLS session keys for Wireshark decryption:

```bash
# Set environment variable to enable keylog
export SSLKEYLOGFILE=/tmp/sslkeylog.txt

# Run your application or example
cargo run --example test_certificate --features tracing-subscriber

# Use the keylog file in Wireshark:
# Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
```

This allows you to decrypt and analyze the NTS-KE TLS traffic in Wireshark for troubleshooting.

## Public NTS Servers

Here are some public NTS servers you can use for testing:

- `time.cloudflare.com` - Cloudflare
- `nts.ntp.se` - Netnod (Sweden)
- `ntppool1.time.nl` - NLnet Labs (Netherlands)
- `time.txryan.com` - Tanner Ryan
- `nts.ntp.org.au` - Australian NTP Pool
- `ptbtime1.ptb.de` - PTB (Germany, public service availability not guaranteed)

The current network test suite is validated against `time.cloudflare.com` and `nts.ntp.se`.
PTB servers are exercised opportunistically because PTB explicitly states that uninterrupted public availability is not guaranteed.

## Integration with rkik

This library is designed for seamless integration with rkik, but can also be used as a standalone NTS client library. The API is intentionally kept simple and focused on authenticated time acquisition.

## Architecture

The library is structured into several modules:

- **`client`**: High-level NTS client implementation
- **`config`**: Configuration types and builders
- **`error`**: Error types and result aliases
- **`nts_ke`**: NTS Key Exchange protocol implementation
- **`types`**: Common types (TimeSnapshot, NtsKeResult, etc.)

## How NTS Works

Network Time Security (NTS) is a security extension for NTP that provides:

1. **Authentication**: Cryptographic verification that time data comes from the expected server
2. **Encryption**: Protection of time synchronization traffic
3. **Resistance to replay attacks**: Each query uses unique authentication cookies

The protocol works in two phases:

1. **NTS-KE (Key Exchange)**: TLS connection to exchange keys and cookies
2. **NTP with NTS**: UDP-based time queries using the negotiated keys

This library handles both phases transparently.

## Requirements

- Rust 1.70 or later
- Tokio runtime

## Development

```bash
# Build the library
cargo build

# Run tests
cargo test

# Run examples
cargo run --example simple_client --features tracing-subscriber

# Build documentation
cargo doc --open
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Resources

- [RFC 8915: Network Time Security for the Network Time Protocol](https://datatracker.ietf.org/doc/html/rfc8915)
- [NTS Pool](https://www.ntppool.org/en/use.html#nts)
