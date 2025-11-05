# rkik-nts

[![Crates.io](https://img.shields.io/crates/v/rkik-nts.svg)](https://crates.io/crates/rkik-nts)
[![Documentation](https://docs.rs/rkik-nts/badge.svg)](https://docs.rs/rkik-nts)

A high-level **NTS (Network Time Security) Client** library for Rust, based on [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) from the Pendulum Project.

This library provides a simple, safe, and ergonomic API for querying time from NTS-secured NTP servers. It handles the complexity of NTS key exchange and authenticated time synchronization, making it easy to integrate secure time synchronization into your applications.

## Features

- **Secure**: Full NTS (Network Time Security) support for authenticated time queries
- **Simple API**: Easy-to-use client interface with sensible defaults
- **Async**: Built on Tokio for efficient async I/O
- **Configurable**: Flexible configuration options for advanced use cases
- **Battle-tested**: Based on ntpd-rs from Project Pendulum
- **Integration-ready**: Designed for seamless integration with [rkik](https://github.com/aguacero7/rkik)

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
rkik-nts = "0.1"
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

See the [examples/](examples/) directory for more detailed examples.

## Public NTS Servers

Here are some public NTS servers you can use for testing:

- `time.cloudflare.com` - Cloudflare
- `nts.ntp.se` - Netnod (Sweden)
- `ntppool1.time.nl` - NLnet Labs (Netherlands)
- `time.txryan.com` - Ryan Sleevi
- `nts.ntp.org.au` - Australian NTP Pool

## Integration with rkik

This library is designed for seamless integration with rkik, but can also be used as a standalone NTS client library. The API is intentionally kept simple and focused on the core functionality of NTS time synchronization.

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

## Based on ntpd-rs

This library is built on top of [ntpd-rs](https://github.com/pendulum-project/ntpd-rs), a memory-safe NTP implementation developed by the Pendulum Project. The ntpd-rs project is maintained by Tweede golf and was originally funded by ISRG's Prossimo project.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Acknowledgments

- The [Pendulum Project](https://github.com/pendulum-project) for ntpd-rs
- [Tweede golf](https://tweedegolf.nl/) for maintaining ntpd-rs

## Resources

- [RFC 8915: Network Time Security for the Network Time Protocol](https://datatracker.ietf.org/doc/html/rfc8915)
- [ntpd-rs Documentation](https://docs.ntpd-rs.pendulum-project.org/)
- [NTS Pool](https://www.ntppool.org/en/use.html#nts)
