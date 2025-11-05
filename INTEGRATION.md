# Integration Guide for rkik

This document provides guidance on integrating `rkik-nts` with the rkik project.

## Overview

`rkik-nts` is designed as a high-level, easy-to-use NTS client library that can be seamlessly integrated into rkik or any other Rust project requiring secure time synchronization.

## Adding as a Dependency

### From crates.io (when published)

```toml
[dependencies]
rkik-nts = "0.1"
tokio = { version = "1", features = ["full"] }
```

### From Git (during development)

```toml
[dependencies]
rkik-nts = { git = "https://github.com/aguacero7/rkik-nts", branch = "main" }
tokio = { version = "1", features = ["full"] }
```

### As a Local Path Dependency

```toml
[dependencies]
rkik-nts = { path = "../rkik-nts" }
tokio = { version = "1", features = ["full"] }
```

## Basic Integration Pattern

Here's a typical pattern for integrating NTS time queries into rkik:

```rust
use rkik_nts::{NtsClient, NtsClientConfig, TimeSnapshot};
use std::time::Duration;

/// Initialize an NTS client for rkik
pub async fn init_nts_client(server: &str) -> Result<NtsClient, Box<dyn std::error::Error>> {
    let config = NtsClientConfig::new(server)
        .with_timeout(Duration::from_secs(10))
        .with_max_retries(3);

    let mut client = NtsClient::new(config);
    client.connect().await?;

    Ok(client)
}

/// Query time and handle the result
pub async fn query_secure_time(
    client: &mut NtsClient
) -> Result<TimeSnapshot, Box<dyn std::error::Error>> {
    let time = client.get_time().await?;

    // Log or handle the time offset
    if time.is_ahead() {
        println!("System clock is {} ms ahead", time.offset_signed());
    } else if time.is_behind() {
        println!("System clock is {} ms behind", time.offset_signed().abs());
    }

    Ok(time)
}
```

## Advanced Integration

### Multiple Server Support

```rust
use rkik_nts::{NtsClient, NtsClientConfig};

pub struct NtsPool {
    clients: Vec<NtsClient>,
    current: usize,
}

impl NtsPool {
    pub async fn new(servers: &[&str]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut clients = Vec::new();

        for server in servers {
            let config = NtsClientConfig::new(*server);
            let mut client = NtsClient::new(config);

            if client.connect().await.is_ok() {
                clients.push(client);
            }
        }

        if clients.is_empty() {
            return Err("Failed to connect to any NTS server".into());
        }

        Ok(Self {
            clients,
            current: 0,
        })
    }

    pub async fn query_time(&mut self) -> Result<TimeSnapshot, Box<dyn std::error::Error>> {
        let result = self.clients[self.current].get_time().await;

        match result {
            Ok(time) => Ok(time),
            Err(_) => {
                // Try next server
                self.current = (self.current + 1) % self.clients.len();
                self.clients[self.current].get_time().await
                    .map_err(|e| e.into())
            }
        }
    }
}
```

### Periodic Time Synchronization

```rust
use tokio::time::{interval, Duration};

pub async fn sync_time_periodically(
    mut client: NtsClient,
    interval_secs: u64
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ticker = interval(Duration::from_secs(interval_secs));

    loop {
        ticker.tick().await;

        match client.get_time().await {
            Ok(time) => {
                println!("Time synced. Offset: {} ms", time.offset_signed());
                // Apply time adjustment in rkik here
            }
            Err(e) => {
                eprintln!("Time sync failed: {}", e);
                // Attempt to reconnect
                if client.reconnect().await.is_ok() {
                    println!("Reconnected to NTS server");
                }
            }
        }
    }
}
```

## Configuration Best Practices

1. **Default Servers**: Use well-known, reliable NTS servers:
   - Cloudflare: `time.cloudflare.com`
   - Netnod (Sweden): `nts.ntp.se`
   - NLnet Labs: `ntppool1.time.nl`

2. **Timeouts**: Set reasonable timeouts (5-10 seconds) to avoid blocking

3. **Retries**: Configure 2-3 retries for transient network issues

4. **TLS Verification**: Always keep certificate verification enabled in production

5. **Error Handling**: Implement robust error handling and fallback strategies

## Testing

When testing rkik with NTS integration:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_nts_integration() {
        let mut client = init_nts_client("time.cloudflare.com")
            .await
            .expect("Failed to initialize NTS client");

        let time = query_secure_time(&mut client)
            .await
            .expect("Failed to query time");

        assert!(time.authenticated);
        println!("Offset: {} ms", time.offset_signed());
    }
}
```

## Performance Considerations

- **Connection Reuse**: Keep NTS clients alive and reuse them for multiple queries
- **Connection Pooling**: For high-frequency queries, maintain a pool of connected clients
- **Async I/O**: All operations are async - leverage Tokio's concurrency features
- **Cookie Management**: The library handles NTS cookie management internally

## Error Handling

The library provides specific error types for different failure modes:

```rust
use rkik_nts::Error;

match client.get_time().await {
    Ok(time) => { /* handle success */ },
    Err(Error::Timeout) => { /* handle timeout */ },
    Err(Error::ServerUnavailable(_)) => { /* handle unreachable server */ },
    Err(Error::KeyExchange(_)) => { /* handle NTS-KE failure */ },
    Err(e) => { /* handle other errors */ },
}
```

## Logging

Enable logging with the `tracing` crate:

```rust
use tracing_subscriber;

tracing_subscriber::fmt()
    .with_max_level(tracing::Level::INFO)
    .init();
```

This will show detailed logs of NTS-KE and time query operations.

## Security Considerations

1. Always verify TLS certificates in production
2. Use authenticated time only (check `time.authenticated`)
3. Implement certificate pinning for critical applications if needed
4. Monitor for clock skew and alert on large offsets

## Support

For issues specific to rkik-nts integration:
- Open an issue at: https://github.com/yourusername/rkik-nts/issues
- Check the examples directory for reference implementations
