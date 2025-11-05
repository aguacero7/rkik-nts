//! Simple NTS client example.
//!
//! This example demonstrates the basic usage of the rkik-nts library
//! to query time from an NTS-secured NTP server.
//!
//! Run with: cargo run --example simple_client --features tracing-subscriber

use rkik_nts::{NtsClient, NtsClientConfig};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // List of public NTS servers to try
    let servers = vec!["time.cloudflare.com", "nts.ntp.se", "ntppool1.time.nl"];

    println!("rkik-nts Simple Client Example\n");
    println!("================================\n");

    for server in servers {
        println!("Querying server: {}", server);
        println!("{}", "-".repeat(50));

        // Create configuration for the NTS server
        let config = NtsClientConfig::new(server);

        // Create NTS client
        let mut client = NtsClient::new(config);

        // Connect and perform NTS key exchange
        match client.connect().await {
            Ok(_) => {
                println!("✓ Successfully connected to {}", server);
                println!("  NTP server: {}", client.ntp_server().unwrap());
            }
            Err(e) => {
                println!("✗ Failed to connect to {}: {}", server, e);
                println!();
                continue;
            }
        }

        // Query time
        match client.get_time().await {
            Ok(time) => {
                println!("✓ Time query successful!\n");
                println!("  Network time:  {:?}", time.network_time);
                println!("  System time:   {:?}", time.system_time);
                println!("  Offset:        {:?}", time.offset);
                println!("  Offset (ms):   {} ms", time.offset_signed());
                println!("  Round-trip:    {:?}", time.round_trip_delay);
                println!("  Authenticated: {}", time.authenticated);
                println!("  Server:        {}", time.server);

                if time.is_ahead() {
                    println!("\n  ⚠ System clock is ahead of network time");
                } else if time.is_behind() {
                    println!("\n  ⚠ System clock is behind network time");
                } else {
                    println!("\n  ✓ System clock is synchronized");
                }
            }
            Err(e) => {
                println!("✗ Failed to query time: {}", e);
            }
        }

        println!();

        // Only query the first successful server
        break;
    }

    Ok(())
}
