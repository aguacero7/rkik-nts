//! Advanced NTS client example with custom configuration.
//!
//! This example demonstrates advanced configuration options
//! and error handling patterns.
//!
//! Run with: cargo run --example custom_config --features tracing-subscriber

use rkik_nts::{NtsClient, NtsClientConfig};
use std::error::Error;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging with debug level
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("rkik-nts Custom Configuration Example\n");
    println!("======================================\n");

    // Create a custom configuration
    let config = NtsClientConfig::new("time.cloudflare.com")
        .with_port(4460) // Standard NTS-KE port
        .with_timeout(Duration::from_secs(5)) // 5 second timeout
        .with_max_retries(3) // Retry up to 3 times
        .with_tls_verification(true) // Verify TLS certificates (default)
        .with_ntp_version(4); // Use NTPv4

    println!("Configuration:");
    println!("  Server:         {}", config.nts_ke_server);
    println!("  Port:           {}", config.nts_ke_port);
    println!("  Timeout:        {:?}", config.timeout);
    println!("  Max retries:    {}", config.max_retries);
    println!("  TLS verify:     {}", config.verify_tls_cert);
    println!("  NTP version:    {}\n", config.ntp_version);

    // Create NTS client
    let mut client = NtsClient::new(config);

    // Connect with error handling
    println!("Connecting to NTS server...");
    match client.connect().await {
        Ok(_) => {
            println!("✓ Connection established");
            if let Some(ntp_server) = client.ntp_server() {
                println!("  Using NTP server: {}", ntp_server);
            }
        }
        Err(e) => {
            eprintln!("✗ Connection failed: {}", e);
            return Err(e.into());
        }
    }

    println!("\nQuerying time (multiple samples)...\n");

    // Query time multiple times to see variance
    for i in 1..=5 {
        match client.get_time().await {
            Ok(time) => {
                println!("Sample {}:", i);
                println!("  Offset:     {} ms", time.offset_signed());
                println!("  Round-trip: {:?}", time.round_trip_delay);

                if time.authenticated {
                    println!("  ✓ Response authenticated via NTS");
                }
            }
            Err(e) => {
                eprintln!("  ✗ Query failed: {}", e);

                // Demonstrate reconnection on error
                if i < 5 {
                    println!("  Attempting to reconnect...");
                    if let Err(e) = client.reconnect().await {
                        eprintln!("  ✗ Reconnection failed: {}", e);
                        break;
                    }
                }
            }
        }

        // Small delay between queries
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    println!(
        "\nClient connection status: {}",
        if client.is_connected() {
            "Connected"
        } else {
            "Disconnected"
        }
    );

    Ok(())
}
