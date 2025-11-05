//! Example showing how rkik can use rkik-nts for NTS diagnostics.
//!
//! This demonstrates all the diagnostic information available from the library
//! that rkik can use for NTS inspection and troubleshooting.
//!
//! Run with: cargo run --example rkik_diagnostics --features tracing-subscriber

use rkik_nts::{NtsClient, NtsClientConfig};
use std::error::Error;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging to see internal details
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("=== rkik-nts Diagnostic Example ===\n");
    println!("This shows all diagnostic information available for rkik integration\n");

    let server = "time.cloudflare.com";
    println!("Target server: {}\n", server);

    // Configure the NTS client
    let config = NtsClientConfig::new(server)
        .with_timeout(Duration::from_secs(10))
        .with_max_retries(3);

    let mut client = NtsClient::new(config);

    // Phase 1: NTS Key Exchange Diagnostics
    println!("─────────────────────────────────────────");
    println!("Phase 1: NTS Key Exchange (NTS-KE)");
    println!("─────────────────────────────────────────\n");

    match client.connect().await {
        Ok(_) => {
            println!("✓ NTS-KE successful\n");

            // Access NTS-KE diagnostic information
            if let Some(ke_info) = client.nts_ke_info() {
                println!("NTS-KE Diagnostics:");
                println!("  NTP Server:      {}", ke_info.ntp_server);
                println!("  AEAD Algorithm:  {}", ke_info.aead_algorithm);
                println!("  KE Duration:     {:?}", ke_info.ke_duration());
                println!("  Cookie Count:    {}", ke_info.cookie_count());
                println!("  Cookie Sizes:    {:?} bytes", ke_info.cookie_sizes());

                // Verbose mode: Show raw cookie data (first few bytes)
                println!("\n  Cookies (hex preview):");
                for (i, cookie) in ke_info.cookies_ref().iter().enumerate() {
                    let preview: Vec<String> = cookie
                        .iter()
                        .take(16)
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    println!(
                        "    Cookie {}: {} {}",
                        i + 1,
                        preview.join(" "),
                        if cookie.len() > 16 { "..." } else { "" }
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("✗ NTS-KE failed: {}", e);
            println!(
                "\nDiagnostic hint: Check firewall, DNS resolution, and port 4460 accessibility"
            );
            return Ok(());
        }
    }

    // Phase 2: NTP Time Query Diagnostics
    println!("\n─────────────────────────────────────────");
    println!("Phase 2: NTP Time Query (NTS-secured)");
    println!("─────────────────────────────────────────\n");

    match client.get_time().await {
        Ok(time) => {
            println!("✓ Time query successful\n");

            println!("Time Synchronization:");
            println!("  System Time:     {:?}", time.system_time);
            println!("  Network Time:    {:?}", time.network_time);
            println!("  Offset:          {} ms", time.offset_signed());
            println!("  Offset (abs):    {:?}", time.offset);
            println!("  Round-trip:      {:?}", time.round_trip_delay);
            println!("  Server:          {}", time.server);
            println!("  Authenticated:   {} ✓", time.authenticated);

            println!("\nClock Status:");
            if time.is_ahead() {
                println!("  ⚠  System clock is AHEAD by {} ms", time.offset_signed());
            } else if time.is_behind() {
                println!(
                    "  ⚠  System clock is BEHIND by {} ms",
                    time.offset_signed().abs()
                );
            } else {
                println!("  ✓  System clock is synchronized");
            }

            // Accuracy assessment
            let offset_ms = time.offset_signed().abs();
            println!("\nAccuracy Assessment:");
            if offset_ms < 10 {
                println!("  ✓ Excellent (< 10ms offset)");
            } else if offset_ms < 100 {
                println!("  ✓ Good (< 100ms offset)");
            } else if offset_ms < 1000 {
                println!("  ⚠ Acceptable (< 1s offset)");
            } else {
                println!("  ✗ Poor (> 1s offset) - Consider syncing");
            }
        }
        Err(e) => {
            eprintln!("✗ Time query failed: {}", e);
            println!("\nDiagnostic hint: Check UDP port 123 accessibility and firewall rules");
        }
    }

    // Phase 3: Multiple Queries for Statistical Analysis
    println!("\n─────────────────────────────────────────");
    println!("Phase 3: Statistical Analysis (5 samples)");
    println!("─────────────────────────────────────────\n");

    let mut offsets = Vec::new();
    let mut rtts = Vec::new();

    for i in 1..=5 {
        tokio::time::sleep(Duration::from_millis(200)).await;

        if let Ok(time) = client.get_time().await {
            let offset = time.offset_signed();
            let rtt = time.round_trip_delay.as_millis();
            offsets.push(offset);
            rtts.push(rtt);

            println!("  Sample {}: offset={:+6} ms, RTT={:4} ms", i, offset, rtt);
        }
    }

    if !offsets.is_empty() {
        let avg_offset: i64 = offsets.iter().sum::<i64>() / offsets.len() as i64;
        let avg_rtt: u128 = rtts.iter().sum::<u128>() / rtts.len() as u128;

        let variance: i64 = offsets
            .iter()
            .map(|&x| (x - avg_offset).pow(2))
            .sum::<i64>()
            / offsets.len() as i64;
        let std_dev = (variance as f64).sqrt();

        println!("\nStatistics:");
        println!("  Average Offset:  {:+6} ms", avg_offset);
        println!("  Std Deviation:   {:6.2} ms", std_dev);
        println!("  Average RTT:     {:4} ms", avg_rtt);
        println!("  Sample Count:    {}", offsets.len());
    }

    // Phase 4: Connection Status Summary
    println!("\n─────────────────────────────────────────");
    println!("Phase 4: Connection Summary");
    println!("─────────────────────────────────────────\n");

    println!("Connection Status:");
    println!("  Connected:       {}", client.is_connected());
    if let Some(server_addr) = client.ntp_server() {
        println!("  Active Server:   {}", server_addr);
    }

    if let Some(ke_info) = client.nts_ke_info() {
        println!("\nSecurity:");
        println!("  Protocol:        NTS (Network Time Security)");
        println!("  Encryption:      {}", ke_info.aead_algorithm);
        println!("  Cookies Cached:  {}", ke_info.cookie_count());
        println!("  Auth Status:     ✓ Authenticated");
    }

    println!("\n─────────────────────────────────────────");
    println!("Diagnostic Report Complete");
    println!("─────────────────────────────────────────");

    Ok(())
}
