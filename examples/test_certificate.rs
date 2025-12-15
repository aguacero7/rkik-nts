//! Test certificate extraction from NTS-KE handshake
//!
//! This example demonstrates how to extract TLS certificate information
//! during the NTS-KE handshake process.

use rkik_nts::{NtsClient, NtsClientConfig};
use tracing::Level;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    println!("Testing NTS-KE certificate extraction\n");
    println!("=====================================\n");

    // Test with Cloudflare NTS server
    println!("Testing with time.cloudflare.com...\n");
    let config = NtsClientConfig::new("time.cloudflare.com");
    let mut client = NtsClient::new(config);

    match client.connect().await {
        Ok(_) => {
            println!("✓ Connected to NTS server successfully!\n");

            if let Some(ke_result) = client.nts_ke_info() {
                println!("NTS-KE handshake successful!");
                println!("NTP Server: {}", ke_result.ntp_server);
                println!("AEAD Algorithm: {}", ke_result.aead_algorithm);
                println!("Cookies received: {}", ke_result.cookie_count());
                println!("Handshake duration: {:?}", ke_result.ke_duration());

                if let Some(ref cert) = ke_result.certificate {
                    println!("\n=== TLS Certificate Information ===");
                    println!("Subject: {}", cert.subject);
                    println!("Issuer: {}", cert.issuer);
                    println!("Valid from: {}", cert.valid_from);
                    println!("Valid until: {}", cert.valid_until);
                    println!("Serial number: {}", cert.serial_number);
                    println!("Signature algorithm: {}", cert.signature_algorithm);
                    println!("Public key algorithm: {}", cert.public_key_algorithm);
                    println!("SHA-256 fingerprint: {}", cert.fingerprint_sha256);
                    println!("Is self-signed: {}", cert.is_self_signed);

                    if !cert.san_dns_names.is_empty() {
                        println!("\nSubject Alternative Names:");
                        for san in &cert.san_dns_names {
                            println!("  - {}", san);
                        }
                    }
                } else {
                    println!("\n⚠ WARNING: No certificate information captured!");
                }
            } else {
                println!("⚠ WARNING: No NTS-KE result available!");
            }
        }
        Err(e) => {
            eprintln!("Error during NTS synchronization: {}", e);
            return Err(e.into());
        }
    }

    println!("\n=====================================");
    println!("Test completed successfully!");

    Ok(())
}
