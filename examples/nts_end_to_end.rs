//! End-to-end NTS validation example.
//!
//! This example performs a full NTS-KE handshake, issues multiple NTS-protected
//! NTP queries, and asserts that responses are authenticated.
//!
//! Run with:
//!   cargo run --example nts_end_to_end --features tracing-subscriber

use rkik_nts::{NtsClient, NtsClientConfig};
use std::error::Error;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let server = std::env::var("NTS_SERVER").unwrap_or_else(|_| "time.cloudflare.com".to_string());

    println!("rkik-nts End-to-End NTS Validation\n");
    println!("Server: {}", server);

    let config = NtsClientConfig::new(&server).with_timeout(Duration::from_secs(10));
    let mut client = NtsClient::new(config);

    client.connect().await?;
    println!("Connected. NTP server: {}", client.ntp_server().unwrap());

    let initial_cookies = client.cookie_count();
    println!("Initial cookies: {}", initial_cookies);

    let time1 = client.get_time().await?;
    assert!(time1.authenticated, "first response not authenticated");
    println!("First response authenticated: {}", time1.authenticated);
    println!("First offset: {} ms", time1.offset_signed());

    let after_first = client.cookie_count();
    println!("Cookies after first query: {}", after_first);
    assert!(after_first > 0, "cookie pool exhausted after first query");

    let time2 = client.get_time().await?;
    assert!(time2.authenticated, "second response not authenticated");
    println!("Second response authenticated: {}", time2.authenticated);
    println!("Second offset: {} ms", time2.offset_signed());

    let after_second = client.cookie_count();
    println!("Cookies after second query: {}", after_second);
    assert!(after_second > 0, "cookie pool exhausted after second query");

    println!("\nNTS validation completed successfully.");

    Ok(())
}
