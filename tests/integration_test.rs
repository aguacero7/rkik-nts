//! Integration tests for rkik-nts library.

use rkik_nts::{NtsClient, NtsClientConfig};
use std::time::Duration;

#[test]
fn test_config_builder() {
    let config = NtsClientConfig::new("time.cloudflare.com")
        .with_port(4460)
        .with_timeout(Duration::from_secs(10))
        .with_max_retries(3);

    assert_eq!(config.nts_ke_server, "time.cloudflare.com");
    assert_eq!(config.nts_ke_port, 4460);
    assert_eq!(config.timeout, Duration::from_secs(10));
    assert_eq!(config.max_retries, 3);
}

#[test]
fn test_config_default() {
    let config = NtsClientConfig::default();
    assert_eq!(config.nts_ke_port, 4460);
    assert_eq!(config.timeout, Duration::from_secs(10));
    assert_eq!(config.max_retries, 3);
    assert!(config.verify_tls_cert);
}

#[test]
fn test_config_with_ntp_version() {
    let config_v3 = NtsClientConfig::new("time.cloudflare.com").with_ntp_version(3);
    assert_eq!(config_v3.ntp_version, 3);

    let config_v4 = NtsClientConfig::new("time.cloudflare.com").with_ntp_version(4);
    assert_eq!(config_v4.ntp_version, 4);
}

#[test]
fn test_client_creation() {
    let config = NtsClientConfig::new("time.cloudflare.com");
    let client = NtsClient::new(config);

    assert!(!client.is_connected());
    assert!(client.ntp_server().is_none());
}

// Note: The following tests require network connectivity and are marked as ignored by default.
// Run with: cargo test -- --ignored

#[tokio::test]
#[ignore]
async fn test_connect_to_cloudflare() {
    let config = NtsClientConfig::new("time.cloudflare.com").with_timeout(Duration::from_secs(10));

    let mut client = NtsClient::new(config);

    match client.connect().await {
        Ok(_) => {
            assert!(client.is_connected());
            assert!(client.ntp_server().is_some());
        }
        Err(e) => {
            eprintln!(
                "Connection failed (this is expected if network is unavailable): {}",
                e
            );
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_get_time() {
    let config = NtsClientConfig::new("time.cloudflare.com").with_timeout(Duration::from_secs(10));

    let mut client = NtsClient::new(config);

    if client.connect().await.is_ok() {
        match client.get_time().await {
            Ok(time) => {
                assert!(time.authenticated);
                println!("Time offset: {} ms", time.offset_signed());
                println!("Round-trip delay: {:?}", time.round_trip_delay);
            }
            Err(e) => {
                eprintln!("Time query failed: {}", e);
            }
        }
    }
}
