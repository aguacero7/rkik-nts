//! Network integration tests for rkik-nts.
//!
//! Requires live NTS servers. Disabled by default.
//! Run with: cargo test --features network-tests
#![cfg(feature = "network-tests")]

use rkik_nts::{Error, NtsClient, NtsClientConfig};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(15);

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "rkik_nts=debug".to_string()),
        )
        .try_init();
}

fn is_transient_network_error(err: &Error) -> bool {
    matches!(err, Error::Timeout | Error::ServerUnavailable(_))
}

#[tokio::test]
async fn test_nts_query_ntp_se() {
    let config = NtsClientConfig::new("nts.ntp.se").with_timeout(TIMEOUT);
    let mut client = NtsClient::new(config);
    client.connect().await.expect("NTS-KE to nts.ntp.se failed");
    let snap = client.get_time().await.expect("time query failed");
    assert!(snap.authenticated, "response must be NTS authenticated");
    assert!(snap.round_trip_delay.as_millis() > 0, "RTT should be positive");
    assert!(snap.round_trip_delay < Duration::from_secs(2), "RTT unreasonably large");
}

#[tokio::test]
async fn test_nts_query_cloudflare() {
    let config = NtsClientConfig::new("time.cloudflare.com").with_timeout(TIMEOUT);
    let mut client = NtsClient::new(config);
    client.connect().await.expect("NTS-KE to time.cloudflare.com failed");
    let snap = client.get_time().await.expect("time query failed");
    assert!(snap.authenticated);
    assert!(snap.round_trip_delay.as_millis() > 0);
}

#[tokio::test]
async fn test_nts_query_ptbtime() {
    init_tracing();
    let ptb_servers = [
        "ptbtime1.ptb.de",
        "ptbtime2.ptb.de",
        "ptbtime3.ptb.de",
        "ptbtime4.ptb.de",
    ];

    for server in ptb_servers {
        let config = NtsClientConfig::new(server).with_timeout(TIMEOUT);
        let mut client = NtsClient::new(config);

        match client.connect().await {
            Ok(()) => match client.get_time().await {
                Ok(snap) => {
                    assert!(snap.authenticated);
                    return;
                }
                Err(err) if is_transient_network_error(&err) => continue,
                Err(err) => panic!("PTB NTS query failed for {server}: {err}"),
            },
            Err(err) if is_transient_network_error(&err) => continue,
            Err(err) => panic!("PTB NTS-KE failed for {server}: {err}"),
        }
    }

    eprintln!("Skipping PTB network test: no PTB public server responded successfully");
}

#[tokio::test]
async fn test_nts_cookie_replenishment_across_queries() {
    let config = NtsClientConfig::new("nts.ntp.se").with_timeout(TIMEOUT);
    let mut client = NtsClient::new(config);
    client.connect().await.unwrap();
    let initial = client.cookie_count();
    assert!(initial >= 1, "should have cookies after connect");
    for i in 0..8 {
        client
            .get_time()
            .await
            .unwrap_or_else(|e| panic!("query {i} failed: {e}"));
        assert!(
            client.cookie_count() >= 1,
            "cookie pool exhausted after query {i}"
        );
    }
    assert!(client.cookie_count() >= 1);
}

#[tokio::test]
async fn test_nts_reconnect_replenishes_cookies() {
    let config = NtsClientConfig::new("nts.ntp.se").with_timeout(TIMEOUT);
    let mut client = NtsClient::new(config);
    client.connect().await.unwrap();
    client.reconnect().await.expect("reconnect failed");
    assert!(
        client.cookie_count() >= 4,
        "cookie pool should be replenished after reconnect, got {}",
        client.cookie_count()
    );
}

#[tokio::test]
async fn test_nts_is_connected_lifecycle() {
    let config = NtsClientConfig::new("nts.ntp.se").with_timeout(TIMEOUT);
    let mut client = NtsClient::new(config);
    assert!(!client.is_connected(), "should not be connected before connect()");
    client.connect().await.unwrap();
    assert!(client.is_connected(), "should be connected after connect()");
}
