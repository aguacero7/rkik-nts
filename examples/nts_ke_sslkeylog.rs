//! Example to capture NTS-KE traffic with SSLKEYLOG for Wireshark decryption
//!
//! This example enables TLS key logging to allow Wireshark to decrypt the TLS traffic
//! and see the actual NTS-KE records (not just encrypted TLS Application Data).
//!
//! Usage:
//! 1. Terminal 1: sudo tcpdump -i any -w /tmp/nts-ke.pcap port 4460
//! 2. Terminal 2: SSLKEYLOGFILE=/tmp/sslkeys.log cargo run --example nts_ke_sslkeylog --features tracing-subscriber
//! 3. Open Wireshark: wireshark /tmp/nts-ke.pcap
//!    - Edit → Preferences → Protocols → TLS
//!    - Set "(Pre)-Master-Secret log filename" to /tmp/sslkeys.log
//! 4. You should now see decrypted NTS-KE records!

use rkik_nts::{NtsClient, NtsClientConfig};
use std::error::Error;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("=== NTS-KE Traffic Capture avec SSLKEYLOG ===\n");

    // Check if SSLKEYLOGFILE is set
    match std::env::var("SSLKEYLOGFILE") {
        Ok(path) => {
            println!("✓ SSLKEYLOGFILE défini : {}", path);
            println!("  Les clés TLS seront enregistrées pour déchiffrement dans Wireshark\n");
        }
        Err(_) => {
            eprintln!("⚠  AVERTISSEMENT : SSLKEYLOGFILE n'est pas défini !");
            eprintln!("   Pour déchiffrer le trafic dans Wireshark, exécutez :");
            eprintln!("   SSLKEYLOGFILE=/tmp/sslkeys.log cargo run --example nts_ke_sslkeylog --features tracing-subscriber\n");
        }
    }

    println!("Instructions pour la capture :\n");
    println!("1. Dans un autre terminal, lancer :");
    println!("   sudo tcpdump -i any -w /tmp/nts-ke.pcap port 4460\n");
    println!("2. Attendre 5 secondes pour que vous puissiez démarrer tcpdump...");

    // Wait for user to start tcpdump
    for i in (1..=5).rev() {
        println!("   Début dans {} secondes...", i);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    println!("\n3. Démarrage de la connexion NTS-KE...\n");

    let server = "time.cloudflare.com";
    println!("Serveur cible : {}", server);
    println!("{}\n", "=".repeat(60));

    // Configure NTS client
    let config = NtsClientConfig::new(server).with_timeout(Duration::from_secs(10));

    let mut client = NtsClient::new(config);

    // Perform NTS-KE
    println!("Phase 1 : NTS-KE (Key Exchange)...");
    match client.connect().await {
        Ok(_) => {
            println!("✓ NTS-KE réussi !\n");

            if let Some(ke_info) = client.nts_ke_info() {
                println!("Informations NTS-KE :");
                println!("  Serveur NTP :     {}", ke_info.ntp_server);
                println!("  Algorithme AEAD : {}", ke_info.aead_algorithm);
                println!("  Durée KE :        {:?}", ke_info.ke_duration);
                println!(
                    "  Cookies :         {}",
                    ke_info.initial_cookie_count
                );
            }
        }
        Err(e) => {
            eprintln!("✗ Erreur NTS-KE : {}", e);
            return Ok(());
        }
    }

    // Perform NTP query
    println!("\nPhase 2 : Requête NTP (avec cookie NTS)...");
    match client.get_time().await {
        Ok(time) => {
            println!("✓ Requête NTP réussie !\n");
            println!("Résultats :");
            println!("  Temps réseau :    {:?}", time.network_time);
            println!("  Temps système :   {:?}", time.system_time);
            println!("  Offset :          {} ms", time.offset_signed());
            println!("  Authentifié :     {}", time.authenticated);
        }
        Err(e) => {
            eprintln!("✗ Erreur NTP : {}", e);
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("Capture terminée !\n");
    println!("Pour analyser la capture dans Wireshark :\n");
    println!("1. Arrêter tcpdump (Ctrl+C)");
    println!("2. Ouvrir Wireshark :");
    println!("   wireshark /tmp/nts-ke.pcap\n");
    println!("3. Configurer le déchiffrement TLS :");
    println!("   Edit → Preferences → Protocols → TLS");
    if let Ok(path) = std::env::var("SSLKEYLOGFILE") {
        println!("   (Pre)-Master-Secret log filename : {}", path);
    } else {
        println!("   (Pre)-Master-Secret log filename : /tmp/sslkeys.log");
    }
    println!("\n4. Filtres Wireshark utiles :");
    println!("   tcp.port == 4460           # Tout le trafic NTS-KE");
    println!("   tls.handshake.extensions_alpn_str == \"ntske/1\"  # ALPN");
    println!("   tls.app_data               # Données applicatives (NTS-KE records)");
    println!("\n5. Vous devriez voir les records NTS-KE déchiffrés :");
    println!("   - End of Message (type 0)");
    println!("   - NTS Next Protocol Negotiation (type 1)");
    println!("   - AEAD Algorithm Negotiation (type 4)");
    println!("   - New Cookie for NTPv4 (type 5)");
    println!("   - NTPv4 Server Negotiation (type 6)");

    Ok(())
}
