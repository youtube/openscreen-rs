// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! OpenScreen Application Protocol Receiver with mDNS Discovery
//!
//! This binary:
//! 1. Generates/loads a self-signed certificate
//! 2. Advertises itself via mDNS
//! 3. Accepts OpenScreen connections and authenticates via SPAKE2
//! 4. Handles agent-info messages

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use openscreen_application::cert::CertificateKey;
use openscreen_application::messages::{AgentInfo, AgentInfoRequest, AgentInfoResponse};
use openscreen_discovery::{AuthToken, DiscoveryPublisher, PublishInfo};
use openscreen_discovery_mdns::MdnsPublisher;
use openscreen_quinn::QuinnServer;
use std::path::PathBuf;
use tracing::{debug, error, info};

#[derive(Parser, Debug)]
#[command(name = "app-receiver")]
#[command(about = "OpenScreen Application Protocol Receiver with mDNS Discovery", long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 4433)]
    port: u16,

    /// Pre-shared key (PSK) for authentication
    #[arg(short = 'k', long, default_value = "test-psk")]
    psk: String,

    /// Friendly display name for this receiver
    #[arg(long, default_value = "OpenScreen Test Receiver")]
    name: String,

    /// Directory for certificate storage
    #[arg(long, default_value = ".openscreen")]
    cert_dir: PathBuf,

    /// Disable mDNS advertising (for testing without discovery)
    #[arg(long)]
    no_mdns: bool,

    /// mDNS port (5353 for production, custom port like 5454 for development to avoid macOS Bonjour conflict)
    #[arg(long, default_value_t = 5353)]
    mdns_port: u16,
}

#[allow(clippy::large_futures)]
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    println!();
    println!(
        "{}",
        "=== OpenScreen Receiver with mDNS Discovery ==="
            .bright_cyan()
            .bold()
    );
    println!("{}: {}", "Name".bright_white(), args.name.bright_white());
    println!("{}: {}", "Port".bright_white(), args.port);
    println!();

    match run_receiver(&args).await {
        Ok(()) => {
            println!();
            println!("OK: Receiver stopped");
            Ok(())
        }
        Err(e) => {
            println!();
            error!("Receiver failed: {:?}", e);
            println!("FAIL: {e:?}");
            std::process::exit(1);
        }
    }
}

/// Run the OpenScreen application receiver
#[allow(clippy::large_futures)]
async fn run_receiver(args: &Args) -> Result<()> {
    // Step 1: Load or generate certificate
    println!("WAIT: Loading certificate...");
    let cert_key = CertificateKey::load_or_generate(&args.cert_dir, &args.name, "local")
        .context("Failed to load/generate certificate")?;

    println!("OK: Certificate loaded");
    println!(
        "   Fingerprint: {}",
        cert_key.fingerprint.to_hex()[..16].bright_white()
    );
    println!("   Hostname: {}", cert_key.hostname.bright_white());
    println!();

    // Step 2: Generate authentication token (for off-network attack prevention)
    let auth_token = AuthToken::generate();
    println!("OK: Auth token: {}", auth_token.as_str().bright_white());
    println!();

    // Step 3: Advertise via mDNS (unless disabled)
    let mdns_publisher = if args.no_mdns {
        println!("- mDNS advertising disabled");
        println!();
        None
    } else {
        println!("WAIT: Starting mDNS advertising...");
        let mut publisher = MdnsPublisher::new_with_port(args.mdns_port)
            .context("Failed to create mDNS publisher")?;

        let publish_info = PublishInfo {
            display_name: args.name.clone(),
            port: args.port,
            fingerprint: cert_key.fingerprint,
            metadata_version: 1,
            auth_token: auth_token.clone(),
            hostname: cert_key.hostname.clone(),
        };

        publisher
            .publish(publish_info)
            .await
            .context("Failed to publish mDNS service")?;

        println!(
            "OK: mDNS service published: {}._openscreen._udp.local.",
            args.name.bright_white()
        );
        println!();

        Some(publisher)
    };

    // Step 4: Start QUIC server
    let bind_addr = format!("0.0.0.0:{}", args.port)
        .parse::<core::net::SocketAddr>()
        .context("Invalid bind address")?;

    println!("WAIT: Initializing QUIC server...");

    // Pass certificate and key to Quinn
    let (cert_der, key_der) = (cert_key.cert_der, cert_key.key_der);

    // Pass auth token to server for validation
    let auth_token_bytes = Some(auth_token.as_str().as_bytes().to_vec());

    let server = QuinnServer::bind(bind_addr, &args.psk, cert_der, key_der, auth_token_bytes)
        .await
        .context("Failed to bind server")?;

    println!("OK: Listening on {bind_addr}");
    println!("{}", "Waiting for connections...".bright_cyan());
    println!();

    // Accept and handle connections
    while let Some(result) = server.accept().await {
        match result {
            Ok(connection) => {
                let remote_addr = connection.remote_address();
                println!(
                    "New connection from {}",
                    remote_addr.to_string().bright_white()
                );
                println!("  OK: Client authenticated!");
                info!("Client {} authenticated", remote_addr);

                // Spawn handler for this connection
                let receiver_name = args.name.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(connection, receiver_name).await {
                        error!("Connection handler failed: {:?}", e);
                        println!("  FAIL: Handler failed: {e:?}");
                    }
                });
            }
            Err(e) => {
                error!("Failed to authenticate connection: {:?}", e);
                println!("  FAIL: Auth failed: {e:?}");
            }
        }
    }

    // Cleanup: Unpublish mDNS service
    if let Some(mut publisher) = mdns_publisher {
        let _ = publisher.unpublish().await;
    }

    Ok(())
}

/// Handle an authenticated connection
async fn handle_connection(
    mut connection: openscreen_quinn::AuthenticatedConnection,
    receiver_name: String,
) -> Result<()> {
    let remote_addr = connection.remote_address();
    info!("Handling connection from {}", remote_addr);

    println!("WAIT: Waiting for agent-info-request...");

    // Receive agent-info-request
    let request_data = connection
        .receive_message()
        .await
        .context("Failed to receive message")?;

    debug!("Received {} bytes", request_data.len());

    // Decode agent-info-request
    let request = AgentInfoRequest::decode(&request_data)
        .map_err(|e| anyhow::anyhow!("Failed to decode request: {e:?}"))?;

    println!(
        "OK: Received agent-info-request (id={})",
        request.request_id
    );
    info!("Agent-info-request: id={}", request.request_id);

    // Build agent-info-response
    let agent_info = AgentInfo {
        display_name: &receiver_name,
        model_name: "OpenScreen Test Receiver",
        capabilities: heapless::Vec::new(),
        state_token: "ready",
        locales: heapless::Vec::new(),
    };

    let response = AgentInfoResponse {
        request_id: request.request_id,
        agent_info,
    };

    // Encode response
    let mut response_buf = heapless::Vec::<u8, 1024>::new();
    response
        .encode(&mut response_buf)
        .map_err(|e| anyhow::anyhow!("Failed to encode response: {e:?}"))?;

    // Send response
    connection
        .send_message(&response_buf)
        .await
        .context("Failed to send response")?;

    println!(
        "OK: Sent agent-info-response ({} bytes)",
        response_buf.len()
    );
    info!("Sent agent-info-response: id={}", request.request_id);

    // Keep connection alive
    info!("Keeping connection alive from {}", remote_addr);
    loop {
        if connection.is_closed() {
            info!("Connection from {} closed", remote_addr);
            println!("  - Connection closed");
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    Ok(())
}
