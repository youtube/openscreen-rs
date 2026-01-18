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

//! OpenScreen Application Protocol Sender with mDNS Discovery
//!
//! This binary:
//! 1. Discovers OpenScreen receivers via mDNS
//! 2. Prompts user to select a device
//! 3. Connects and authenticates via SPAKE2
//! 4. Exchanges agent-info messages

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use openscreen_application::messages::{AgentInfoRequest, AgentInfoResponse};
use openscreen_crypto_rustcrypto::RustCryptoCryptoProvider;
use openscreen_discovery::{DiscoveryBrowser, ServiceInfo};
use openscreen_discovery_mdns::MdnsBrowser;
use openscreen_quinn::QuinnClient;
use std::time::Duration;
use tracing::{debug, error, info};

#[derive(Parser, Debug)]
#[command(name = "app-sender")]
#[command(about = "OpenScreen Application Protocol Sender with mDNS Discovery", long_about = None)]
struct Args {
    /// Pre-shared key (PSK) for authentication
    #[arg(short = 'k', long, default_value = "test-psk")]
    psk: String,

    /// Discovery timeout in seconds
    #[arg(short, long, default_value_t = 3)]
    discovery_timeout: u64,

    /// Request ID for agent-info-request
    #[arg(short, long, default_value_t = 1)]
    request_id: u64,

    /// Skip discovery and connect directly to hostname:port (for testing without mDNS)
    #[arg(long)]
    direct_host: Option<String>,

    /// Port for direct connection (requires --direct-host)
    #[arg(long, default_value_t = 4433)]
    direct_port: u16,

    /// Expected certificate fingerprint for direct connection (hex string, for testing/debugging)
    #[arg(long)]
    expected_fingerprint: Option<String>,

    /// Authentication token for direct connection (for testing/debugging)
    #[arg(long)]
    auth_token: Option<String>,

    /// mDNS port (5353 for production, custom port like 5454 for development to avoid macOS Bonjour conflict)
    #[arg(long, default_value_t = 5353)]
    mdns_port: u16,
}

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
        "=== OpenScreen Sender with mDNS Discovery ==="
            .bright_cyan()
            .bold()
    );
    println!();

    match run_sender(&args).await {
        Ok(()) => {
            println!();
            println!(
                "{}",
                "OK: Test completed successfully!".bright_green().bold()
            );
            Ok(())
        }
        Err(e) => {
            println!();
            error!("Test failed: {:?}", e);
            println!("{} {:?}", "FAIL: Test failed:".bright_red().bold(), e);
            std::process::exit(1);
        }
    }
}

/// Run the sender with device discovery and connection
#[allow(clippy::too_many_lines)]
async fn run_sender(args: &Args) -> Result<()> {
    // Step 1: Device discovery or direct connection
    let (service_info, ip_address) = if let Some(host) = &args.direct_host {
        println!("- Using direct connection");
        println!("  Host: {host}");
        println!("  Port: {}", args.direct_port);

        let ip_address: core::net::IpAddr = host
            .parse()
            .context("Failed to parse direct host as IP address")?;

        // Parse fingerprint if provided, otherwise use dummy (all zeros)
        let fingerprint = if let Some(fp_hex) = &args.expected_fingerprint {
            println!("  Expected fingerprint: {}", &fp_hex[..16].bright_cyan());

            // Parse hex string to bytes
            let fp_bytes =
                hex::decode(fp_hex).context("Failed to parse fingerprint as hex string")?;

            if fp_bytes.len() != 32 {
                anyhow::bail!(
                    "Fingerprint must be exactly 32 bytes (64 hex chars), got {} bytes",
                    fp_bytes.len()
                );
            }

            let mut fp_array = [0u8; 32];
            fp_array.copy_from_slice(&fp_bytes);
            openscreen_discovery::Fingerprint::from_bytes(fp_array)
        } else {
            println!("  WARN: No fingerprint provided (will accept any cert)",);
            openscreen_discovery::Fingerprint::from_bytes([0u8; 32])
        };
        println!();

        // Parse auth token if provided
        let auth_token = if let Some(token) = &args.auth_token {
            println!("  Auth token: {}", token.bright_cyan());
            openscreen_discovery::AuthToken::from_string(token.clone())
        } else {
            println!("  WARN: No auth token provided");
            openscreen_discovery::AuthToken::from_string(String::new())
        };

        // Create a ServiceInfo for direct connection
        let service_info = ServiceInfo {
            instance_name: host.clone(),
            display_name: host.clone(),
            ip_address,
            port: args.direct_port,
            fingerprint,
            metadata_version: 1,
            auth_token,
            discovered_at: std::time::SystemTime::now(),
        };
        (service_info, ip_address)
    } else {
        // Discover devices via mDNS
        println!("WAIT: Discovering OpenScreen receivers...");

        let mut browser =
            MdnsBrowser::new_with_port(args.mdns_port).context("Failed to create mDNS browser")?;
        browser
            .start_browsing()
            .await
            .context("Failed to start browsing")?;

        // Wait for discovery
        tokio::time::sleep(Duration::from_secs(args.discovery_timeout)).await;

        let services = browser.discovered_services();

        if services.is_empty() {
            return Err(anyhow::anyhow!(
                "No OpenScreen receivers found after {} seconds",
                args.discovery_timeout
            ));
        }

        println!("OK: Found {} receiver(s)", services.len());
        println!();

        // Display discovered devices
        println!("{}", "Available Receivers:".bright_cyan().bold());
        for (i, service) in services.iter().enumerate() {
            println!(
                "{} {} - {} ({}:{})",
                format!("[{}]", i + 1).bright_white().bold(),
                service.display_name.bright_white(),
                &service.fingerprint.to_hex()[..16],
                service.ip_address,
                service.port
            );
        }
        println!();

        // Select device (for now, just use the first one)
        let selected = &services[0];
        println!(
            "-> Selected: {}",
            selected.display_name.bright_white().bold()
        );
        println!();

        let ip_address = selected.ip_address;

        (selected.clone(), ip_address)
    };

    // Step 2: Create Quinn client with expected fingerprint
    print!("{}", "WAIT: Initializing QUIC client... ".bright_yellow());
    std::io::Write::flush(&mut std::io::stdout())?;

    let crypto_provider = RustCryptoCryptoProvider::new();
    let bind_addr = "0.0.0.0:0".parse().unwrap();

    // Get expected fingerprint from mDNS discovery (for MITM protection)
    let expected_fingerprint = *service_info.fingerprint.as_bytes();

    let mut client = QuinnClient::new(crypto_provider, bind_addr, expected_fingerprint)
        .context("Failed to create Quinn client")?;

    println!("OK:");
    debug!(
        "Quinn client initialized with bind address {} and fingerprint verification",
        bind_addr
    );

    // Step 3: Configure PSK and auth token
    print!("{}", "WAIT: Configuring authentication... ".bright_yellow());
    std::io::Write::flush(&mut std::io::stdout())?;

    client
        .set_psk(args.psk.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to set PSK: {e:?}"))?;

    if !service_info.auth_token.as_str().is_empty() {
        client
            .set_auth_token(service_info.auth_token.as_str().as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to set auth token: {e:?}"))?;
    }

    println!("OK:");
    debug!("PSK and auth token configured");

    // Step 4: Connect and authenticate
    // Fingerprint verification now happens during TLS handshake
    print!(
        "{}",
        "WAIT: Connecting to receiver (QUIC + TLS + SPAKE2)... ".bright_yellow()
    );
    std::io::Write::flush(&mut std::io::stdout())?;

    let server_addr = core::net::SocketAddr::new(ip_address, service_info.port);

    match client.connect(server_addr, &ip_address.to_string()).await {
        Ok(()) => {
            println!("OK:");
            info!("QUIC connection and authentication complete");
        }
        Err(e) => {
            println!("FAIL:");
            return Err(anyhow::anyhow!("Connection failed: {e:?}"));
        }
    }

    // Step 5: Verify authentication
    if !client.is_authenticated() {
        return Err(anyhow::anyhow!("Authentication did not complete"));
    }

    // Step 6: Send agent-info-request
    print!("{}", "WAIT: Sending agent-info-request... ".bright_yellow());
    std::io::Write::flush(&mut std::io::stdout())?;

    let request = AgentInfoRequest {
        request_id: args.request_id,
    };
    let mut buf = heapless::Vec::<u8, 1024>::new();
    request
        .encode(&mut buf)
        .map_err(|e| anyhow::anyhow!("Failed to encode request: {e:?}"))?;

    client
        .send_application_data(&buf)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send request: {e:?}"))?;

    println!("OK: {} bytes", buf.len());
    info!(
        "Sent agent-info-request (request_id={}, {} bytes)",
        args.request_id,
        buf.len()
    );

    // Step 7: Receive agent-info-response
    print!(
        "{}",
        "WAIT: Waiting for agent-info-response... ".bright_yellow()
    );
    std::io::Write::flush(&mut std::io::stdout())?;

    let response_data = client
        .receive_application_data()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to receive response: {e:?}"))?;

    println!("OK: Received {} bytes", response_data.len());
    info!(
        "Received agent-info-response ({} bytes)",
        response_data.len()
    );

    // Step 8: Decode and display response
    let response = AgentInfoResponse::decode(&response_data)
        .map_err(|e| anyhow::anyhow!("Failed to decode response: {e:?}"))?;

    println!();
    println!("{}", "=== Agent Info Response ===".bright_cyan().bold());
    println!();
    println!("{:20} {}", "Request ID:", response.request_id);
    println!(
        "{:20} {}",
        "Display Name:", response.agent_info.display_name
    );
    println!("{:20} {}", "Model Name:", response.agent_info.model_name);
    println!("{:20} {}", "State Token:", response.agent_info.state_token);

    Ok(())
}
