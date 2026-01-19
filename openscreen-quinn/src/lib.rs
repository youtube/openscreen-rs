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

//! OpenScreen Network Protocol implementation using Quinn (pure Rust QUIC)
//!
//! This crate provides the glue between the no_std Sans-IO `openscreen-network`
//! protocol implementation and the Quinn QUIC library.
//!

#![allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::large_futures,
    clippy::unused_async
)]
//! # Architecture
//!
//! The Quinn adapter follows the Sans-IO pattern:
//! - `NetworkState` is the pure no_std state machine
//! - `QuinnClient` wraps Quinn and drives the state machine
//! - `QuinnServer` provides listener-style API for accepting connections
//! - Crypto operations are executed via `CryptoProvider`
//! - All I/O is handled by Quinn and Tokio

pub mod server;

use openscreen_crypto::CryptoProvider;
use openscreen_network::{
    state_machine::Spake2StateMachine, CryptoData, NetworkError, NetworkInput, NetworkOutput,
};
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, trace};

pub use openscreen_network;
pub use server::{AuthenticatedConnection, QuinnServer};

/// Errors that can occur in the Quinn adapter
#[derive(Debug, Error)]
pub enum QuinnError {
    #[error("Network protocol error: {0:?}")]
    Protocol(NetworkError),

    #[error("Quinn connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("Quinn connect error: {0}")]
    ConnectError(#[from] quinn::ConnectError),

    #[error("Quinn write error: {0}")]
    WriteError(#[from] quinn::WriteError),

    #[error("Quinn read error: {0}")]
    ReadError(#[from] quinn::ReadError),

    #[error("Quinn closed stream: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),

    #[error("Quinn read to end error: {0}")]
    ReadToEndError(#[from] quinn::ReadToEndError),

    #[error("TLS configuration error: {0}")]
    Tls(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Crypto operation failed")]
    Crypto,

    #[error("Not connected")]
    NotConnected,
}

impl From<NetworkError> for QuinnError {
    fn from(e: NetworkError) -> Self {
        QuinnError::Protocol(e)
    }
}

/// Quinn-based OpenScreen Network Protocol client
///
/// This client handles:
/// - QUIC connection establishment
/// - TLS configuration with ALPN "osp"
/// - Unidirectional stream management
/// - Sans-IO state machine integration
/// - Crypto operations via CryptoProvider
pub struct QuinnClient<C: CryptoProvider> {
    /// QUIC endpoint
    endpoint: Endpoint,
    /// Active QUIC connection (if connected)
    connection: Option<quinn::Connection>,
    /// Network protocol state machine (owns CryptoData internally)
    network_state: Spake2StateMachine,
    /// Crypto provider for executing crypto operations
    crypto_provider: C,
    /// Our TLS certificate (for computing fingerprint)
    local_cert_der: Vec<u8>,
}

impl<C: CryptoProvider> QuinnClient<C> {
    /// Create a new Quinn client with fingerprint verification
    ///
    /// # Arguments
    /// * `crypto_provider` - Implementation of CryptoProvider for crypto operations
    /// * `bind_addr` - Local address to bind to (typically "0.0.0.0:0")
    /// * `expected_fingerprint` - Expected SPKI fingerprint from mDNS discovery (for MITM protection)
    ///
    /// # Returns
    /// * `Ok(QuinnClient)` - Client successfully created
    /// * `Err(QuinnError)` - Failed to create client
    ///
    /// # Security Note
    ///
    /// The `expected_fingerprint` MUST be the fingerprint from mDNS discovery (`fp=` TXT record).
    /// The TLS handshake will reject connections to servers with mismatched fingerprints.
    pub fn new(
        crypto_provider: C,
        bind_addr: SocketAddr,
        expected_fingerprint: [u8; 32],
    ) -> Result<Self, QuinnError> {
        // Generate self-signed certificate for the client
        // This is required for TLS fingerprint extraction per RFC 9382
        debug!("Generating self-signed client certificate");
        let cert = rcgen::generate_simple_self_signed(vec!["openscreen-client".into()])
            .map_err(|e| QuinnError::Tls(format!("Failed to generate certificate: {e}")))?;

        let cert_der = cert.cert.der().to_vec();
        let priv_key_der = cert.key_pair.serialize_der();

        // Create TLS client config with ALPN "osp"
        // Use FingerprintVerifier to reject mismatched fingerprints during TLS handshake
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FingerprintVerifier::new(
                expected_fingerprint,
            )))
            .with_client_auth_cert(
                vec![CertificateDer::from(cert_der.clone())],
                rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key_der.into()),
            )
            .map_err(|e| QuinnError::Tls(format!("Failed to configure TLS: {e}")))?;

        crypto.alpn_protocols = vec![b"osp".to_vec()];

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| QuinnError::Tls(e.to_string()))?,
        ));

        let mut endpoint =
            Endpoint::client(bind_addr).map_err(|e| QuinnError::Tls(e.to_string()))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            connection: None,
            network_state: Spake2StateMachine::new(CryptoData::new()),
            crypto_provider,
            local_cert_der: cert_der,
        })
    }

    /// Set the pre-shared key (PSK) for authentication
    pub fn set_psk(&mut self, psk: &[u8]) -> Result<(), NetworkError> {
        self.network_state.crypto_data_mut().set_psk(psk)
    }

    /// Set the authentication token from mDNS
    pub fn set_auth_token(&mut self, token: &[u8]) -> Result<(), NetworkError> {
        self.network_state.crypto_data_mut().set_auth_token(token)
    }

    /// Check if authenticated
    pub fn is_authenticated(&self) -> bool {
        self.network_state.is_authenticated()
    }

    /// Connect to a remote OpenScreen receiver
    ///
    /// # Arguments
    /// * `server_addr` - Address of the OpenScreen receiver
    /// * `server_name` - Server name for SNI (typically the hostname)
    ///
    /// # Returns
    /// * `Ok(())` - Successfully connected and authenticated
    /// * `Err(QuinnError)` - Connection or authentication failed
    ///
    /// # Security Note
    ///
    /// Fingerprint verification happens during the TLS handshake (via `FingerprintVerifier`).
    /// If the server's certificate fingerprint doesn't match the expected fingerprint provided
    /// at construction time, the TLS handshake will fail with a clear error message.
    pub async fn connect(
        &mut self,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<(), QuinnError> {
        // Establish QUIC connection with fingerprint verification
        // FingerprintVerifier will reject mismatched fingerprints during TLS handshake
        debug!("Connecting to {}...", server_addr);
        let connection = self.endpoint.connect(server_addr, server_name)?.await?;

        let conn_id = format!("{:?}", connection.stable_id());
        info!(
            "[CONN:{}] QUIC connection established to {} (fingerprint verified during TLS handshake)",
            conn_id, server_addr
        );
        self.connection = Some(connection.clone());

        // Extract TLS certificate fingerprints (RFC 9382 requirement)
        debug!("Extracting TLS certificate fingerprints");

        // Get peer certificate fingerprint (already verified during TLS handshake)
        let peer_fingerprint = get_peer_certificate_fingerprint(&connection)?;
        debug!(
            "Peer certificate SPKI fingerprint: {}",
            hex::encode(peer_fingerprint)
        );

        // Compute local certificate SPKI fingerprint
        let local_fingerprint = compute_spki_fingerprint(&self.local_cert_der).map_err(|e| {
            QuinnError::Tls(format!("Failed to compute local SPKI fingerprint: {e}"))
        })?;
        debug!(
            "Local certificate SPKI fingerprint: {}",
            hex::encode(local_fingerprint)
        );

        // Set fingerprints in CryptoData
        let crypto_data = self.network_state.crypto_data_mut();
        crypto_data
            .set_my_fingerprint(&local_fingerprint)
            .map_err(QuinnError::Protocol)?;
        crypto_data
            .set_peer_fingerprint(&peer_fingerprint)
            .map_err(QuinnError::Protocol)?;
        crypto_data.set_role(false); // Client is initiator (not responder)

        debug!("TLS fingerprints set in CryptoData");

        // Feed TransportConnected event to state machine
        trace!("Calling process_event(TransportConnected)");
        self.process_event(NetworkInput::TransportConnected).await?;

        trace!("process_event returned, calling run_until_authenticated");
        // Run event loop until authenticated (default 30 second timeout)
        self.run_until_authenticated(connection, std::time::Duration::from_secs(30))
            .await?;

        debug!("run_until_authenticated returned successfully");
        Ok(())
    }

    /// Run the event loop until authentication completes
    async fn run_until_authenticated(
        &mut self,
        connection: quinn::Connection,
        auth_timeout: std::time::Duration,
    ) -> Result<(), QuinnError> {
        use tokio::time::{timeout, Duration};

        let auth_future = async {
            trace!("Entered run_until_authenticated event loop");

            // Give Quinn a moment to transmit queued data before we start waiting
            tokio::time::sleep(Duration::from_millis(200)).await;
            trace!("Waited 200ms for Quinn to transmit initial message");

            loop {
                if self.is_authenticated() {
                    debug!("Authenticated! Returning from event loop");
                    return Ok::<(), QuinnError>(());
                }

                // Wait for incoming unidirectional stream
                trace!("Waiting for incoming stream with accept_uni()");
                tokio::select! {
                    result = connection.accept_uni() => {
                        trace!("accept_uni() returned: {:?}", result.as_ref().map(|_| "Ok"));
                        match result {
                            Ok(mut recv_stream) => {
                                let conn_id = format!("{:?}", connection.stable_id());
                                let stream_id = recv_stream.id();
                                debug!("[CONN:{}][STREAM:{}] Stream received from server", conn_id, stream_id.index());

                                // Read all data from the stream
                                let mut buffer = Vec::new();
                                while let Ok(Some(chunk)) = recv_stream.read_chunk(4096, true).await {
                                    buffer.extend_from_slice(&chunk.bytes);
                                }

                                debug!("[CONN:{}][STREAM:{}] RX {} bytes from server", conn_id, stream_id.index(), buffer.len());
                                trace!("[CONN:{}][STREAM:{}] RX HEXDUMP: {}", conn_id, stream_id.index(), hex::encode(&buffer));

                                // Try to parse and log message type
                                if let Ok(msg) = openscreen_network::NetworkMessage::decode(&buffer) {
                                    let msg_type = match msg {
                                        openscreen_network::NetworkMessage::AuthCapabilities(_) => "AuthCapabilities",
                                        openscreen_network::NetworkMessage::AuthSpake2Handshake(_) => "AuthSpake2Handshake",
                                        openscreen_network::NetworkMessage::AuthSpake2Confirmation(_) => "AuthSpake2Confirmation",
                                        openscreen_network::NetworkMessage::AuthStatus(_) => "AuthStatus",
                                    };
                                    info!("[CONN:{}][STREAM:{}] 📥 RX {} (parsed)", conn_id, stream_id.index(), msg_type);
                                } else {
                                    debug!("[CONN:{}][STREAM:{}] RX unparseable message (may be application data)", conn_id, stream_id.index());
                                }

                                // Feed the data to the state machine
                                // StreamId is 0 since we're not tracking multiple streams yet
                                self.process_event(NetworkInput::DataReceived(0, &buffer)).await?;
                            }
                            Err(e) => {
                                return Err(QuinnError::Connection(e));
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        // Periodic tick to drive the state machine
                        // This is required for the initiator to execute crypto operations proactively
                        trace!("Timeout elapsed, calling Tick to drive state machine");
                        self.process_event(NetworkInput::Tick(0)).await?;
                    }
                }
            }
        };

        timeout(auth_timeout, auth_future)
            .await
            .map_err(|_| QuinnError::Protocol(NetworkError::AuthenticationFailed))?
    }

    /// Process a network input event through the state machine
    async fn process_event(&mut self, input: NetworkInput<'_>) -> Result<(), QuinnError> {
        const MAX_OUTPUTS: usize = 16;
        let mut outputs = heapless::Vec::<NetworkOutput, MAX_OUTPUTS>::new();

        trace!("process_event: input={:?}", input);

        // Feed input to state machine
        match self.network_state.handle(&input, &mut outputs) {
            Ok(()) => {
                trace!("handle succeeded, {} outputs", outputs.len());
            }
            Err(e) => {
                debug!("handle failed: {:?}", e);
                return Err(e.into());
            }
        }

        // Process all outputs
        // We need to handle RequestCrypto and NeedsPoll specially to avoid borrow checker issues.
        // RequestCrypto contains references to crypto_data, but we need to call
        // methods on self that borrow mutably. Solution: clone the crypto request
        // and drop the outputs Vec before making the recursive call.

        // First pass: check for RequestCrypto and NeedsPoll and handle them
        let mut needs_poll = false;
        for output in &outputs {
            match output {
                NetworkOutput::RequestCrypto(request) => {
                    // Clone the request to break the borrow chain
                    let request_clone = request.clone();
                    // Drop outputs to release the borrow on self.crypto_data
                    drop(outputs);

                    // Execute crypto operation
                    let result = self
                        .crypto_provider
                        .execute(&request_clone)
                        .map_err(|_| QuinnError::Crypto)?;

                    // Feed result back to state machine (recursive call)
                    // Use Box::pin to handle recursive async call
                    return Box::pin(self.process_event(NetworkInput::CryptoCompleted(result)))
                        .await;
                }
                NetworkOutput::NeedsPoll => {
                    needs_poll = true;
                }
                _ => {}
            }
        }

        // Handle NeedsPoll by calling Tick recursively (with loop protection)
        // NOTE: This implementation has known limitations with chained crypto operations
        // See notes/GEMINI_SUGGESTED_FIX.md for the robust drain() pattern fix
        if needs_poll {
            drop(outputs);
            trace!("NeedsPoll detected, calling process_event(Tick)");
            const MAX_POLL_ITERATIONS: usize = 10;
            for iteration in 0..MAX_POLL_ITERATIONS {
                trace!("Poll iteration {}", iteration);

                // Extract crypto request from tick and process needs_poll
                let (crypto_request_opt, mut needs_another_poll) = {
                    let tick_input = NetworkInput::Tick(0);
                    let mut tick_outputs = heapless::Vec::<NetworkOutput, MAX_OUTPUTS>::new();
                    self.network_state.handle(&tick_input, &mut tick_outputs)?;

                    // Clone the crypto request if present, check for NeedsPoll
                    let request = tick_outputs.iter().find_map(|output| match output {
                        NetworkOutput::RequestCrypto(request) => Some(request.clone()),
                        _ => None,
                    });
                    let needs_poll = tick_outputs
                        .iter()
                        .any(|output| matches!(output, NetworkOutput::NeedsPoll));

                    (request, needs_poll)
                }; // tick_input and tick_outputs drop here

                // If there's a crypto request, process it
                if let Some(request_clone) = crypto_request_opt {
                    let result = self
                        .crypto_provider
                        .execute(&request_clone)
                        .map_err(|_| QuinnError::Crypto)?;

                    // Process crypto result and send any messages - all in one scope
                    let crypto_input = NetworkInput::CryptoCompleted(result);
                    let mut crypto_outputs = heapless::Vec::<NetworkOutput, MAX_OUTPUTS>::new();
                    self.network_state
                        .handle(&crypto_input, &mut crypto_outputs)?;

                    // Process all outputs while crypto_input is still alive
                    for output in &crypto_outputs {
                        match output {
                            NetworkOutput::SendMessage(msg) => {
                                if let Some(conn) = &self.connection {
                                    let conn_id = format!("{:?}", conn.stable_id());
                                    // CBOR encode the structured message
                                    let cbor_bytes =
                                        openscreen_network::messages::encode_network_message(msg)
                                            .map_err(|_| NetworkError::EncodeFailed)?;
                                    let mut send_stream = conn.open_uni().await?;
                                    let send_stream_id = send_stream.id();
                                    send_stream.write_all(&cbor_bytes).await?;
                                    send_stream.finish()?;

                                    let msg_type = match msg {
                                        openscreen_network::NetworkMessage::AuthCapabilities(_) => "AuthCapabilities",
                                        openscreen_network::NetworkMessage::AuthSpake2Handshake(_) => "AuthSpake2Handshake",
                                        openscreen_network::NetworkMessage::AuthSpake2Confirmation(_) => "AuthSpake2Confirmation",
                                        openscreen_network::NetworkMessage::AuthStatus(_) => "AuthStatus",
                                    };

                                    info!(
                                        "[CONN:{}][STREAM:{}] 📤 TX {} bytes ({}) after poll+crypto",
                                        conn_id,
                                        send_stream_id.index(),
                                        cbor_bytes.len(),
                                        msg_type
                                    );
                                    trace!(
                                        "[CONN:{}][STREAM:{}] TX HEXDUMP: {}",
                                        conn_id,
                                        send_stream_id.index(),
                                        hex::encode(&cbor_bytes)
                                    );
                                }
                            }
                            NetworkOutput::NeedsPoll => {
                                needs_another_poll = true;
                            }
                            _ => {
                                trace!("Tick crypto output: {:?}", output);
                            }
                        }
                    }
                    // crypto_input and crypto_outputs drop here together
                }

                if !needs_another_poll {
                    break;
                }
            }
            return Ok(());
        }

        // Second pass: process non-crypto outputs
        // We extract actions into an owned structure to avoid borrow checker issues.
        // The `outputs` vector borrows from self.network_state, but we need &mut self to send.
        // Solution: Copy data into owned PendingAction, drop outputs, then execute actions.
        enum PendingAction {
            SendBytes {
                data: Vec<u8>,
                description: String,
                is_app_data: bool,
            },
            #[allow(dead_code)] // Will be used when stream management is implemented
            CloseStream(u64),
            CloseConnection,
            Event(openscreen_network::NetworkEvent),
        }

        let mut pending_actions = Vec::new();

        for output in &outputs {
            match output {
                NetworkOutput::SendMessage(msg) => {
                    let msg_type = match msg {
                        openscreen_network::NetworkMessage::AuthCapabilities(_) => {
                            "AuthCapabilities"
                        }
                        openscreen_network::NetworkMessage::AuthSpake2Handshake(_) => {
                            "AuthSpake2Handshake"
                        }
                        openscreen_network::NetworkMessage::AuthSpake2Confirmation(_) => {
                            "AuthSpake2Confirmation"
                        }
                        openscreen_network::NetworkMessage::AuthStatus(_) => "AuthStatus",
                    };

                    // Encode immediately to owned Vec<u8>
                    match openscreen_network::messages::encode_network_message(msg) {
                        Ok(heapless_vec) => {
                            pending_actions.push(PendingAction::SendBytes {
                                data: heapless_vec.to_vec(),
                                description: msg_type.to_string(),
                                is_app_data: false,
                            });
                        }
                        Err(_e) => {
                            error!("Failed to encode message {}", msg_type);
                            return Err(QuinnError::Protocol(NetworkError::EncodeFailed));
                        }
                    }
                }
                NetworkOutput::SendData { data } => {
                    pending_actions.push(PendingAction::SendBytes {
                        data: data.to_vec(), // Copy slice to owned Vec
                        description: format!("{} bytes raw app data", data.len()),
                        is_app_data: true,
                    });
                }
                NetworkOutput::CloseStream(id) => {
                    pending_actions.push(PendingAction::CloseStream(*id));
                }
                NetworkOutput::CloseConnection => {
                    pending_actions.push(PendingAction::CloseConnection);
                }
                NetworkOutput::Event(evt) => {
                    pending_actions.push(PendingAction::Event(evt.clone()));
                }
                NetworkOutput::OpenUniStream => {
                    // Quinn opens streams implicitly on write
                }
                NetworkOutput::RequestCrypto(_) => {
                    unreachable!("RequestCrypto handled in first pass");
                }
                NetworkOutput::NeedsPoll => {
                    // Handled in first pass
                }
            }
        }

        // DROP THE BORROW on outputs (releases borrow on self.network_state)
        drop(outputs);

        // Execute actions with &mut self
        for action in pending_actions {
            match action {
                PendingAction::SendBytes {
                    data,
                    description,
                    is_app_data,
                } => {
                    if let Some(conn) = &self.connection {
                        let conn_id = format!("{:?}", conn.stable_id());
                        let mut send_stream = conn.open_uni().await?;
                        let stream_id = send_stream.id();

                        send_stream.write_all(&data).await?;
                        send_stream.finish()?;

                        let type_label = if is_app_data {
                            "raw app data"
                        } else {
                            &description
                        };
                        info!(
                            "[CONN:{}][STREAM:{}] 📤 TX {} bytes ({})",
                            conn_id,
                            stream_id.index(),
                            data.len(),
                            type_label
                        );
                        trace!(
                            "[CONN:{}][STREAM:{}] TX HEXDUMP: {}",
                            conn_id,
                            stream_id.index(),
                            hex::encode(&data)
                        );
                    } else {
                        error!("FAIL: SEND FAILED: Not connected (connection was closed)");
                        return Err(QuinnError::NotConnected);
                    }
                }
                PendingAction::CloseConnection => {
                    if let Some(conn) = &self.connection {
                        conn.close(0u32.into(), b"connection closed");
                    }
                    self.connection = None;
                }
                PendingAction::Event(_evt) => {
                    // Events handled elsewhere if needed
                }
                PendingAction::CloseStream(_) => {
                    // Streams closed on drop
                }
            }
        }

        Ok(())
    }

    /// Send application-layer data on a new QUIC stream
    ///
    /// This sends raw application protocol data (e.g., agent-info messages)
    /// after authentication has completed. The data is sent on a new unidirectional stream.
    ///
    /// # Arguments
    /// * `data` - Application data to send (e.g., CBOR-encoded agent-info-request)
    ///
    /// # Returns
    /// * `Ok(())` - Data sent successfully
    /// * `Err(QuinnError)` - Failed to send data
    pub async fn send_application_data(&mut self, data: &[u8]) -> Result<(), QuinnError> {
        if let Some(conn) = &self.connection {
            let conn_id = format!("{:?}", conn.stable_id());
            let mut send_stream = conn.open_uni().await?;
            let send_stream_id = send_stream.id();
            send_stream.write_all(data).await?;
            send_stream.finish()?;
            info!(
                "[CONN:{}][STREAM:{}] 📤 TX {} bytes (application data)",
                conn_id,
                send_stream_id.index(),
                data.len()
            );
            trace!(
                "[CONN:{}][STREAM:{}] TX HEXDUMP: {}",
                conn_id,
                send_stream_id.index(),
                hex::encode(data)
            );
            Ok(())
        } else {
            error!("FAIL: SEND FAILED: Not connected (connection was closed)");
            Err(QuinnError::NotConnected)
        }
    }

    /// Receive application-layer data from the next QUIC stream
    ///
    /// This receives raw application protocol data (e.g., agent-info messages)
    /// after authentication has completed. Blocks until data arrives on a new stream.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Received application data
    /// * `Err(QuinnError)` - Failed to receive data
    pub async fn receive_application_data(&mut self) -> Result<Vec<u8>, QuinnError> {
        if let Some(conn) = &self.connection {
            let conn_id = format!("{:?}", conn.stable_id());
            let mut recv_stream = conn.accept_uni().await?;
            let stream_id = recv_stream.id();
            let data = recv_stream.read_to_end(usize::MAX).await?;
            info!(
                "[CONN:{}][STREAM:{}] 📥 RX {} bytes (application data)",
                conn_id,
                stream_id.index(),
                data.len()
            );
            trace!(
                "[CONN:{}][STREAM:{}] RX HEXDUMP: {}",
                conn_id,
                stream_id.index(),
                hex::encode(&data)
            );
            Ok(data)
        } else {
            Err(QuinnError::NotConnected)
        }
    }
}

/// Extract TLS certificate fingerprint from a QUIC connection
///
/// Returns the SHA-256 hash of the peer's certificate, which is used
/// as the identity for RFC 9382 SPAKE2 confirmation transcript.
///
/// # Arguments
/// * `connection` - The established QUIC connection
///
/// # Returns
/// * `Ok([u8; 32])` - SHA-256 fingerprint of peer's certificate
/// * `Err(QuinnError)` - Failed to extract certificate
fn get_peer_certificate_fingerprint(
    connection: &quinn::Connection,
) -> Result<[u8; 32], QuinnError> {
    // Get peer identity (certificate chain)
    let identity = connection
        .peer_identity()
        .ok_or_else(|| QuinnError::Tls("No peer identity available".into()))?;

    // Downcast to rustls certificate chain
    let certs = identity
        .downcast::<Vec<CertificateDer>>()
        .map_err(|_| QuinnError::Tls("Failed to downcast peer identity to certificates".into()))?;

    // First certificate is the peer's certificate (others are intermediates/CA)
    let peer_cert = certs
        .first()
        .ok_or_else(|| QuinnError::Tls("No peer certificate in chain".into()))?;

    // Compute SHA-256 fingerprint of SPKI (Subject Public Key Info)
    // Per W3C OpenScreen spec: fingerprint = SHA-256(SPKI), NOT full cert
    let fingerprint = compute_spki_fingerprint(peer_cert.as_ref())
        .map_err(|e| QuinnError::Tls(format!("Failed to compute SPKI fingerprint: {e}")))?;

    debug!(
        "Extracted peer certificate SPKI fingerprint: {}",
        hex::encode(fingerprint)
    );
    Ok(fingerprint)
}

/// Compute SHA-256 fingerprint of a certificate's SPKI (Subject Public Key Info)
///
/// Per W3C OpenScreen spec § Computing the Certificate Fingerprint:
/// "The certificate fingerprint is the SHA-256 hash of the SubjectPublicKeyInfo."
///
/// This is the CORRECT way to compute OpenScreen fingerprints.
/// DO NOT hash the full certificate DER!
///
/// # Arguments
/// * `cert_der` - DER-encoded certificate bytes
///
/// # Returns
/// * `Result<[u8; 32], String>` - SHA-256 fingerprint of SPKI, or error if parsing fails
///
/// # Security Note
///
/// SPKI fingerprints are stable across certificate renewals (same key pair = same fingerprint).
/// This is required for Trust-On-First-Use (TOFU) and prevents MITM attacks.
fn compute_spki_fingerprint(cert_der: &[u8]) -> Result<[u8; 32], String> {
    use x509_parser::prelude::*;

    // Parse the X.509 certificate
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("Failed to parse certificate: {e}"))?;

    // Extract SPKI bytes (this is the DER-encoded SubjectPublicKeyInfo)
    let spki_bytes = cert.public_key().raw;

    // Compute SHA-256 of SPKI
    let mut hasher = Sha256::new();
    hasher.update(spki_bytes);
    let hash = hasher.finalize();

    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&hash);

    debug!(
        "Computed SPKI fingerprint: {} (SPKI size: {} bytes)",
        hex::encode(fingerprint),
        spki_bytes.len()
    );

    Ok(fingerprint)
}

/// Custom certificate verifier that validates SPKI fingerprint during TLS handshake
///
/// This verifier ensures the peer certificate's SPKI fingerprint matches the expected
/// fingerprint from mDNS discovery, preventing MITM attacks at the TLS layer.
///
/// Per W3C OpenScreen spec § Security Considerations:
/// "The fingerprint MUST be verified against the fp= TXT record from mDNS discovery."
#[derive(Debug, Clone)]
struct FingerprintVerifier {
    expected_fingerprint: [u8; 32],
}

impl FingerprintVerifier {
    fn new(expected_fingerprint: [u8; 32]) -> Self {
        Self {
            expected_fingerprint,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Compute SPKI fingerprint of presented certificate
        let actual_fingerprint = compute_spki_fingerprint(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("Fingerprint computation failed: {e}")))?;

        // Compare with expected fingerprint from mDNS
        if actual_fingerprint != self.expected_fingerprint {
            error!(
                "TLS handshake: Fingerprint mismatch! Expected: {}, Got: {}",
                hex::encode(self.expected_fingerprint),
                hex::encode(actual_fingerprint)
            );
            return Err(rustls::Error::General(format!(
                "Certificate fingerprint mismatch: expected {}, got {}",
                hex::encode(self.expected_fingerprint),
                hex::encode(actual_fingerprint)
            )));
        }

        debug!(
            "TLS handshake: Certificate fingerprint verified: {}",
            hex::encode(actual_fingerprint)
        );

        // Fingerprint matches - accept certificate
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Use rustls's default crypto provider to verify the signature
        // This properly validates TLS 1.2 signatures according to the spec
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Use rustls's default crypto provider to verify the signature
        // This properly validates TLS 1.3 signatures with stricter ECDSA semantics
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Use the crypto provider's supported schemes instead of hardcoding
        // This ensures we support all schemes that the crypto provider can handle
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openscreen_crypto::MockCryptoProvider;

    #[tokio::test]
    async fn test_create_client() {
        let crypto = MockCryptoProvider::new(b"test");
        let expected_fp = [0u8; 32]; // Dummy fingerprint for testing
        let client = QuinnClient::new(crypto, "0.0.0.0:0".parse().unwrap(), expected_fp);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_set_psk_and_token() {
        let crypto = MockCryptoProvider::new(b"test");
        let expected_fp = [0u8; 32]; // Dummy fingerprint for testing
        let mut client =
            QuinnClient::new(crypto, "0.0.0.0:0".parse().unwrap(), expected_fp).unwrap();

        assert!(client.set_psk(b"my-secret-password").is_ok());
        assert!(client.set_auth_token(b"token-123").is_ok());

        assert!(!client.is_authenticated());
        // NetworkConnectionState enum removed - state is tracked internally by Spake2StateMachine
    }
}
