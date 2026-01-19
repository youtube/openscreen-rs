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

//! QuinnServer - High-level server API for OpenScreen protocol
//!
//! Provides a clean listener-style API for accepting and authenticating
//! OpenScreen connections over QUIC.

use crate::QuinnError;
use anyhow::{Context, Result};
use openscreen_crypto::CryptoProvider;
use openscreen_crypto_rustcrypto::RustCryptoCryptoProvider;
use openscreen_network::{
    state_machine::Spake2StateMachine, CryptoData, NetworkInput, NetworkOutput,
};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{debug, error, info, trace, warn};

/// Custom client certificate verifier that accepts any client certificate
///
/// This is used for TLS fingerprint extraction per RFC 9382. The actual
/// authentication happens via SPAKE2, not TLS certificate validation.
///
/// WARNING: This accepts ALL client certificates. This is acceptable because:
/// 1. We only use the cert for fingerprint extraction (identity binding)
/// 2. Actual authentication is via SPAKE2 PSK
/// 3. Self-signed certs are expected in OpenScreen
#[derive(Debug)]
struct AcceptAnyClientCert;

impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCert {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Accept all client certificates - authentication is via SPAKE2
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// High-level OpenScreen server
///
/// Provides a listener-style API for accepting authenticated connections.
/// Handles TLS setup, QUIC endpoint creation, and SPAKE2 authentication.
///
/// # Example
///
/// ```no_run
/// use openscreen_quinn::QuinnServer;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     use std::net::SocketAddr;
///     let addr: SocketAddr = "0.0.0.0:4433".parse()?;
///     let server = QuinnServer::bind(addr, "test-psk").await?;
///
///     while let Some(result) = server.accept().await {
///         match result {
///             Ok(mut conn) => {
///                 tokio::spawn(async move {
///                     // Connection is already authenticated
///                     // Now handle application messages
///                     if let Ok(data) = conn.receive_message().await {
///                         // Process received data
///                         let _ = data;
///                     }
///                 });
///             }
///             Err(e) => { /* Handle auth failure */ let _ = e; }
///         }
///     }
///     Ok(())
/// }
/// ```
pub struct QuinnServer {
    endpoint: quinn::Endpoint,
    psk: String,
    cert_der: Vec<u8>,
    auth_token: Option<Vec<u8>>,
}

impl QuinnServer {
    /// Create and bind a new OpenScreen server
    ///
    /// # Arguments
    /// * `bind_addr` - Socket address to bind to (e.g., "0.0.0.0:4433")
    /// * `psk` - Pre-shared key for SPAKE2 authentication
    pub async fn bind(bind_addr: impl Into<SocketAddr>, psk: impl Into<String>) -> Result<Self> {
        let bind_addr = bind_addr.into();
        let psk = psk.into();

        debug!("Generating self-signed certificate");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .context("Failed to generate certificate")?;
        let cert_der = cert.cert.der().to_vec();
        let priv_key = cert.key_pair.serialize_der();

        debug!("Configuring TLS with client cert verifier");
        let client_cert_verifier = Arc::new(AcceptAnyClientCert);

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
                rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key.into()),
            )
            .context("Failed to create TLS config")?;

        server_crypto.alpn_protocols = vec![b"osp".to_vec()];

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .context("Failed to create QUIC server config")?,
        ));

        let endpoint = quinn::Endpoint::server(server_config, bind_addr)
            .context("Failed to create endpoint")?;

        info!("QuinnServer bound to {}", bind_addr);

        Ok(Self {
            endpoint,
            psk,
            cert_der,
            auth_token: None,
        })
    }

    /// Create and bind a new OpenScreen server with a provided certificate
    ///
    /// This variant allows you to provide your own certificate instead of generating one.
    /// Useful for persistent identity and mDNS discovery integration.
    ///
    /// # Arguments
    /// * `bind_addr` - Socket address to bind to (e.g., "0.0.0.0:4433")
    /// * `psk` - Pre-shared key for SPAKE2 authentication
    /// * `cert_der` - DER-encoded certificate
    /// * `key_der` - DER-encoded private key (PKCS#8 format)
    /// * `auth_token` - Optional authentication token from mDNS (for off-network attack prevention)
    pub async fn bind_with_cert(
        bind_addr: impl Into<SocketAddr>,
        psk: impl Into<String>,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
        auth_token: Option<Vec<u8>>,
    ) -> Result<Self> {
        let bind_addr = bind_addr.into();
        let psk = psk.into();

        debug!("Configuring TLS with provided certificate");
        let client_cert_verifier = Arc::new(AcceptAnyClientCert);

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
            )
            .context("Failed to create TLS config")?;

        server_crypto.alpn_protocols = vec![b"osp".to_vec()];

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .context("Failed to create QUIC server config")?,
        ));

        let endpoint = quinn::Endpoint::server(server_config, bind_addr)
            .context("Failed to create endpoint")?;

        info!(
            "QuinnServer bound to {} with provided certificate",
            bind_addr
        );

        Ok(Self {
            endpoint,
            psk,
            cert_der,
            auth_token,
        })
    }

    /// Accept the next incoming connection and authenticate it
    ///
    /// Returns `None` when the server is shutting down.
    /// Returns `Ok(AuthenticatedConnection)` on successful authentication.
    /// Returns `Err(...)` if authentication fails.
    pub async fn accept(&self) -> Option<Result<AuthenticatedConnection>> {
        let incoming = self.endpoint.accept().await?;

        let psk = self.psk.clone();
        let cert_der = self.cert_der.clone();
        let auth_token = self.auth_token.clone();

        // Drive authentication to completion
        Some(match incoming.await {
            Ok(connection) => {
                match Self::authenticate_connection(connection, psk, cert_der, auth_token).await {
                    Ok(conn) => Ok(conn),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(anyhow::anyhow!("Failed to accept connection: {e}")),
        })
    }

    /// Get the local address the server is bound to
    ///
    /// Useful for testing with dynamic port allocation.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| anyhow::anyhow!("Failed to get local address: {e}"))
    }

    /// Get the server's certificate fingerprint (SPKI SHA-256)
    ///
    /// This is the fingerprint that clients should use for verification.
    /// It should be advertised via mDNS in the `fp=` TXT record.
    pub fn fingerprint(&self) -> [u8; 32] {
        Self::compute_spki_fingerprint(&self.cert_der)
            .expect("Failed to compute server fingerprint")
    }

    /// Authenticate a QUIC connection using SPAKE2
    ///
    /// Internal method that drives the state machine to completion.
    async fn authenticate_connection(
        connection: quinn::Connection,
        psk: String,
        local_cert_der: Vec<u8>,
        auth_token: Option<Vec<u8>>,
    ) -> Result<AuthenticatedConnection> {
        let remote_addr = connection.remote_address();
        let conn_id = format!("{:?}", connection.stable_id());

        debug!(
            "[CONN:{}] Authenticating connection from {}",
            conn_id, remote_addr
        );

        // Extract TLS certificate fingerprints (RFC 9382 requirement)
        let peer_fingerprint = Self::get_peer_certificate_fingerprint(&connection)?;
        let local_fingerprint = Self::compute_spki_fingerprint(&local_cert_der)?;

        // Create state machine
        let mut crypto_data = CryptoData::new();
        crypto_data
            .set_psk(psk.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to set PSK: {e:?}"))?;
        crypto_data
            .set_my_fingerprint(&local_fingerprint)
            .map_err(|e| anyhow::anyhow!("Failed to set local fingerprint: {e:?}"))?;
        crypto_data
            .set_peer_fingerprint(&peer_fingerprint)
            .map_err(|e| anyhow::anyhow!("Failed to set peer fingerprint: {e:?}"))?;
        crypto_data.set_role(true); // Server is responder

        // Set auth token if provided (for off-network attack prevention)
        if let Some(token) = auth_token {
            crypto_data
                .set_auth_token(&token)
                .map_err(|e| anyhow::anyhow!("Failed to set auth token: {e:?}"))?;
            debug!("[CONN:{}] Auth token configured for validation", conn_id);
        }

        let mut network_state = Spake2StateMachine::new(crypto_data);
        let crypto_provider = RustCryptoCryptoProvider::new();

        // Send initial auth-capabilities on connection
        {
            let mut outputs = heapless::Vec::<NetworkOutput, 16>::new();
            let input = NetworkInput::TransportConnected;

            network_state
                .handle(&input, &mut outputs)
                .map_err(|e| anyhow::anyhow!("TransportConnected failed: {e:?}"))?;

            for output in &outputs {
                if let NetworkOutput::SendMessage(ref msg) = output {
                    Self::send_message(&connection, &conn_id, msg).await?;
                }
            }
        }

        // Run authentication event loop with timeout
        const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
        let auth_future = Self::drive_authentication(
            connection.clone(),
            conn_id.clone(),
            network_state,
            crypto_provider,
        );

        match tokio::time::timeout(AUTH_TIMEOUT, auth_future).await {
            Ok(Ok(_)) => {
                info!("[CONN:{}] Authentication successful", conn_id);
                Ok(AuthenticatedConnection { connection })
            }
            Ok(Err(e)) => {
                error!("[CONN:{}] Authentication failed: {:?}", conn_id, e);
                Err(e)
            }
            Err(_) => {
                warn!("[CONN:{}] Authentication timeout", conn_id);
                Err(anyhow::anyhow!("Authentication timeout"))
            }
        }
    }

    /// Drive the state machine until authentication completes
    async fn drive_authentication(
        connection: quinn::Connection,
        conn_id: String,
        mut network_state: Spake2StateMachine,
        mut crypto_provider: RustCryptoCryptoProvider,
    ) -> Result<()> {
        let mut iteration = 0u64;

        loop {
            iteration += 1;
            trace!(
                "[CONN:{}][LOOP-{}] Event loop iteration",
                conn_id,
                iteration
            );

            if network_state.is_authenticated() {
                info!("[CONN:{}] Authentication complete", conn_id);
                return Ok(());
            }

            tokio::select! {
                biased;

                result = connection.accept_uni() => {
                    match result {
                        Ok(mut recv_stream) => {
                            let stream_id = recv_stream.id();

                            // Read all data from stream
                            let mut buffer = Vec::new();
                            while let Ok(Some(chunk)) = recv_stream.read_chunk(4096, true).await {
                                buffer.extend_from_slice(&chunk.bytes);
                            }

                            if buffer.is_empty() {
                                continue;
                            }

                            debug!("[CONN:{}][STREAM:{}] RX {} bytes", conn_id, stream_id.index(), buffer.len());

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

                            // Feed to state machine
                            let mut outputs = heapless::Vec::new();
                            let input = NetworkInput::DataReceived(0, &buffer);
                            network_state.handle(&input, &mut outputs)
                                .map_err(|e| anyhow::anyhow!("State machine error: {e:?}"))?;

                            // Process outputs - handle crypto requests in loop
                            loop {
                                let mut crypto_request = None;
                                for output in &outputs {
                                    if let NetworkOutput::RequestCrypto(request) = output {
                                        crypto_request = Some(request.clone());
                                        break;
                                    }
                                }

                                match crypto_request {
                                    Some(request) => {
                                        // Send any pending messages before crypto
                                        for output in &outputs {
                                            if let NetworkOutput::SendMessage(msg) = output {
                                                Self::send_message(&connection, &conn_id, msg).await?;
                                            }
                                        }
                                        drop(outputs);

                                        // Execute crypto
                                        let result = crypto_provider.execute(&request)
                                            .map_err(|e| anyhow::anyhow!("Crypto failed: {e:?}"))?;

                                        let mut more_outputs = heapless::Vec::new();
                                        let input = NetworkInput::CryptoCompleted(result);
                                        network_state.handle(&input, &mut more_outputs)
                                            .map_err(|e| anyhow::anyhow!("CryptoCompleted failed: {e:?}"))?;

                                        outputs = more_outputs;
                                    }
                                    None => break,
                                }
                            }

                            // Process remaining outputs
                            let mut needs_poll = false;
                            for output in outputs {
                                match output {
                                    NetworkOutput::SendMessage(msg) => {
                                        Self::send_message(&connection, &conn_id, &msg).await?;
                                    }
                                    NetworkOutput::Event(openscreen_network::NetworkEvent::Authenticated) => {
                                        debug!("[CONN:{}] Authenticated!", conn_id);
                                    }
                                    NetworkOutput::Event(openscreen_network::NetworkEvent::AuthenticationFailed(e)) => {
                                        return Err(anyhow::anyhow!("Auth failed: {e:?}"));
                                    }
                                    NetworkOutput::NeedsPoll => {
                                        needs_poll = true;
                                    }
                                    _ => {}
                                }
                            }

                            // Handle NeedsPoll
                            if needs_poll {
                                let mut tick_outputs = heapless::Vec::new();
                                network_state.handle(&NetworkInput::Tick(0), &mut tick_outputs).ok();
                                for output in tick_outputs {
                                    if let NetworkOutput::SendMessage(msg) = output {
                                        Self::send_message(&connection, &conn_id, &msg).await?;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!("Client disconnected: {e}"));
                        }
                    }
                },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    network_state.handle(&NetworkInput::Tick(0), &mut heapless::Vec::new()).ok();
                }
            }
        }
    }

    /// Helper: Send a network message over QUIC
    async fn send_message(
        connection: &quinn::Connection,
        conn_id: &str,
        msg: &openscreen_network::NetworkMessage<'_>,
    ) -> Result<()> {
        use openscreen_network::messages::encode_network_message;

        let msg_type = match msg {
            openscreen_network::NetworkMessage::AuthCapabilities(_) => "AuthCapabilities",
            openscreen_network::NetworkMessage::AuthSpake2Handshake(_) => "AuthSpake2Handshake",
            openscreen_network::NetworkMessage::AuthSpake2Confirmation(_) => {
                "AuthSpake2Confirmation"
            }
            openscreen_network::NetworkMessage::AuthStatus(_) => "AuthStatus",
        };

        let cbor_bytes = encode_network_message(msg)
            .map_err(|e| anyhow::anyhow!("Failed to encode message: {e:?}"))?;

        let mut send_stream = connection
            .open_uni()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to open stream: {e}"))?;
        let send_stream_id = send_stream.id();

        send_stream
            .write_all(&cbor_bytes)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to write message: {e}"))?;
        send_stream
            .finish()
            .map_err(|e| anyhow::anyhow!("Failed to finish stream: {e}"))?;

        info!(
            "[CONN:{}][STREAM:{}] 📤 TX {} bytes ({})",
            conn_id,
            send_stream_id.index(),
            cbor_bytes.len(),
            msg_type
        );

        Ok(())
    }

    /// Helper: Extract peer certificate fingerprint
    fn get_peer_certificate_fingerprint(connection: &quinn::Connection) -> Result<[u8; 32]> {
        let identity = connection
            .peer_identity()
            .ok_or_else(|| anyhow::anyhow!("No peer identity available"))?;

        let certs = identity
            .downcast::<Vec<CertificateDer>>()
            .map_err(|_| anyhow::anyhow!("Failed to downcast peer identity"))?;

        let peer_cert = certs
            .first()
            .ok_or_else(|| anyhow::anyhow!("No peer certificate in chain"))?;

        // Compute SPKI fingerprint (per W3C OpenScreen spec)
        Self::compute_spki_fingerprint(peer_cert.as_ref())
    }

    /// Compute SHA-256 fingerprint of a certificate's SPKI (Subject Public Key Info)
    ///
    /// Per W3C OpenScreen spec § Computing the Certificate Fingerprint:
    /// "The certificate fingerprint is the SHA-256 hash of the SubjectPublicKeyInfo."
    ///
    /// # Arguments
    /// * `cert_der` - DER-encoded certificate bytes
    ///
    /// # Returns
    /// * `Result<[u8; 32], anyhow::Error>` - SHA-256 fingerprint of SPKI
    fn compute_spki_fingerprint(cert_der: &[u8]) -> Result<[u8; 32]> {
        use x509_parser::prelude::*;

        // Parse the X.509 certificate
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {e}"))?;

        // Extract SPKI bytes
        let spki_bytes = cert.public_key().raw;

        // Compute SHA-256 of SPKI
        let mut hasher = Sha256::new();
        hasher.update(spki_bytes);
        let hash = hasher.finalize();

        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&hash);

        Ok(fingerprint)
    }
}

/// An authenticated OpenScreen connection
///
/// Returned by `QuinnServer::accept()` after successful SPAKE2 authentication.
/// Provides methods for sending and receiving application-layer messages.
pub struct AuthenticatedConnection {
    connection: quinn::Connection,
}

impl AuthenticatedConnection {
    /// Receive the next application message from the peer
    ///
    /// Blocks until a message is received or the connection is closed.
    pub async fn receive_message(&mut self) -> Result<Vec<u8>, QuinnError> {
        let mut recv_stream = self
            .connection
            .accept_uni()
            .await
            .map_err(|e| QuinnError::NetworkError(format!("Failed to accept stream: {e}")))?;

        let mut buffer = Vec::new();
        while let Ok(Some(chunk)) = recv_stream.read_chunk(4096, true).await {
            buffer.extend_from_slice(&chunk.bytes);
        }

        if buffer.is_empty() {
            return Err(QuinnError::NetworkError("Empty message".into()));
        }

        Ok(buffer)
    }

    /// Send an application message to the peer
    pub async fn send_message(&mut self, data: &[u8]) -> Result<(), QuinnError> {
        let mut send_stream = self
            .connection
            .open_uni()
            .await
            .map_err(|e| QuinnError::NetworkError(format!("Failed to open stream: {e}")))?;

        send_stream
            .write_all(data)
            .await
            .map_err(|e| QuinnError::NetworkError(format!("Failed to write: {e}")))?;

        send_stream
            .finish()
            .map_err(|e| QuinnError::NetworkError(format!("Failed to finish: {e}")))?;

        Ok(())
    }

    /// Get the remote address of this connection
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Check if the connection is still open
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
}
