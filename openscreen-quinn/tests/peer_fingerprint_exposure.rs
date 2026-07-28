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

//! Integration test: server-side peer fingerprint exposure
//!
//! After SPAKE2 completes, `QuinnServer::accept` returns an
//! `AuthenticatedConnection` whose `peer_fingerprint()` accessor must return
//! the SPKI fingerprint of the *client's* certificate. This is the stable
//! cryptographic identity the receiver uses to key per-peer state and to
//! cross-reference the peer against mDNS discovery records.
//!
//! Prior to this being exposed, the server verified the client fingerprint
//! during SPAKE2 but then discarded it, forcing callers to treat the
//! authenticated peer as anonymous. This test locks in the contract that
//! the verified fingerprint is observable.
//!
//! The expected fingerprint is computed via `openscreen_discovery::Fingerprint`
//! rather than `openscreen_quinn`'s internal helper, so the assertion is a
//! genuine cross-crate cross-check, not a tautology over the same code path.

mod common;

use common::generate_test_cert;
use openscreen_crypto_rustcrypto::RustCryptoCryptoProvider;
use openscreen_discovery::Fingerprint;
use openscreen_quinn::{QuinnClient, QuinnServer};
use std::net::SocketAddr;

/// Drive both sides to a fully authenticated connection, then assert that
/// `AuthenticatedConnection::peer_fingerprint()` on the server side equals
/// the SPKI SHA-256 fingerprint of the client's certificate.
#[tokio::test(flavor = "multi_thread")]
async fn server_observes_verified_peer_fingerprint_after_spake2() {
    // ---- Server ----
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server_cert, server_key) = generate_test_cert("test-server.local");
    let server = QuinnServer::bind(server_addr, "shared-psk", server_cert, server_key, None)
        .await
        .expect("Failed to start server");
    let bound_addr = server.local_addr().expect("Failed to get server address");
    let server_fingerprint = server.fingerprint();

    // Spawn the acceptor so it drives SPAKE2 concurrently with the client.
    // No `sleep` here: `QuinnServer::bind` binds the UDP socket synchronously,
    // so packets from the client are buffered by the OS / Quinn's background
    // driver even before `accept()` is polled.
    let server_task = tokio::spawn(async move {
        server
            .accept()
            .await
            .expect("accept returned None")
            .expect("accept returned an error")
    });

    // ---- Client ----
    let (client_cert, client_key) = generate_test_cert("test-client.local");
    // Independent cross-crate computation of the expected fingerprint.
    let expected_client_fingerprint = Fingerprint::from_der_cert(&client_cert)
        .expect("Failed to compute client SPKI fingerprint");
    let expected_client_fingerprint = expected_client_fingerprint.as_bytes();

    let crypto_provider = RustCryptoCryptoProvider::new();
    let client_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut client = QuinnClient::new(
        crypto_provider,
        client_bind,
        server_fingerprint,
        client_cert.clone(),
        client_key,
    )
    .expect("Failed to create client");
    client.set_psk(b"shared-psk").expect("Failed to set PSK");

    // Drive the client side to completion. If auth fails or times out, the
    // server-side fingerprint is not observable, so the test is meaningless.
    tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        client.connect(bound_addr, "localhost"),
    )
    .await
    .expect("client connect timed out")
    .expect("client connect failed");
    assert!(
        client.is_authenticated(),
        "client must be authenticated before we inspect the server-side peer fingerprint"
    );

    let server_connection = tokio::time::timeout(tokio::time::Duration::from_secs(5), server_task)
        .await
        .expect("server accept timed out")
        .expect("server task panicked");

    assert_eq!(
        server_connection.peer_fingerprint(),
        *expected_client_fingerprint,
        "server-side peer_fingerprint must equal the SPKI fingerprint of the client certificate"
    );
}
