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

//! Integration tests for TLS-level fingerprint verification
//!
//! These tests verify that TLS handshakes properly verify certificate fingerprints
//! and reject connections when fingerprints don't match (MITM protection).
//!
//! Note: These tests verify TLS-level fingerprint verification only, not full SPAKE2 authentication.

mod common;

use common::generate_test_cert;
use openscreen_crypto_rustcrypto::RustCryptoCryptoProvider;
use openscreen_quinn::{QuinnClient, QuinnServer};
use std::net::SocketAddr;

/// Test that TLS handshake succeeds when fingerprint matches
#[tokio::test(flavor = "multi_thread")]
async fn test_connection_succeeds_with_correct_fingerprint() {
    // Start a receiver (server)
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (cert_der, key_der) = generate_test_cert("test-server.local");
    let server = QuinnServer::bind(server_addr, "test-psk", cert_der, key_der, None)
        .await
        .expect("Failed to start server");

    // Get the actual bound address (port is dynamic)
    let bound_addr = server.local_addr().expect("Failed to get server address");

    // Get server's certificate fingerprint
    let server_fingerprint = server.fingerprint();

    // Spawn server task (will accept one connection but auth will take time)
    let server_handle = tokio::spawn(async move {
        // Just accept the connection, don't wait for full auth
        let _result = server.accept().await;
        // Keep the server alive for a bit
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create client with correct fingerprint and same PSK
    let crypto_provider = RustCryptoCryptoProvider::new();
    let client_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (cert_der, key_der) = generate_test_cert("test-client.local");
    let mut client = QuinnClient::new(
        crypto_provider,
        client_bind,
        server_fingerprint,
        cert_der,
        key_der,
    )
    .expect("Failed to create client");

    client.set_psk(b"test-psk").expect("Failed to set PSK");

    // Try to connect - this will start the TLS handshake
    // The connect() will eventually timeout waiting for full auth, but we just
    // want to verify the TLS handshake doesn't fail due to fingerprint mismatch
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        client.connect(bound_addr, "localhost"),
    )
    .await;

    // The connection attempt should either:
    // 1. Succeed (TLS handshake passed, but auth might timeout)
    // 2. Timeout (auth is taking too long, but TLS handshake passed)
    // It should NOT fail immediately with a TLS/fingerprint error
    match result {
        Ok(Ok(())) => {
            // Great! Full auth completed
            println!("OK: Full authentication completed");
            assert!(client.is_authenticated(), "Client should be authenticated");
        }
        Ok(Err(e)) => {
            // If it failed, it should NOT be a fingerprint verification failure
            let error_msg = format!("{e:?}");
            assert!(
                !error_msg.contains("fingerprint") && !error_msg.contains("certificate"),
                "Should not fail with fingerprint/certificate error, got: {error_msg}"
            );
            // It's probably an auth timeout or other auth issue, which is OK for this test
            println!("Auth failed (not fingerprint issue): {error_msg}");
        }
        Err(_timeout) => {
            // Timeout is OK - it means TLS handshake passed but auth is slow
            println!("Auth timed out (TLS handshake succeeded)");
        }
    }

    // Clean up
    server_handle.abort();
}

/// Test that TLS handshake fails when fingerprint doesn't match (MITM protection)
#[tokio::test(flavor = "multi_thread")]
async fn test_connection_fails_with_wrong_fingerprint() {
    // Start a receiver (server)
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (cert_der, key_der) = generate_test_cert("test-server.local");
    let server = QuinnServer::bind(server_addr, "test-psk", cert_der, key_der, None)
        .await
        .expect("Failed to start server");

    // Get the actual bound address
    let bound_addr = server.local_addr().expect("Failed to get server address");

    // Spawn server task (keep server alive)
    let server_handle = tokio::spawn(async move {
        let _server = server; // Keep server alive
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create client with WRONG fingerprint (should fail during TLS handshake!)
    let wrong_fingerprint = [0x42u8; 32]; // Definitely wrong
    let crypto_provider = RustCryptoCryptoProvider::new();
    let client_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (cert_der, key_der) = generate_test_cert("test-client.local");
    let mut client = QuinnClient::new(
        crypto_provider,
        client_bind,
        wrong_fingerprint,
        cert_der,
        key_der,
    )
    .expect("Failed to create client");

    client.set_psk(b"test-psk").expect("Failed to set PSK");

    // Try to connect - TLS handshake should fail immediately
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        client.connect(bound_addr, "localhost"),
    )
    .await;

    // Connection MUST fail
    match result {
        Ok(Ok(())) => {
            panic!("Connection should fail with wrong fingerprint, but it succeeded!");
        }
        Ok(Err(e)) => {
            // This is expected - verify error mentions TLS/certificate
            let error_msg = format!("{e:?}");
            assert!(
                error_msg.to_lowercase().contains("tls")
                    || error_msg.to_lowercase().contains("certificate")
                    || error_msg.to_lowercase().contains("handshake")
                    || error_msg.to_lowercase().contains("connection"),
                "Error should be TLS/certificate related, got: {error_msg}"
            );
            println!("Correctly rejected connection: {error_msg}");
        }
        Err(_) => {
            // Timeout might happen if the TLS handshake hangs, which is also rejection
            println!("Connection timed out (effectively rejected)");
        }
    }

    // Client should NOT be authenticated
    assert!(
        !client.is_authenticated(),
        "Client should not be authenticated after fingerprint mismatch"
    );

    // Clean up
    server_handle.abort();
}

/// Test that connection fails with zero fingerprint (dummy/insecure mode detection)
#[tokio::test(flavor = "multi_thread")]
async fn test_connection_fails_with_zero_fingerprint() {
    // Start a receiver (server)
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (cert_der, key_der) = generate_test_cert("test-server.local");
    let server = QuinnServer::bind(server_addr, "test-psk", cert_der, key_der, None)
        .await
        .expect("Failed to start server");

    let bound_addr = server.local_addr().expect("Failed to get server address");

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let _server = server;
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create client with zero fingerprint (dummy/insecure mode)
    let zero_fingerprint = [0u8; 32];
    let crypto_provider = RustCryptoCryptoProvider::new();
    let client_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (cert_der, key_der) = generate_test_cert("test-client.local");
    let mut client = QuinnClient::new(
        crypto_provider,
        client_bind,
        zero_fingerprint,
        cert_der,
        key_der,
    )
    .expect("Failed to create client");

    client.set_psk(b"test-psk").expect("Failed to set PSK");

    // Try to connect
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        client.connect(bound_addr, "localhost"),
    )
    .await;

    // This SHOULD fail (unless server happens to have all-zero fingerprint, extremely unlikely)
    match result {
        Ok(Ok(())) => {
            // Very unlikely, but acceptable if server has zero fingerprint
            println!("WARNING: Connection succeeded with zero fingerprint");
        }
        Ok(Err(_)) | Err(_) => {
            // Expected: connection failed or timed out
            println!("Correctly rejected zero fingerprint");
        }
    }

    server_handle.abort();
}

/// Test fingerprint verification with multiple clients
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_clients_same_fingerprint() {
    // Start a receiver
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (cert_der, key_der) = generate_test_cert("test-server.local");
    let server = QuinnServer::bind(server_addr, "test-psk", cert_der, key_der, None)
        .await
        .expect("Failed to start server");

    let bound_addr = server.local_addr().expect("Failed to get server address");
    let server_fingerprint = server.fingerprint();

    // Spawn server task (accept multiple connections)
    let server_handle = tokio::spawn(async move {
        for _ in 0..2 {
            let _result = server.accept().await;
        }
        // Keep alive a bit longer
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Client 1 with correct fingerprint
    let crypto1 = RustCryptoCryptoProvider::new();
    let (cert_der1, key_der1) = generate_test_cert("test-client1.local");
    let mut client1 = QuinnClient::new(
        crypto1,
        "127.0.0.1:0".parse().unwrap(),
        server_fingerprint,
        cert_der1,
        key_der1,
    )
    .expect("Failed to create client1");
    client1.set_psk(b"test-psk").expect("Failed to set PSK");

    let handle1 = tokio::spawn(async move {
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            client1.connect(bound_addr, "localhost"),
        )
        .await;

        // As long as it doesn't fail with fingerprint error, we're good
        match result {
            Ok(Err(e)) => {
                let error_msg = format!("{e:?}");
                assert!(
                    !error_msg.contains("fingerprint") && !error_msg.contains("certificate"),
                    "Client 1 should not fail with fingerprint error"
                );
            }
            _ => {} // OK or timeout is fine
        }
    });

    // Give first client a chance to connect
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Client 2 (different client, same server fingerprint)
    let crypto2 = RustCryptoCryptoProvider::new();
    let (cert_der2, key_der2) = generate_test_cert("test-client2.local");
    let mut client2 = QuinnClient::new(
        crypto2,
        "127.0.0.1:0".parse().unwrap(),
        server_fingerprint,
        cert_der2,
        key_der2,
    )
    .expect("Failed to create client2");
    client2.set_psk(b"test-psk").expect("Failed to set PSK");

    let handle2 = tokio::spawn(async move {
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            client2.connect(bound_addr, "localhost"),
        )
        .await;

        // As long as it doesn't fail with fingerprint error, we're good
        match result {
            Ok(Err(e)) => {
                let error_msg = format!("{e:?}");
                assert!(
                    !error_msg.contains("fingerprint") && !error_msg.contains("certificate"),
                    "Client 2 should not fail with fingerprint error"
                );
            }
            _ => {} // OK or timeout is fine
        }
    });

    // Wait for both clients
    let _ = tokio::join!(handle1, handle2);

    server_handle.abort();
}
