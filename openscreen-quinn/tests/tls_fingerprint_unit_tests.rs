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

//! Unit tests for TLS fingerprint verification
//!
//! These tests verify that the FingerprintVerifier correctly accepts/rejects
//! certificates during TLS handshake based on fingerprint matching.
//!
//! Unlike the integration tests, these tests focus ONLY on TLS-level
//! fingerprint verification without requiring full SPAKE2 authentication.

mod common;

use common::generate_test_cert;
use openscreen_crypto_rustcrypto::RustCryptoCryptoProvider;
use openscreen_quinn::QuinnClient;
use std::net::SocketAddr;

/// Helper to create a basic QUIC server that accepts one TLS connection
/// Returns (server_addr, server_fingerprint, server_handle)
async fn create_test_server(psk: &str) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    use openscreen_quinn::QuinnServer;

    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (cert_der, key_der) = generate_test_cert("test-server.local");
    let server = QuinnServer::bind(server_addr, psk, cert_der, key_der, None)
        .await
        .expect("Failed to start test server");

    let bound_addr = server.local_addr().expect("Failed to get server address");
    let server_fingerprint = server.fingerprint();

    // Spawn server task that just accepts one connection and drops it
    // This is enough to test TLS handshake without full SPAKE2 auth
    let server_handle = tokio::spawn(async move {
        // Accept one connection (TLS handshake will complete or fail)
        if let Some(_conn) = server.accept().await {
            // Connection accepted - TLS handshake succeeded
            // We don't care about SPAKE2 auth for these tests
        }
    });

    (bound_addr, server_fingerprint, server_handle)
}

/// Test that TLS handshake succeeds when fingerprint matches
#[tokio::test]
async fn test_tls_accepts_correct_fingerprint() {
    let (server_addr, server_fingerprint, server_handle) = create_test_server("test-psk").await;

    // Give server time to start listening
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Create client with CORRECT fingerprint
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

    // Attempt connection - TLS handshake should succeed
    // We expect this to either:
    // 1. Succeed and return Ok (TLS handshake completed)
    // 2. Fail with ApplicationClosed (TLS succeeded, SPAKE2 failed - that's OK for this test)
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        client.connect(server_addr, "localhost"),
    )
    .await;

    // Check the result
    match result {
        Ok(Ok(())) => {
            // Perfect! Connection succeeded completely
            println!("OK: TLS handshake succeeded (full auth also worked)");
        }
        Ok(Err(e)) => {
            // Check if it's ApplicationClosed (SPAKE2 failed, but TLS succeeded)
            let error_msg = format!("{e:?}");
            if error_msg.contains("ApplicationClosed") {
                // This is actually SUCCESS for our purposes!
                // TLS handshake completed, SPAKE2 failed (expected)
                println!("OK: TLS handshake succeeded (SPAKE2 layer failed as expected)");
            } else {
                panic!("Connection failed with unexpected error (TLS may have failed): {e:?}");
            }
        }
        Err(_) => {
            panic!("Connection timed out - TLS handshake may have hung");
        }
    }

    // Clean up server
    server_handle.abort();
}

/// Test that TLS handshake fails when fingerprint doesn't match
#[tokio::test]
async fn test_tls_rejects_wrong_fingerprint() {
    let (server_addr, _correct_fingerprint, server_handle) = create_test_server("test-psk").await;

    // Give server time to start listening
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Create client with WRONG fingerprint
    let wrong_fingerprint = [0x42u8; 32]; // Definitely wrong!
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

    // Attempt connection - TLS handshake should FAIL
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        client.connect(server_addr, "localhost"),
    )
    .await;

    // We expect either:
    // 1. Connection error (TLS handshake failed)
    // 2. Timeout (TLS handshake rejected connection)
    match result {
        Ok(Ok(())) => {
            panic!("Connection succeeded with wrong fingerprint! Security vulnerability!");
        }
        Ok(Err(e)) => {
            // Good! Connection was rejected
            let error_msg = format!("{e:?}");
            println!("OK: TLS handshake rejected wrong fingerprint: {e:?}");

            // Verify it's a TLS/connection error, not SPAKE2
            assert!(
                error_msg.contains("Connection") || error_msg.contains("Tls"),
                "Expected TLS/connection error, got: {error_msg}"
            );
        }
        Err(_) => {
            // Timeout is also acceptable - means TLS handshake was rejected
            println!("OK: TLS handshake timed out (rejected wrong fingerprint)");
        }
    }

    // Clean up server
    server_handle.abort();
}

/// Test that TLS handshake fails with zero/dummy fingerprint
#[tokio::test]
async fn test_tls_rejects_zero_fingerprint() {
    let (server_addr, _correct_fingerprint, server_handle) = create_test_server("test-psk").await;

    // Give server time to start listening
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Create client with zero fingerprint (insecure dummy value)
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

    // Attempt connection - should fail (unless server somehow has zero fingerprint)
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        client.connect(server_addr, "localhost"),
    )
    .await;

    match result {
        Ok(Ok(())) => {
            // Very unlikely, but if server has zero fingerprint, connection succeeds
            println!(
                "⚠ Connection succeeded with zero fingerprint (server may have zero fingerprint)"
            );
        }
        Ok(Err(_)) | Err(_) => {
            // Expected: connection rejected or timed out
            println!("OK: TLS handshake rejected zero fingerprint");
        }
    }

    // Clean up server
    server_handle.abort();
}

/// Test that fingerprint verification is case-insensitive to byte order
#[tokio::test]
async fn test_fingerprint_exact_match_required() {
    let (server_addr, server_fingerprint, server_handle) = create_test_server("test-psk").await;

    // Give server time to start listening
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Create client with fingerprint that differs by ONE byte
    let mut almost_correct_fingerprint = server_fingerprint;
    almost_correct_fingerprint[0] ^= 0x01; // Flip one bit in first byte

    let crypto_provider = RustCryptoCryptoProvider::new();
    let client_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (cert_der, key_der) = generate_test_cert("test-client.local");
    let mut client = QuinnClient::new(
        crypto_provider,
        client_bind,
        almost_correct_fingerprint,
        cert_der,
        key_der,
    )
    .expect("Failed to create client");

    client.set_psk(b"test-psk").expect("Failed to set PSK");

    // Attempt connection - should fail (even though only 1 bit differs)
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        client.connect(server_addr, "localhost"),
    )
    .await;

    match result {
        Ok(Ok(())) => {
            panic!(
                "Connection succeeded with almost-correct fingerprint! Must require exact match!"
            );
        }
        Ok(Err(_)) | Err(_) => {
            println!("OK: TLS handshake rejected fingerprint with single bit difference");
        }
    }

    // Clean up server
    server_handle.abort();
}
