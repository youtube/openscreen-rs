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

//! AwaitingHandshake State - Waiting for peer's handshake message

use super::{Computing, GeneratingHandshake, State};
use crate::{crypto_data::CryptoData, NetworkError, NetworkInput, NetworkOutput};
use heapless::Vec;
use openscreen_crypto::{CryptoOpKind, CryptoRequest, Spake2Operation};

/// Waiting for peer's handshake message
///
/// The initiator has sent its handshake and is waiting for the responder's.
///
/// Following the State Context Pattern, `CryptoData` is passed by reference.
#[derive(Debug)]
pub struct AwaitingHandshake {
    // No fields - state data is in parent Spake2StateMachine
}

impl AwaitingHandshake {
    /// Create a new AwaitingHandshake state
    pub fn new() -> Self {
        Self {}
    }

    /// Handle input events in the AwaitingHandshake state
    ///
    /// Expected input: `DataReceived` - Peer's handshake message
    /// Transitions to: `Computing` (initiator) or `GeneratingHandshake` (responder)
    ///
    /// # Protocol Change
    /// responder flow: Receive initiator's handshake -> Request Spake2::Start -> GeneratingHandshake
    /// initiator flow: Already has handshake -> Request FinishWithConfirmation -> Computing
    ///
    /// # Lifetime Parameters
    /// - `'a`: Lifetime of outputs - tied to `crypto_data`
    /// - `'b`: Lifetime of input - independent of outputs
    pub fn handle<'a, 'b>(
        self,
        crypto_data: &'a mut CryptoData,
        input: &'b NetworkInput<'b>,
        outputs: &mut Vec<NetworkOutput<'a>, 16>,
    ) -> Result<State, NetworkError> {
        match input {
            NetworkInput::DataReceived(_stream, peer_handshake_cbor) => {
                // Decode message FIRST to extract token and validate
                use crate::messages::NetworkMessage;
                let msg = NetworkMessage::decode(peer_handshake_cbor)
                    .map_err(|_| NetworkError::DecodeFailed)?;

                let (peer_token, peer_public) = match msg {
                    NetworkMessage::AuthSpake2Handshake(hs) => {
                        (hs.initiation_token.token, hs.public_value)
                    }
                    _ => return Err(NetworkError::DecodeFailed),
                };

                // VALIDATE AUTH TOKEN (if we are responder with advertised token)
                // Per W3C spec: "Agents should discard any authentication message whose
                // auth-initiation-token is set and does not match the at provided by the
                // advertising agent."
                //
                // SECURITY: Uses constant-time comparison to prevent timing attacks (CWE-208)
                if crypto_data.is_responder && !crypto_data.auth_token.is_empty() {
                    let expected_token = crypto_data
                        .auth_token_str()
                        .ok_or(NetworkError::AuthenticationFailed)?;

                    match peer_token {
                        Some(received) => {
                            log::debug!("Token validation: expected='{expected_token}', received='{received}'");

                            // Use constant-time comparison to prevent timing side-channel attacks
                            use subtle::ConstantTimeEq;
                            let is_equal = received.as_bytes().ct_eq(expected_token.as_bytes());

                            if !bool::from(is_equal) {
                                // Token mismatch - REJECT connection immediately
                                log::error!(
                                    "Token mismatch! Expected '{expected_token}', got '{received}'"
                                );
                                return Err(NetworkError::AuthenticationFailed);
                            }
                            log::debug!("Token validation passed");
                            // Token matches - proceed with authentication
                        }
                        None => {
                            // Token expected but not provided - REJECT
                            // This prevents off-LAN brute-force attacks
                            return Err(NetworkError::AuthenticationFailed);
                        }
                    }
                }

                // Token validated (or not required) - store CBOR and proceed
                crypto_data.peer_handshake_msg.clear();
                crypto_data
                    .peer_handshake_msg
                    .extend_from_slice(peer_handshake_cbor)
                    .map_err(|_| NetworkError::BufferFull)?;

                // Store peer's public key for crypto operations
                crypto_data.peer_public_temp.clear();
                crypto_data
                    .peer_public_temp
                    .extend_from_slice(peer_public)
                    .map_err(|_| NetworkError::BufferFull)?;

                // Role differentiation
                // Responder doesn't have its own handshake yet -> request Spake2::Start
                if crypto_data.is_responder && crypto_data.spake2_public.is_empty() {
                    // Responder flow: Request Spake2::Start to generate our handshake
                    log::debug!(
                        "AwaitingHandshake: responder requesting SPAKE2 Start with password_id=None (identity will be 'initiator'/'responder'), psk_len={}",
                        crypto_data.psk.len()
                    );
                    let op_id = 1; // TODO: proper op_id generation
                    let request = CryptoRequest {
                        op_id,
                        kind: CryptoOpKind::Spake2(Spake2Operation::Start {
                            password_id: None,
                            password: &crypto_data.psk,
                            is_responder: crypto_data.is_responder,
                        }),
                    };

                    outputs
                        .push(NetworkOutput::RequestCrypto(request))
                        .map_err(|_| NetworkError::BufferFull)?;

                    // Transition to GeneratingHandshake - waiting for crypto to generate our handshake
                    Ok(State::GeneratingHandshake(GeneratingHandshake::new()))
                } else {
                    // Initiator flow: Already have our handshake -> FinishWithConfirmation

                    // Build transcript = our_handshake_msg || peer_handshake_msg
                    crypto_data.transcript.clear();
                    crypto_data
                        .transcript
                        .extend_from_slice(&crypto_data.our_handshake_msg)
                        .map_err(|_| NetworkError::BufferFull)?;
                    crypto_data
                        .transcript
                        .extend_from_slice(&crypto_data.peer_handshake_msg)
                        .map_err(|_| NetworkError::BufferFull)?;

                    let op_id = 3; // TODO: proper op_id generation
                    let request = CryptoRequest {
                        op_id,
                        kind: CryptoOpKind::Spake2(Spake2Operation::FinishWithConfirmation {
                            state: &crypto_data.spake2_public, // Our SPAKE2 state from Start
                            peer_public: &crypto_data.peer_public_temp,
                            message_transcript: &crypto_data.transcript, // Full CBOR messages
                            my_tls_fingerprint: &crypto_data.my_fingerprint, // TLS cert fingerprint
                            peer_tls_fingerprint: &crypto_data.peer_fingerprint, // Peer's TLS fingerprint
                            is_responder: crypto_data.is_responder,
                        }),
                    };

                    outputs
                        .push(NetworkOutput::RequestCrypto(request))
                        .map_err(|_| NetworkError::BufferFull)?;

                    // Transition to Computing - waiting for crypto to derive keys
                    Ok(State::Computing(Computing::new()))
                }
            }

            NetworkInput::Tick(_) => {
                // Tick is fine, just stay in current state
                Ok(State::AwaitingHandshake(self))
            }
            _ => {
                panic!(
                    "AwaitingHandshake: unexpected input {:?} - only DataReceived or Tick expected",
                    input
                );
            }
        }
    }
}

impl Default for AwaitingHandshake {
    fn default() -> Self {
        Self::new()
    }
}
