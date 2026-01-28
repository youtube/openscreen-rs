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

//! AwaitingCapabilities State - Both sides wait for peer's auth-capabilities

use crate::state_machine::{AwaitingHandshake, InitiatingHandshake, State};
use crate::{AuthCapabilities, CryptoData, NetworkError, NetworkInput, NetworkOutput};
use openscreen_crypto::{CryptoOpKind, CryptoRequest, Spake2Operation};

/// State: Waiting for peer's auth-capabilities message
#[derive(Debug)]
pub struct AwaitingCapabilities;

impl Default for AwaitingCapabilities {
    fn default() -> Self {
        Self::new()
    }
}

impl AwaitingCapabilities {
    pub fn new() -> Self {
        Self
    }

    pub fn handle<'a>(
        self,
        crypto_data: &'a mut CryptoData,
        input: &NetworkInput,
        outputs: &mut heapless::Vec<NetworkOutput<'a>, 16>,
    ) -> Result<State, NetworkError> {
        match input {
            NetworkInput::DataReceived(_stream_id, data) => {
                // Decode AuthCapabilities message from CBOR
                let _caps =
                    AuthCapabilities::decode(data).map_err(|_| NetworkError::DecodeFailed)?;

                // Note: Capabilities validation (psk_min_bits_of_entropy, etc.) deferred to future work
                // Currently accepting any valid auth-capabilities message

                if crypto_data.is_responder {
                    // Responder: wait for initiator's handshake
                    log::debug!(
                        "AwaitingCapabilities: responder, transitioning to AwaitingHandshake"
                    );
                    Ok(State::AwaitingHandshake(AwaitingHandshake::new()))
                } else {
                    // Initiator: request crypto to generate handshake
                    log::debug!(
                        "AwaitingCapabilities: initiator, requesting SPAKE2 Start with password_id=None (identity will be 'initiator'/'responder'), psk_len={}",
                        crypto_data.psk.len()
                    );
                    let op = CryptoOpKind::Spake2(Spake2Operation::Start {
                        password_id: None,
                        password: &crypto_data.psk,
                        is_responder: false,
                    });
                    let op_id = 1; // TODO: Use proper op_id tracking
                    outputs
                        .push(NetworkOutput::RequestCrypto(CryptoRequest {
                            op_id,
                            kind: op,
                        }))
                        .map_err(|_| NetworkError::BufferFull)?;

                    Ok(State::InitiatingHandshake(InitiatingHandshake::new()))
                }
            }
            NetworkInput::Tick(_) => {
                // Tick is fine, just stay in current state
                Ok(State::AwaitingCapabilities(self))
            }
            _ => {
                panic!("AwaitingCapabilities: unexpected input {:?} - only DataReceived or Tick expected", input);
            }
        }
    }
}
