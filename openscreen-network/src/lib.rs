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

#![no_std]
#![allow(clippy::too_many_lines, clippy::items_after_statements)]

//! OpenScreen Network Protocol
//!
//! This crate implements the OpenScreen Network Protocol, which handles
//! authentication between devices using SPAKE2 password-authenticated key exchange.
//!
//! The Network Protocol is the first layer in the OpenScreen protocol suite,
//! establishing a secure authenticated channel before any application-level
//! messages (presentations, agent info) can be exchanged.

pub mod crypto_data;
pub mod messages;
pub mod state;
pub mod state_machine;

use openscreen_common::StreamId;
use openscreen_crypto::{CryptoRequest, CryptoResult};

pub use crypto_data::*;
pub use messages::*;
pub use state::*;
pub use state_machine::{
    ConnectionPhase, NetworkStateMachine, PeerAgentInfo, Spake2StateMachine, State as Spake2State,
};

/// Maximum encoded message size
pub const MAX_CBOR_SIZE: usize = 1024;

/// Maximum output queue size
pub const MAX_OUTPUT_QUEUE: usize = 16;

/// Input events to the network state machine
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // CryptoResult is large but infrequent
pub enum NetworkInput<'a> {
    /// Transport connected and ready
    TransportConnected,
    /// A stream was opened (by us or peer)
    StreamOpened(StreamId),
    /// A stream was closed
    StreamClosed(StreamId),
    /// Data received on a stream
    DataReceived(StreamId, &'a [u8]),
    /// A cryptographic operation completed
    CryptoCompleted(CryptoResult),
    /// Time has advanced (for processing state transitions)
    Tick(u64),
}

// NetworkMessage is now defined in messages.rs with a compliant structure
// It is re-exported via `pub use messages::*` above

/// Output actions from the network state machine
#[derive(Debug, Clone)]
pub enum NetworkOutput<'a> {
    /// Open a new unidirectional stream
    OpenUniStream,
    /// Send a structured protocol message (will be CBOR-encoded at transport boundary).
    ///
    /// This contains a type-safe structured message, NOT raw bytes.
    /// The transport layer is responsible for CBOR encoding per W3C OpenScreen spec.
    SendMessage(NetworkMessage<'a>),
    /// Send raw application-layer data (NOT authentication messages).
    ///
    /// This is used by the application protocol layer for non-authentication messages.
    /// Authentication messages MUST use SendMessage() for proper CBOR encoding.
    SendData { data: &'a [u8] },
    /// Close a specific stream
    CloseStream(StreamId),
    /// Close the entire connection
    CloseConnection,
    /// Request a cryptographic operation
    RequestCrypto(CryptoRequest<'a>),
    /// State machine needs to be polled again immediately
    NeedsPoll,
    /// Notify application of an event
    Event(NetworkEvent),
}

/// Events emitted by the network layer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkEvent {
    /// Authentication completed successfully
    Authenticated,
    /// Authentication failed
    AuthenticationFailed(NetworkError),
}

/// Network protocol errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    /// Invalid state for operation
    InvalidState,
    /// Failed to encode message
    EncodeFailed,
    /// Failed to decode message
    DecodeFailed,
    /// Cryptographic operation failed
    CryptoFailed,
    /// Authentication failed
    AuthenticationFailed,
    /// Buffer overflow
    BufferFull,
}
