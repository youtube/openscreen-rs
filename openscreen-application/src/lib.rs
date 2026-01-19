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
#![allow(
    unused_attributes,
    deprecated,
    clippy::too_many_lines,
    clippy::large_enum_variant,
    clippy::used_underscore_binding,
    clippy::empty_line_after_doc_comments
)]

//! OpenScreen Application Protocol
//!
//! This crate implements the OpenScreen Application Protocol, which provides
//! Agent Info and Presentation API functionality on top of the Network Protocol's
//! authenticated channel.
//!
//! The Application Protocol is the second layer in the OpenScreen protocol suite,
//! sitting above the Network Protocol (authentication).

pub mod messages;
pub mod state;

use heapless::{String, Vec};
use openscreen_common::{MessageError, StreamId, MAX_CBOR_SIZE};
use openscreen_crypto::{CryptoRequest, CryptoResult};
use openscreen_network::{
    NetworkError, NetworkEvent, NetworkInput, NetworkOutput, Spake2StateMachine,
};

pub use messages::*;
pub use state::*;

/// Maximum output queue size
pub const MAX_OUTPUT_QUEUE: usize = 16;

/// Input events to the application state machine
#[derive(Debug, Clone)]
pub enum ApplicationInput<'a> {
    // User commands
    /// Start a presentation with the given URL
    StartPresentation {
        url: &'a str,
        presentation_id: &'a str,
    },

    /// Terminate a presentation
    TerminatePresentation {
        presentation_id: &'a str,
        reason: PresentationTerminationReason,
    },

    /// Check URL availability for presentation
    CheckUrlAvailability {
        urls: &'a [&'a str],
        watch_duration: u64,
    },

    /// Open a presentation connection
    OpenPresentationConnection {
        presentation_id: &'a str,
        url: &'a str,
    },

    /// Send data on a presentation connection
    SendPresentationMessage {
        connection_id: u64,
        message: &'a [u8],
    },

    /// Close a presentation connection
    ClosePresentationConnection {
        connection_id: u64,
        reason: PresentationConnectionCloseReason,
    },

    /// Request agent status
    RequestAgentStatus { status_message: Option<&'a str> },

    /// Request agent info
    RequestAgentInfo,

    // Transport events (delegated to network layer)
    /// Transport connected and ready
    TransportConnected,
    /// A stream was opened
    StreamOpened(StreamId),
    /// A stream was closed
    StreamClosed(StreamId),
    /// Data received on a stream
    DataReceived(StreamId, &'a [u8]),
    /// A cryptographic operation completed
    CryptoCompleted(CryptoResult),
    /// Time has advanced
    Tick(u64),
}

/// Output actions from the application state machine
#[derive(Debug, Clone)]
pub enum ApplicationOutput<'a> {
    /// Open a new bidirectional stream
    OpenBiStream,
    /// Send data on a specific stream
    SendData {
        stream: StreamId,
        data: Vec<u8, MAX_CBOR_SIZE>,
    },
    /// Close a specific stream
    CloseStream(StreamId),
    /// Close the entire connection
    CloseConnection,
    /// Request a cryptographic operation
    RequestCrypto(CryptoRequest<'a>),
    /// State machine needs to be polled again
    NeedsPoll,
    /// Notify application of an event
    Event(ApplicationEvent),
}

/// Events emitted by the application layer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationEvent {
    /// Authentication completed successfully
    Authenticated,
    /// Authentication failed
    AuthenticationFailed,
    /// Presentation started successfully
    PresentationStarted { connection_id: u64 },
    /// Presentation was rejected
    PresentationRejected,
    /// Presentation terminated
    PresentationTerminated {
        presentation_id: String<256>,
        reason: PresentationTerminationReason,
    },
    /// Presentation connection opened
    PresentationConnectionOpened { connection_id: u64 },
    /// Presentation message received
    PresentationMessageReceived {
        connection_id: u64,
        message: Vec<u8, 1024>,
    },
    /// Presentation connection closed
    PresentationConnectionClosed {
        connection_id: u64,
        reason: PresentationConnectionCloseReason,
    },
    /// URL availability changed
    UrlAvailabilityChanged {
        urls: Vec<String<256>, 16>,
        available: bool,
    },
    /// Agent status received
    AgentStatusReceived { status_message: Option<String<256>> },
    /// Agent info changed
    AgentInfoChanged,
    /// Presentation changed (connection count)
    PresentationChanged,
}

/// Application protocol errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationError {
    /// Invalid state for operation
    InvalidState,
    /// Failed to encode message
    EncodeFailed,
    /// Failed to decode message
    DecodeFailed,
    /// Network layer error
    NetworkError(NetworkError),
    /// Buffer overflow
    BufferFull,
    /// Not authenticated yet
    NotAuthenticated,
}

impl From<NetworkError> for ApplicationError {
    fn from(err: NetworkError) -> Self {
        ApplicationError::NetworkError(err)
    }
}

impl From<MessageError> for ApplicationError {
    fn from(_err: MessageError) -> Self {
        ApplicationError::EncodeFailed
    }
}

/// Application protocol state machine
pub struct ApplicationStateMachine {
    network: Spake2StateMachine,
    app_state: ApplicationState,
    next_request_id: u64,
}

impl ApplicationStateMachine {
    /// Create a new application state machine
    pub fn new() -> Self {
        Self {
            network: Spake2StateMachine::default(),
            app_state: ApplicationState::Idle,
            next_request_id: 1,
        }
    }

    /// Check if authenticated
    pub fn is_authenticated(&self) -> bool {
        self.network.is_authenticated()
    }

    /// Get current application state
    pub fn application_state(&self) -> ApplicationState {
        self.app_state
    }

    /// Main state transition function
    ///
    /// Takes an input event and returns a queue of output actions to perform.
    pub fn handle_input<'a>(
        &'a mut self,
        input: ApplicationInput<'a>,
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        outputs.clear();

        match input {
            // User commands handled at application layer
            ApplicationInput::StartPresentation {
                url,
                presentation_id,
            } => self.handle_start_presentation(url, presentation_id, outputs),

            ApplicationInput::TerminatePresentation {
                presentation_id,
                reason,
            } => self.handle_terminate_presentation(presentation_id, reason, outputs),

            ApplicationInput::CheckUrlAvailability {
                urls,
                watch_duration,
            } => self.handle_check_url_availability(urls, watch_duration, outputs),

            ApplicationInput::OpenPresentationConnection {
                presentation_id,
                url,
            } => self.handle_open_presentation_connection(presentation_id, url, outputs),

            ApplicationInput::SendPresentationMessage {
                connection_id,
                message,
            } => self.handle_send_presentation_message(connection_id, message, outputs),

            ApplicationInput::ClosePresentationConnection {
                connection_id,
                reason,
            } => self.handle_close_presentation_connection(connection_id, reason, outputs),

            ApplicationInput::RequestAgentStatus { status_message } => {
                self.handle_request_agent_status(status_message, outputs)
            }

            ApplicationInput::RequestAgentInfo => self.handle_request_agent_info(outputs),

            // Transport/crypto events delegated to network layer
            ApplicationInput::TransportConnected => {
                self.handle_network_event(NetworkInput::TransportConnected, outputs)
            }
            ApplicationInput::StreamOpened(id) => {
                self.handle_network_event(NetworkInput::StreamOpened(id), outputs)
            }
            ApplicationInput::StreamClosed(id) => {
                self.handle_network_event(NetworkInput::StreamClosed(id), outputs)
            }
            ApplicationInput::DataReceived(stream, data) => {
                self.handle_data_received(stream, data, outputs)
            }
            ApplicationInput::CryptoCompleted(result) => {
                self.handle_network_event(NetworkInput::CryptoCompleted(result), outputs)
            }
            ApplicationInput::Tick(timestamp) => {
                self.handle_network_event(NetworkInput::Tick(timestamp), outputs)
            }
        }
    }

    fn handle_start_presentation<'a>(
        &mut self,
        url: &'a str,
        presentation_id: &'a str,
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        if !self.is_authenticated() {
            return Err(ApplicationError::NotAuthenticated);
        }

        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);

        let msg = ApplicationMessage::PresentationStartRequest(PresentationStartRequest {
            request_id,
            presentation_id,
            url,
            headers: Vec::new(),
        });

        let mut buf = Vec::new();
        msg.encode(&mut buf)?;

        outputs
            .push(ApplicationOutput::SendData {
                stream: 0,
                data: buf,
            })
            .map_err(|_| ApplicationError::BufferFull)?;

        Ok(())
    }

    fn handle_terminate_presentation<'a>(
        &mut self,
        presentation_id: &'a str,
        reason: PresentationTerminationReason,
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        if !self.is_authenticated() {
            return Err(ApplicationError::NotAuthenticated);
        }

        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);

        let msg =
            ApplicationMessage::PresentationTerminationRequest(PresentationTerminationRequest {
                request_id,
                presentation_id,
                reason,
            });

        let mut buf = Vec::new();
        msg.encode(&mut buf)?;

        outputs
            .push(ApplicationOutput::SendData {
                stream: 0,
                data: buf,
            })
            .map_err(|_| ApplicationError::BufferFull)?;

        Ok(())
    }

    fn handle_check_url_availability<'a>(
        &mut self,
        urls: &'a [&'a str],
        watch_duration: u64,
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        if !self.is_authenticated() {
            return Err(ApplicationError::NotAuthenticated);
        }

        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);

        let mut url_vec = Vec::new();
        for url in urls {
            url_vec
                .push(*url)
                .map_err(|_| ApplicationError::BufferFull)?;
        }

        let msg = ApplicationMessage::PresentationUrlAvailabilityRequest(
            PresentationUrlAvailabilityRequest {
                request_id,
                urls: url_vec,
                watch_duration,
                watch_id: 0, // No watch
            },
        );

        let mut buf = Vec::new();
        msg.encode(&mut buf)?;

        outputs
            .push(ApplicationOutput::SendData {
                stream: 0,
                data: buf,
            })
            .map_err(|_| ApplicationError::BufferFull)?;

        Ok(())
    }

    fn handle_open_presentation_connection<'a>(
        &mut self,
        presentation_id: &'a str,
        url: &'a str,
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        if !self.is_authenticated() {
            return Err(ApplicationError::NotAuthenticated);
        }

        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);

        let msg = ApplicationMessage::PresentationConnectionOpenRequest(
            PresentationConnectionOpenRequest {
                request_id,
                presentation_id,
                url,
            },
        );

        let mut buf = Vec::new();
        msg.encode(&mut buf)?;

        outputs
            .push(ApplicationOutput::SendData {
                stream: 0,
                data: buf,
            })
            .map_err(|_| ApplicationError::BufferFull)?;

        Ok(())
    }

    fn handle_send_presentation_message<'a>(
        &mut self,
        connection_id: u64,
        message: &'a [u8],
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        if !self.is_authenticated() {
            return Err(ApplicationError::NotAuthenticated);
        }

        let msg =
            ApplicationMessage::PresentationConnectionMessage(PresentationConnectionMessage {
                connection_id,
                message,
            });

        let mut buf = Vec::new();
        msg.encode(&mut buf)?;

        outputs
            .push(ApplicationOutput::SendData {
                stream: 0,
                data: buf,
            })
            .map_err(|_| ApplicationError::BufferFull)?;

        Ok(())
    }

    fn handle_close_presentation_connection<'a>(
        &mut self,
        connection_id: u64,
        reason: PresentationConnectionCloseReason,
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        if !self.is_authenticated() {
            return Err(ApplicationError::NotAuthenticated);
        }

        let msg = ApplicationMessage::PresentationConnectionCloseEvent(
            PresentationConnectionCloseEvent {
                connection_id,
                reason,
                error_message: None,
                connection_count: 0, // Unknown
            },
        );

        let mut buf = Vec::new();
        msg.encode(&mut buf)?;

        outputs
            .push(ApplicationOutput::SendData {
                stream: 0,
                data: buf,
            })
            .map_err(|_| ApplicationError::BufferFull)?;

        Ok(())
    }

    fn handle_request_agent_status<'a>(
        &mut self,
        status_message: Option<&'a str>,
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        if !self.is_authenticated() {
            return Err(ApplicationError::NotAuthenticated);
        }

        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);

        let status = status_message.map(|s| Status { status: s });

        let msg = ApplicationMessage::AgentStatusRequest(AgentStatusRequest { request_id, status });

        let mut buf = Vec::new();
        msg.encode(&mut buf)?;

        outputs
            .push(ApplicationOutput::SendData {
                stream: 0,
                data: buf,
            })
            .map_err(|_| ApplicationError::BufferFull)?;

        Ok(())
    }

    fn handle_request_agent_info<'a>(
        &mut self,
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        if !self.is_authenticated() {
            return Err(ApplicationError::NotAuthenticated);
        }

        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);

        let msg = ApplicationMessage::AgentInfoRequest(AgentInfoRequest { request_id });

        let mut buf = Vec::new();
        msg.encode(&mut buf)?;

        outputs
            .push(ApplicationOutput::SendData {
                stream: 0,
                data: buf,
            })
            .map_err(|_| ApplicationError::BufferFull)?;

        Ok(())
    }

    fn handle_data_received<'a>(
        &'a mut self,
        stream: StreamId,
        data: &'a [u8],
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        // Try to decode as ApplicationMessage first
        if let Ok(app_msg) = ApplicationMessage::decode(data) {
            self.handle_application_message(app_msg, outputs)
        } else {
            // Might be a network message, delegate to network layer
            self.handle_network_event(NetworkInput::DataReceived(stream, data), outputs)
        }
    }

    fn handle_application_message<'a>(
        &mut self,
        msg: ApplicationMessage<'a>,
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        match msg {
            ApplicationMessage::AgentInfoResponse(_response) => {
                outputs
                    .push(ApplicationOutput::Event(ApplicationEvent::AgentInfoChanged))
                    .map_err(|_| ApplicationError::BufferFull)?;
            }
            ApplicationMessage::AgentStatusResponse(_response) => {
                // Extract status message if present
                let status_msg = _response.status.map(|s| {
                    let mut string = String::new();
                    let _ = string.push_str(s.status);
                    string
                });
                outputs
                    .push(ApplicationOutput::Event(
                        ApplicationEvent::AgentStatusReceived {
                            status_message: status_msg,
                        },
                    ))
                    .map_err(|_| ApplicationError::BufferFull)?;
            }
            ApplicationMessage::AgentInfoEvent(_event) => {
                outputs
                    .push(ApplicationOutput::Event(ApplicationEvent::AgentInfoChanged))
                    .map_err(|_| ApplicationError::BufferFull)?;
            }
            ApplicationMessage::PresentationStartResponse(response) => match response.result {
                PresentationResult::Success => {
                    self.app_state = ApplicationState::Presenting;
                    outputs
                        .push(ApplicationOutput::Event(
                            ApplicationEvent::PresentationStarted {
                                connection_id: response.connection_id,
                            },
                        ))
                        .map_err(|_| ApplicationError::BufferFull)?;
                }
                _ => {
                    outputs
                        .push(ApplicationOutput::Event(
                            ApplicationEvent::PresentationRejected,
                        ))
                        .map_err(|_| ApplicationError::BufferFull)?;
                }
            },
            ApplicationMessage::PresentationTerminationEvent(event) => {
                self.app_state = ApplicationState::Authenticated;
                let mut presentation_id = String::new();
                let _ = presentation_id.push_str(event.presentation_id);
                outputs
                    .push(ApplicationOutput::Event(
                        ApplicationEvent::PresentationTerminated {
                            presentation_id,
                            reason: event.reason,
                        },
                    ))
                    .map_err(|_| ApplicationError::BufferFull)?;
            }
            ApplicationMessage::PresentationConnectionOpenResponse(response) => {
                if response.result == PresentationResult::Success {
                    outputs
                        .push(ApplicationOutput::Event(
                            ApplicationEvent::PresentationConnectionOpened {
                                connection_id: response.connection_id,
                            },
                        ))
                        .map_err(|_| ApplicationError::BufferFull)?;
                }
            }
            ApplicationMessage::PresentationConnectionMessage(msg) => {
                let mut message_vec = Vec::new();
                message_vec
                    .extend_from_slice(msg.message)
                    .map_err(|_| ApplicationError::BufferFull)?;
                outputs
                    .push(ApplicationOutput::Event(
                        ApplicationEvent::PresentationMessageReceived {
                            connection_id: msg.connection_id,
                            message: message_vec,
                        },
                    ))
                    .map_err(|_| ApplicationError::BufferFull)?;
            }
            ApplicationMessage::PresentationConnectionCloseEvent(event) => {
                outputs
                    .push(ApplicationOutput::Event(
                        ApplicationEvent::PresentationConnectionClosed {
                            connection_id: event.connection_id,
                            reason: event.reason,
                        },
                    ))
                    .map_err(|_| ApplicationError::BufferFull)?;
            }
            ApplicationMessage::PresentationChangeEvent(_event) => {
                outputs
                    .push(ApplicationOutput::Event(
                        ApplicationEvent::PresentationChanged,
                    ))
                    .map_err(|_| ApplicationError::BufferFull)?;
            }
            // Other messages we don't handle yet
            _ => {}
        }
        Ok(())
    }

    fn handle_network_event<'a>(
        &'a mut self,
        input: NetworkInput<'a>,
        outputs: &mut Vec<ApplicationOutput<'a>, MAX_OUTPUT_QUEUE>,
    ) -> Result<(), ApplicationError> {
        let mut network_outputs = Vec::new();
        self.network.handle(&input, &mut network_outputs)?;

        // Convert NetworkOutput to ApplicationOutput
        for output in network_outputs {
            match output {
                NetworkOutput::OpenUniStream => {
                    outputs
                        .push(ApplicationOutput::OpenBiStream)
                        .map_err(|_| ApplicationError::BufferFull)?;
                }
                NetworkOutput::SendMessage(_msg) => {
                    // Network-level authentication messages (AuthCapabilities, AuthHandshake, AuthConfirmation)
                    // are NOT handled by application layer - they're handled directly by transport (Quinn)
                    // Just ignore them here
                }
                NetworkOutput::SendData { .. } => {
                    // Raw application data - also handled by transport layer
                    // Just ignore here
                }
                NetworkOutput::CloseStream(stream) => {
                    outputs
                        .push(ApplicationOutput::CloseStream(stream))
                        .map_err(|_| ApplicationError::BufferFull)?;
                }
                NetworkOutput::CloseConnection => {
                    outputs
                        .push(ApplicationOutput::CloseConnection)
                        .map_err(|_| ApplicationError::BufferFull)?;
                }
                NetworkOutput::RequestCrypto(req) => {
                    outputs
                        .push(ApplicationOutput::RequestCrypto(req))
                        .map_err(|_| ApplicationError::BufferFull)?;
                }
                NetworkOutput::NeedsPoll => {
                    outputs
                        .push(ApplicationOutput::NeedsPoll)
                        .map_err(|_| ApplicationError::BufferFull)?;
                }
                NetworkOutput::Event(event) => {
                    // Convert network events to application events
                    match event {
                        NetworkEvent::Authenticated => {
                            self.app_state = ApplicationState::Authenticated;
                            outputs
                                .push(ApplicationOutput::Event(ApplicationEvent::Authenticated))
                                .map_err(|_| ApplicationError::BufferFull)?;
                        }
                        NetworkEvent::AuthenticationFailed(_err) => {
                            outputs
                                .push(ApplicationOutput::Event(
                                    ApplicationEvent::AuthenticationFailed,
                                ))
                                .map_err(|_| ApplicationError::BufferFull)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for ApplicationStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

// Certificate management (only available with `std` for binaries)
#[cfg(all(feature = "bin", not(target_family = "wasm")))]
pub mod cert;
