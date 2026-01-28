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

//! OpenScreen Application Protocol Message Types
//!
//! This module implements CBOR encoding/decoding for OpenScreen application protocol messages
//! (Agent Info and Presentation API) based on the W3C specification's CDDL definitions.
//!
//! Reference: ref/w3c_ref/messages_appendix.cddl

use heapless::Vec;
use minicbor::{Decoder, Encoder};
use openscreen_common::{
    decode_type_key, encode_type_key, MessageError, MAX_STRING_LENGTH, MAX_URLS,
};

/// A wrapper around heapless::Vec that implements minicbor's Write trait
struct VecWriter<'a, const N: usize> {
    vec: &'a mut Vec<u8, N>,
}

impl<'a, const N: usize> VecWriter<'a, N> {
    fn new(vec: &'a mut Vec<u8, N>) -> Self {
        Self { vec }
    }
}

impl<'a, const N: usize> minicbor::encode::Write for VecWriter<'a, N> {
    type Error = MessageError;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.vec
            .extend_from_slice(buf)
            .map_err(|_| MessageError::BufferFull)
    }
}

/// Maximum size for a single CBOR message
pub const MAX_MESSAGE_SIZE: usize = 1024;

/// Maximum length for string fields (display names, model names, URLs)
pub const MAX_STRING_LEN: usize = MAX_STRING_LENGTH;

/// Maximum size for byte arrays
pub const MAX_BYTES_LEN: usize = 64;

/// Application message type keys as defined in CDDL
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ApplicationMessageType {
    // Agent info messages (10-13, 120)
    AgentInfoRequest = 10,
    AgentInfoResponse = 11,
    AgentStatusRequest = 12,
    AgentStatusResponse = 13,
    AgentInfoEvent = 120,

    // Presentation messages (14-16, 103-110, 113, 121)
    PresentationUrlAvailabilityRequest = 14,
    PresentationUrlAvailabilityResponse = 15,
    PresentationConnectionMessage = 16,
    PresentationUrlAvailabilityEvent = 103,
    PresentationStartRequest = 104,
    PresentationStartResponse = 105,
    PresentationTerminationRequest = 106,
    PresentationTerminationResponse = 107,
    PresentationTerminationEvent = 108,
    PresentationConnectionOpenRequest = 109,
    PresentationConnectionOpenResponse = 110,
    PresentationConnectionCloseEvent = 113,
    PresentationChangeEvent = 121,
}

impl ApplicationMessageType {
    pub fn from_u16(value: u16) -> Result<Self, MessageError> {
        match value {
            10 => Ok(Self::AgentInfoRequest),
            11 => Ok(Self::AgentInfoResponse),
            12 => Ok(Self::AgentStatusRequest),
            13 => Ok(Self::AgentStatusResponse),
            120 => Ok(Self::AgentInfoEvent),
            14 => Ok(Self::PresentationUrlAvailabilityRequest),
            15 => Ok(Self::PresentationUrlAvailabilityResponse),
            16 => Ok(Self::PresentationConnectionMessage),
            103 => Ok(Self::PresentationUrlAvailabilityEvent),
            104 => Ok(Self::PresentationStartRequest),
            105 => Ok(Self::PresentationStartResponse),
            106 => Ok(Self::PresentationTerminationRequest),
            107 => Ok(Self::PresentationTerminationResponse),
            108 => Ok(Self::PresentationTerminationEvent),
            109 => Ok(Self::PresentationConnectionOpenRequest),
            110 => Ok(Self::PresentationConnectionOpenResponse),
            113 => Ok(Self::PresentationConnectionCloseEvent),
            121 => Ok(Self::PresentationChangeEvent),
            _ => Err(MessageError::InvalidMessageType),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCapability {
    ReceiveAudio = 1,
    ReceiveVideo = 2,
    ReceivePresentation = 3,
    ControlPresentation = 4,
    ReceiveRemotePlayback = 5,
    ControlRemotePlayback = 6,
    ReceiveStreaming = 7,
    SendStreaming = 8,
}

impl AgentCapability {
    pub fn from_u8(value: u8) -> Result<Self, MessageError> {
        match value {
            1 => Ok(Self::ReceiveAudio),
            2 => Ok(Self::ReceiveVideo),
            3 => Ok(Self::ReceivePresentation),
            4 => Ok(Self::ControlPresentation),
            5 => Ok(Self::ReceiveRemotePlayback),
            6 => Ok(Self::ControlRemotePlayback),
            7 => Ok(Self::ReceiveStreaming),
            8 => Ok(Self::SendStreaming),
            _ => Err(MessageError::InvalidField),
        }
    }
}

/// Agent information
/// CDDL:
/// agent-info = {
///   0: text ; display-name
///   1: text ; model-name
///   2: [* agent-capability] ; capabilities
///   3: text ; state-token
///   4: [* text] ; locales
/// }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInfo<'a> {
    pub display_name: &'a str,
    pub model_name: &'a str,
    pub capabilities: Vec<AgentCapability, 16>,
    pub state_token: &'a str,
    pub locales: Vec<&'a str, 8>,
}

/// Agent info request message (type key 10)
/// CDDL: agent-info-request = { 0: request-id }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentInfoRequest {
    pub request_id: u64,
}

impl AgentInfoRequest {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(ApplicationMessageType::AgentInfoRequest as u16, buf)?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with request-id
        encoder.map(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::AgentInfoRequest as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode the CBOR body (after type key has been consumed)
    pub fn decode_body(body: &[u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        // Body is a map with one field
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(1) {
            return Err(MessageError::InvalidField);
        }

        // Field 0: request-id
        let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
        if key != 0 {
            return Err(MessageError::InvalidField);
        }
        let request_id = decoder.u64().map_err(|_| MessageError::DecodeFailed)?;

        Ok(Self { request_id })
    }
}

/// Agent info response message (type key 11)
/// CDDL: agent-info-response = { 0: request-id, 1: agent-info }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInfoResponse<'a> {
    pub request_id: u64,
    pub agent_info: AgentInfo<'a>,
}

impl<'a> AgentInfoResponse<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(ApplicationMessageType::AgentInfoResponse as u16, buf)?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 2 fields
        encoder.map(2).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: request-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: agent-info (nested map)
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder.map(5).map_err(|_| MessageError::EncodeFailed)?;

        // agent-info field 0: display-name
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.agent_info.display_name)
            .map_err(|_| MessageError::EncodeFailed)?;

        // agent-info field 1: model-name
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.agent_info.model_name)
            .map_err(|_| MessageError::EncodeFailed)?;

        // agent-info field 2: capabilities array
        encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .array(self.agent_info.capabilities.len() as u64)
            .map_err(|_| MessageError::EncodeFailed)?;
        for cap in &self.agent_info.capabilities {
            encoder
                .u8(*cap as u8)
                .map_err(|_| MessageError::EncodeFailed)?;
        }

        // agent-info field 3: state-token
        encoder.u8(3).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.agent_info.state_token)
            .map_err(|_| MessageError::EncodeFailed)?;

        // agent-info field 4: locales array
        encoder.u8(4).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .array(self.agent_info.locales.len() as u64)
            .map_err(|_| MessageError::EncodeFailed)?;
        for locale in &self.agent_info.locales {
            encoder
                .str(locale)
                .map_err(|_| MessageError::EncodeFailed)?;
        }

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::AgentInfoResponse as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode the CBOR body (after type key has been consumed)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        // Body is a map with 2 fields
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(2) {
            return Err(MessageError::InvalidField);
        }

        // Field 0: request-id
        let key0 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
        if key0 != 0 {
            return Err(MessageError::InvalidField);
        }
        let request_id = decoder.u64().map_err(|_| MessageError::DecodeFailed)?;

        // Field 1: agent-info
        let key1 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
        if key1 != 1 {
            return Err(MessageError::InvalidField);
        }

        // Decode agent-info map
        let agent_map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if agent_map_len != Some(5) {
            return Err(MessageError::InvalidField);
        }

        // Decode all agent-info fields
        let mut display_name = None;
        let mut model_name = None;
        let mut capabilities = Vec::new();
        let mut state_token = None;
        let mut locales = Vec::new();

        for _ in 0..5 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    let name = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                    if name.len() > MAX_STRING_LEN {
                        return Err(MessageError::FieldTooLong);
                    }
                    display_name = Some(name);
                }
                1 => {
                    let name = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                    if name.len() > MAX_STRING_LEN {
                        return Err(MessageError::FieldTooLong);
                    }
                    model_name = Some(name);
                }
                2 => {
                    let cap_array_len = decoder.array().map_err(|_| MessageError::DecodeFailed)?;
                    if let Some(len) = cap_array_len {
                        for _ in 0..len {
                            let cap_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                            let cap = AgentCapability::from_u8(cap_u8)?;
                            capabilities
                                .push(cap)
                                .map_err(|_| MessageError::BufferFull)?;
                        }
                    }
                }
                3 => {
                    let token = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                    if token.len() > MAX_STRING_LEN {
                        return Err(MessageError::FieldTooLong);
                    }
                    state_token = Some(token);
                }
                4 => {
                    let locale_array_len =
                        decoder.array().map_err(|_| MessageError::DecodeFailed)?;
                    if let Some(len) = locale_array_len {
                        for _ in 0..len {
                            let locale = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                            if locale.len() > MAX_STRING_LEN {
                                return Err(MessageError::FieldTooLong);
                            }
                            locales.push(locale).map_err(|_| MessageError::BufferFull)?;
                        }
                    }
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            request_id,
            agent_info: AgentInfo {
                display_name: display_name.ok_or(MessageError::MissingField)?,
                model_name: model_name.ok_or(MessageError::MissingField)?,
                capabilities,
                state_token: state_token.ok_or(MessageError::MissingField)?,
                locales,
            },
        })
    }
}

// ============================================================================
// ============================================================================

/// Status information
/// CDDL: status = { 0: text }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status<'a> {
    pub status: &'a str,
}

/// Agent status request message (type key 12)
/// CDDL: agent-status-request = { request, ? 1: status }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStatusRequest<'a> {
    pub request_id: u64,
    pub status: Option<Status<'a>>,
}

impl<'a> AgentStatusRequest<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(ApplicationMessageType::AgentStatusRequest as u16, buf)?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with request-id and optional status
        let field_count = if self.status.is_some() { 2 } else { 1 };
        encoder
            .map(field_count)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: request-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: status (optional)
        if let Some(ref status) = self.status {
            encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
            // status is a map with one field
            encoder.map(1).map_err(|_| MessageError::EncodeFailed)?;
            encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
            encoder
                .str(status.status)
                .map_err(|_| MessageError::EncodeFailed)?;
        }

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::AgentStatusRequest as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode the CBOR body (after type key has been consumed)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        // Decode body map
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len.is_none() {
            return Err(MessageError::DecodeFailed);
        }

        let mut request_id = None;
        let mut status = None;

        for _ in 0..map_len.unwrap() {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    request_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    // status is a map
                    let status_map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
                    if status_map_len != Some(1) {
                        return Err(MessageError::DecodeFailed);
                    }
                    let status_key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                    if status_key != 0 {
                        return Err(MessageError::InvalidField);
                    }
                    let status_str = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                    if status_str.len() > MAX_STRING_LEN {
                        return Err(MessageError::FieldTooLong);
                    }
                    status = Some(Status { status: status_str });
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            request_id: request_id.ok_or(MessageError::MissingField)?,
            status,
        })
    }
}

/// Agent status response message (type key 13)
/// CDDL: agent-status-response = { response, ? 1: status }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStatusResponse<'a> {
    pub request_id: u64,
    pub status: Option<Status<'a>>,
}

impl<'a> AgentStatusResponse<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(ApplicationMessageType::AgentStatusResponse as u16, buf)?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with request-id and optional status
        let field_count = if self.status.is_some() { 2 } else { 1 };
        encoder
            .map(field_count)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: request-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: status (optional)
        if let Some(ref status) = self.status {
            encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
            // status is a map with one field
            encoder.map(1).map_err(|_| MessageError::EncodeFailed)?;
            encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
            encoder
                .str(status.status)
                .map_err(|_| MessageError::EncodeFailed)?;
        }

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::AgentStatusResponse as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode the CBOR body (after type key has been consumed)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        // Decode body map
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len.is_none() {
            return Err(MessageError::DecodeFailed);
        }

        let mut request_id = None;
        let mut status = None;

        for _ in 0..map_len.unwrap() {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    request_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    // status is a map
                    let status_map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
                    if status_map_len != Some(1) {
                        return Err(MessageError::DecodeFailed);
                    }
                    let status_key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                    if status_key != 0 {
                        return Err(MessageError::InvalidField);
                    }
                    let status_str = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                    if status_str.len() > MAX_STRING_LEN {
                        return Err(MessageError::FieldTooLong);
                    }
                    status = Some(Status { status: status_str });
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            request_id: request_id.ok_or(MessageError::MissingField)?,
            status,
        })
    }
}

/// Agent info event message (type key 120)
/// CDDL: agent-info-event = { 0: agent-info }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInfoEvent<'a> {
    pub agent_info: AgentInfo<'a>,
}

impl<'a> AgentInfoEvent<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(ApplicationMessageType::AgentInfoEvent as u16, buf)?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with one field (agent-info)
        encoder.map(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;

        // Encode agent-info as a map with 5 fields
        encoder.map(5).map_err(|_| MessageError::EncodeFailed)?;

        // agent-info field 0: display-name
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.agent_info.display_name)
            .map_err(|_| MessageError::EncodeFailed)?;

        // agent-info field 1: model-name
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.agent_info.model_name)
            .map_err(|_| MessageError::EncodeFailed)?;

        // agent-info field 2: capabilities array
        encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .array(self.agent_info.capabilities.len() as u64)
            .map_err(|_| MessageError::EncodeFailed)?;
        for cap in &self.agent_info.capabilities {
            encoder
                .u8(*cap as u8)
                .map_err(|_| MessageError::EncodeFailed)?;
        }

        // agent-info field 3: state-token
        encoder.u8(3).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.agent_info.state_token)
            .map_err(|_| MessageError::EncodeFailed)?;

        // agent-info field 4: locales array
        encoder.u8(4).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .array(self.agent_info.locales.len() as u64)
            .map_err(|_| MessageError::EncodeFailed)?;
        for locale in &self.agent_info.locales {
            encoder
                .str(locale)
                .map_err(|_| MessageError::EncodeFailed)?;
        }

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::AgentInfoEvent as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode the CBOR body (after type key has been consumed)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        // Body is a map with agent-info
        let body_map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if body_map_len != Some(1) {
            return Err(MessageError::DecodeFailed);
        }

        let body_key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
        if body_key != 0 {
            return Err(MessageError::InvalidField);
        }

        // Decode agent-info map
        let agent_info_map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if agent_info_map_len != Some(5) {
            return Err(MessageError::DecodeFailed);
        }

        let mut display_name = None;
        let mut model_name = None;
        let mut capabilities = Vec::new();
        let mut state_token = None;
        let mut locales = Vec::new();

        for _ in 0..5 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    let name = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                    if name.len() > MAX_STRING_LEN {
                        return Err(MessageError::FieldTooLong);
                    }
                    display_name = Some(name);
                }
                1 => {
                    let name = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                    if name.len() > MAX_STRING_LEN {
                        return Err(MessageError::FieldTooLong);
                    }
                    model_name = Some(name);
                }
                2 => {
                    let cap_array_len = decoder.array().map_err(|_| MessageError::DecodeFailed)?;
                    if let Some(len) = cap_array_len {
                        for _ in 0..len {
                            let cap_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                            let cap = AgentCapability::from_u8(cap_u8)?;
                            capabilities
                                .push(cap)
                                .map_err(|_| MessageError::BufferFull)?;
                        }
                    }
                }
                3 => {
                    let token = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                    if token.len() > MAX_STRING_LEN {
                        return Err(MessageError::FieldTooLong);
                    }
                    state_token = Some(token);
                }
                4 => {
                    let locale_array_len =
                        decoder.array().map_err(|_| MessageError::DecodeFailed)?;
                    if let Some(len) = locale_array_len {
                        for _ in 0..len {
                            let locale = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                            if locale.len() > MAX_STRING_LEN {
                                return Err(MessageError::FieldTooLong);
                            }
                            locales.push(locale).map_err(|_| MessageError::BufferFull)?;
                        }
                    }
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            agent_info: AgentInfo {
                display_name: display_name.ok_or(MessageError::MissingField)?,
                model_name: model_name.ok_or(MessageError::MissingField)?,
                capabilities,
                state_token: state_token.ok_or(MessageError::MissingField)?,
                locales,
            },
        })
    }
}

/// Result codes for presentation operations
/// CDDL: result = (success: 1, invalid-url: 10, invalid-presentation-id: 11, ...)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum PresentationResult {
    Success = 1,
    InvalidUrl = 10,
    InvalidPresentationId = 11,
    Timeout = 100,
    TransientError = 101,
}

impl PresentationResult {
    pub fn from_u8(value: u8) -> Result<Self, MessageError> {
        match value {
            1 => Ok(Self::Success),
            10 => Ok(Self::InvalidUrl),
            11 => Ok(Self::InvalidPresentationId),
            100 => Ok(Self::Timeout),
            101 => Ok(Self::TransientError),
            _ => Err(MessageError::InvalidField),
        }
    }
}

/// Presentation termination source
/// CDDL: presentation-termination-source = &(controller: 1, receiver: 2, unknown: 255)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum PresentationTerminationSource {
    Controller = 1,
    Receiver = 2,
    Unknown = 255,
}

impl PresentationTerminationSource {
    pub fn from_u8(value: u8) -> Result<Self, MessageError> {
        match value {
            1 => Ok(Self::Controller),
            2 => Ok(Self::Receiver),
            255 => Ok(Self::Unknown),
            _ => Err(MessageError::InvalidField),
        }
    }
}

/// Presentation termination reason
/// CDDL: presentation-termination-reason = &(
///   application-request: 1,
///   user-request: 2,
///   receiver-replaced-presentation: 20,
///   receiver-idle-too-long: 30,
///   receiver-attempted-to-navigate: 31,
///   receiver-powering-down: 100,
///   receiver-error: 101,
///   unknown: 255
/// )
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum PresentationTerminationReason {
    ApplicationRequest = 1,
    UserRequest = 2,
    ReceiverReplacedPresentation = 20,
    ReceiverIdleTooLong = 30,
    ReceiverAttemptedToNavigate = 31,
    ReceiverPoweringDown = 100,
    ReceiverError = 101,
    Unknown = 255,
}

impl PresentationTerminationReason {
    pub fn from_u8(value: u8) -> Result<Self, MessageError> {
        match value {
            1 => Ok(Self::ApplicationRequest),
            2 => Ok(Self::UserRequest),
            20 => Ok(Self::ReceiverReplacedPresentation),
            30 => Ok(Self::ReceiverIdleTooLong),
            31 => Ok(Self::ReceiverAttemptedToNavigate),
            100 => Ok(Self::ReceiverPoweringDown),
            101 => Ok(Self::ReceiverError),
            255 => Ok(Self::Unknown),
            _ => Err(MessageError::InvalidField),
        }
    }
}

/// Presentation connection close reason
/// CDDL: &(close-method-called: 1, connection-object-discarded: 10,
///         unrecoverable-error-while-sending-or-receiving-message: 100)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum PresentationConnectionCloseReason {
    CloseMethodCalled = 1,
    ConnectionObjectDiscarded = 10,
    UnrecoverableError = 100,
}

impl PresentationConnectionCloseReason {
    pub fn from_u8(value: u8) -> Result<Self, MessageError> {
        match value {
            1 => Ok(Self::CloseMethodCalled),
            10 => Ok(Self::ConnectionObjectDiscarded),
            100 => Ok(Self::UnrecoverableError),
            _ => Err(MessageError::InvalidField),
        }
    }
}

/// URL availability status
/// CDDL: url-availability = &(available: 0, unavailable: 1, invalid: 10)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum UrlAvailability {
    Available = 0,
    Unavailable = 1,
    Invalid = 10,
}

impl UrlAvailability {
    pub fn from_u8(value: u8) -> Result<Self, MessageError> {
        match value {
            0 => Ok(Self::Available),
            1 => Ok(Self::Unavailable),
            10 => Ok(Self::Invalid),
            _ => Err(MessageError::InvalidField),
        }
    }
}

/// HTTP header (key-value pair)
/// CDDL: http-header = [key: text, value: text]

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

/// Presentation start request message (type key 104)
/// CDDL:
/// presentation-start-request = {
///   0: request-id
///   1: text ; presentation-id
///   2: text ; url
///   3: [* http-header] ; headers
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationStartRequest<'a> {
    pub request_id: u64,
    pub presentation_id: &'a str,
    pub url: &'a str,
    pub headers: Vec<HttpHeader<'a>, 8>,
}

impl<'a> PresentationStartRequest<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(ApplicationMessageType::PresentationStartRequest as u16, buf)?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 4 fields
        encoder.map(4).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: request-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: presentation-id
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.presentation_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 2: url
        encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.url)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 3: headers array
        encoder.u8(3).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .array(self.headers.len() as u64)
            .map_err(|_| MessageError::EncodeFailed)?;
        for header in &self.headers {
            encoder.array(2).map_err(|_| MessageError::EncodeFailed)?;
            encoder
                .str(header.key)
                .map_err(|_| MessageError::EncodeFailed)?;
            encoder
                .str(header.value)
                .map_err(|_| MessageError::EncodeFailed)?;
        }

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationStartRequest as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        // Body is a map with 4 fields
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(4) {
            return Err(MessageError::InvalidField);
        }

        let mut request_id = None;
        let mut presentation_id = None;
        let mut url = None;
        let mut headers = Vec::new();

        for _ in 0..4 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    request_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    let pres_id = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                    if pres_id.len() > MAX_STRING_LEN {
                        return Err(MessageError::FieldTooLong);
                    }
                    presentation_id = Some(pres_id);
                }
                2 => {
                    let url_str = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                    if url_str.len() > MAX_STRING_LEN {
                        return Err(MessageError::FieldTooLong);
                    }
                    url = Some(url_str);
                }
                3 => {
                    let headers_array_len =
                        decoder.array().map_err(|_| MessageError::DecodeFailed)?;
                    if let Some(len) = headers_array_len {
                        for _ in 0..len {
                            let header_array_len =
                                decoder.array().map_err(|_| MessageError::DecodeFailed)?;
                            if header_array_len != Some(2) {
                                return Err(MessageError::InvalidField);
                            }
                            let header_key =
                                decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                            if header_key.len() > MAX_STRING_LEN {
                                return Err(MessageError::FieldTooLong);
                            }
                            let header_value =
                                decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                            if header_value.len() > MAX_STRING_LEN {
                                return Err(MessageError::FieldTooLong);
                            }
                            headers
                                .push(HttpHeader {
                                    key: header_key,
                                    value: header_value,
                                })
                                .map_err(|_| MessageError::BufferFull)?;
                        }
                    }
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            request_id: request_id.ok_or(MessageError::MissingField)?,
            presentation_id: presentation_id.ok_or(MessageError::MissingField)?,
            url: url.ok_or(MessageError::MissingField)?,
            headers,
        })
    }
}

/// Presentation start response message (type key 105)
/// CDDL:
/// presentation-start-response = {
///   0: request-id
///   1: &result
///   2: uint ; connection-id
///   ? 3: uint ; http-response-code
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationStartResponse {
    pub request_id: u64,
    pub result: PresentationResult,
    pub connection_id: u64,
    pub http_response_code: Option<u16>,
}

impl PresentationStartResponse {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(
            ApplicationMessageType::PresentationStartResponse as u16,
            buf,
        )?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 3 or 4 fields
        let field_count = if self.http_response_code.is_some() {
            4
        } else {
            3
        };
        encoder
            .map(field_count)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: request-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: result
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u8(self.result as u8)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 2: connection-id
        encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.connection_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 3: http-response-code (optional)
        if let Some(code) = self.http_response_code {
            encoder.u8(3).map_err(|_| MessageError::EncodeFailed)?;
            encoder.u16(code).map_err(|_| MessageError::EncodeFailed)?;
        }

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationStartResponse as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &[u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        // Body is a map with 3 or 4 fields
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(3) && map_len != Some(4) {
            return Err(MessageError::InvalidField);
        }

        let field_count = map_len.unwrap();
        let mut request_id = None;
        let mut result = None;
        let mut connection_id = None;
        let mut http_response_code = None;

        for _ in 0..field_count {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    request_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    let result_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                    result = Some(PresentationResult::from_u8(result_u8)?);
                }
                2 => {
                    connection_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                3 => {
                    http_response_code =
                        Some(decoder.u16().map_err(|_| MessageError::DecodeFailed)?);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            request_id: request_id.ok_or(MessageError::MissingField)?,
            result: result.ok_or(MessageError::MissingField)?,
            connection_id: connection_id.ok_or(MessageError::MissingField)?,
            http_response_code,
        })
    }
}

/// Presentation termination request message (type key 106)
/// CDDL:
/// presentation-termination-request = {
///   request
///   1: text ; presentation-id
///   2: presentation-termination-reason ; reason
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationTerminationRequest<'a> {
    pub request_id: u64,
    pub presentation_id: &'a str,
    pub reason: PresentationTerminationReason,
}

impl<'a> PresentationTerminationRequest<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(
            ApplicationMessageType::PresentationTerminationRequest as u16,
            buf,
        )?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 3 fields
        encoder.map(3).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: request-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: presentation-id
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.presentation_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 2: reason
        encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u8(self.reason as u8)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationTerminationRequest as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        // Read the map
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(3) {
            return Err(MessageError::InvalidField);
        }

        let mut request_id = None;
        let mut presentation_id = None;
        let mut reason = None;

        for _ in 0..3 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    request_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    presentation_id = Some(decoder.str().map_err(|_| MessageError::DecodeFailed)?);
                }
                2 => {
                    let reason_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                    reason = Some(PresentationTerminationReason::from_u8(reason_u8)?);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            request_id: request_id.ok_or(MessageError::MissingField)?,
            presentation_id: presentation_id.ok_or(MessageError::MissingField)?,
            reason: reason.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Presentation termination response message (type key 107)
/// CDDL:
/// presentation-termination-response = {
///   response
///   1: &result ; result
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationTerminationResponse {
    pub request_id: u64,
    pub result: PresentationResult,
}

impl PresentationTerminationResponse {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(
            ApplicationMessageType::PresentationTerminationResponse as u16,
            buf,
        )?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 2 fields
        encoder.map(2).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: request-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: result
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u8(self.result as u8)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationTerminationResponse as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &[u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(2) {
            return Err(MessageError::InvalidField);
        }

        let mut request_id = None;
        let mut result = None;

        for _ in 0..2 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    request_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    let result_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                    result = Some(PresentationResult::from_u8(result_u8)?);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            request_id: request_id.ok_or(MessageError::MissingField)?,
            result: result.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Presentation termination event message (type key 108)
/// CDDL:
/// presentation-termination-event = {
///   0: text ; presentation-id
///   1: presentation-termination-source ; source
///   2: presentation-termination-reason ; reason
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationTerminationEvent<'a> {
    pub presentation_id: &'a str,
    pub source: PresentationTerminationSource,
    pub reason: PresentationTerminationReason,
}

impl<'a> PresentationTerminationEvent<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(
            ApplicationMessageType::PresentationTerminationEvent as u16,
            buf,
        )?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 3 fields
        encoder.map(3).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: presentation-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.presentation_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: source
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u8(self.source as u8)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 2: reason
        encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u8(self.reason as u8)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationTerminationEvent as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(3) {
            return Err(MessageError::InvalidField);
        }

        let mut presentation_id = None;
        let mut source = None;
        let mut reason = None;

        for _ in 0..3 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    presentation_id = Some(decoder.str().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    let source_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                    source = Some(PresentationTerminationSource::from_u8(source_u8)?);
                }
                2 => {
                    let reason_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                    reason = Some(PresentationTerminationReason::from_u8(reason_u8)?);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            presentation_id: presentation_id.ok_or(MessageError::MissingField)?,
            source: source.ok_or(MessageError::MissingField)?,
            reason: reason.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Presentation connection open request message (type key 109)
/// CDDL:
/// presentation-connection-open-request = {
///   request
///   1: text ; presentation-id
///   2: text ; url
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationConnectionOpenRequest<'a> {
    pub request_id: u64,
    pub presentation_id: &'a str,
    pub url: &'a str,
}

impl<'a> PresentationConnectionOpenRequest<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(
            ApplicationMessageType::PresentationConnectionOpenRequest as u16,
            buf,
        )?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 3 fields
        encoder.map(3).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: request-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: presentation-id
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.presentation_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 2: url
        encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.url)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationConnectionOpenRequest as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(3) {
            return Err(MessageError::InvalidField);
        }

        let mut request_id = None;
        let mut presentation_id = None;
        let mut url = None;

        for _ in 0..3 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    request_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    presentation_id = Some(decoder.str().map_err(|_| MessageError::DecodeFailed)?);
                }
                2 => {
                    url = Some(decoder.str().map_err(|_| MessageError::DecodeFailed)?);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            request_id: request_id.ok_or(MessageError::MissingField)?,
            presentation_id: presentation_id.ok_or(MessageError::MissingField)?,
            url: url.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Presentation connection open response message (type key 110)
/// CDDL:
/// presentation-connection-open-response = {
///   response
///   1: &result ; result
///   2: uint ; connection-id
///   3: uint ; connection-count
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationConnectionOpenResponse {
    pub request_id: u64,
    pub result: PresentationResult,
    pub connection_id: u64,
    pub connection_count: u64,
}

impl PresentationConnectionOpenResponse {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(
            ApplicationMessageType::PresentationConnectionOpenResponse as u16,
            buf,
        )?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 4 fields
        encoder.map(4).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: request-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: result
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u8(self.result as u8)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 2: connection-id
        encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.connection_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 3: connection-count
        encoder.u8(3).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.connection_count)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationConnectionOpenResponse as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &[u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(4) {
            return Err(MessageError::InvalidField);
        }

        let mut request_id = None;
        let mut result = None;
        let mut connection_id = None;
        let mut connection_count = None;

        for _ in 0..4 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    request_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    let result_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                    result = Some(PresentationResult::from_u8(result_u8)?);
                }
                2 => {
                    connection_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                3 => {
                    connection_count = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            request_id: request_id.ok_or(MessageError::MissingField)?,
            result: result.ok_or(MessageError::MissingField)?,
            connection_id: connection_id.ok_or(MessageError::MissingField)?,
            connection_count: connection_count.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Presentation URL availability request message (type key 14)
/// CDDL:
/// presentation-url-availability-request = {
///   request
///   1: [1* text] ; urls
///   2: microseconds ; watch-duration
///   3: watch-id ; watch-id
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationUrlAvailabilityRequest<'a> {
    pub request_id: u64,
    pub urls: Vec<&'a str, MAX_URLS>,
    pub watch_duration: u64,
    pub watch_id: u64,
}

impl<'a> PresentationUrlAvailabilityRequest<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(
            ApplicationMessageType::PresentationUrlAvailabilityRequest as u16,
            buf,
        )?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 4 fields
        encoder.map(4).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: request-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: urls (array of strings)
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .array(self.urls.len() as u64)
            .map_err(|_| MessageError::EncodeFailed)?;
        for url in &self.urls {
            encoder.str(url).map_err(|_| MessageError::EncodeFailed)?;
        }

        // Field 2: watch-duration
        encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.watch_duration)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 3: watch-id
        encoder.u8(3).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.watch_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationUrlAvailabilityRequest as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(4) {
            return Err(MessageError::InvalidField);
        }

        let mut request_id = None;
        let mut urls = None;
        let mut watch_duration = None;
        let mut watch_id = None;

        for _ in 0..4 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    request_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    // Decode array of URLs
                    let array_len = decoder.array().map_err(|_| MessageError::DecodeFailed)?;
                    let count = array_len.ok_or(MessageError::InvalidField)?;

                    let mut url_vec = Vec::new();
                    for _ in 0..count {
                        let url = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                        url_vec.push(url).map_err(|_| MessageError::BufferFull)?;
                    }
                    urls = Some(url_vec);
                }
                2 => {
                    watch_duration = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                3 => {
                    watch_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            request_id: request_id.ok_or(MessageError::MissingField)?,
            urls: urls.ok_or(MessageError::MissingField)?,
            watch_duration: watch_duration.ok_or(MessageError::MissingField)?,
            watch_id: watch_id.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Presentation URL availability response message (type key 15)
/// CDDL:
/// presentation-url-availability-response = {
///   response
///   1: [1* url-availability] ; url-availabilities
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationUrlAvailabilityResponse {
    pub request_id: u64,
    pub url_availabilities: Vec<UrlAvailability, MAX_URLS>,
}

impl PresentationUrlAvailabilityResponse {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(
            ApplicationMessageType::PresentationUrlAvailabilityResponse as u16,
            buf,
        )?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 2 fields
        encoder.map(2).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: request-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.request_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: url-availabilities (array of enum values)
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .array(self.url_availabilities.len() as u64)
            .map_err(|_| MessageError::EncodeFailed)?;
        for availability in &self.url_availabilities {
            encoder
                .u8(*availability as u8)
                .map_err(|_| MessageError::EncodeFailed)?;
        }

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationUrlAvailabilityResponse as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &[u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(2) {
            return Err(MessageError::InvalidField);
        }

        let mut request_id = None;
        let mut url_availabilities = None;

        for _ in 0..2 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    request_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    // Decode array of availability values
                    let array_len = decoder.array().map_err(|_| MessageError::DecodeFailed)?;
                    let count = array_len.ok_or(MessageError::InvalidField)?;

                    let mut avail_vec = Vec::new();
                    for _ in 0..count {
                        let avail_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                        let avail = UrlAvailability::from_u8(avail_u8)?;
                        avail_vec
                            .push(avail)
                            .map_err(|_| MessageError::BufferFull)?;
                    }
                    url_availabilities = Some(avail_vec);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            request_id: request_id.ok_or(MessageError::MissingField)?,
            url_availabilities: url_availabilities.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Presentation URL availability event message (type key 103)
/// CDDL:
/// presentation-url-availability-event = {
///   0: watch-id ; watch-id
///   1: [1* url-availability] ; url-availabilities
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationUrlAvailabilityEvent {
    pub watch_id: u64,
    pub url_availabilities: Vec<UrlAvailability, MAX_URLS>,
}

impl PresentationUrlAvailabilityEvent {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(
            ApplicationMessageType::PresentationUrlAvailabilityEvent as u16,
            buf,
        )?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 2 fields
        encoder.map(2).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: watch-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.watch_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: url-availabilities (array of enum values)
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .array(self.url_availabilities.len() as u64)
            .map_err(|_| MessageError::EncodeFailed)?;
        for availability in &self.url_availabilities {
            encoder
                .u8(*availability as u8)
                .map_err(|_| MessageError::EncodeFailed)?;
        }

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationUrlAvailabilityEvent as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &[u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(2) {
            return Err(MessageError::InvalidField);
        }

        let mut watch_id = None;
        let mut url_availabilities = None;

        for _ in 0..2 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    watch_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    // Decode array of availability values
                    let array_len = decoder.array().map_err(|_| MessageError::DecodeFailed)?;
                    let count = array_len.ok_or(MessageError::InvalidField)?;

                    let mut avail_vec = Vec::new();
                    for _ in 0..count {
                        let avail_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                        let avail = UrlAvailability::from_u8(avail_u8)?;
                        avail_vec
                            .push(avail)
                            .map_err(|_| MessageError::BufferFull)?;
                    }
                    url_availabilities = Some(avail_vec);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            watch_id: watch_id.ok_or(MessageError::MissingField)?,
            url_availabilities: url_availabilities.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Presentation connection close event message (type key 113)
/// CDDL:
/// presentation-connection-close-event = {
///   0: uint ; connection-id
///   1: &(close-method-called: 1, connection-object-discarded: 10,
///        unrecoverable-error-while-sending-or-receiving-message: 100) ; reason
///   ? 2: text ; error-message
///   3: uint ; connection-count
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationConnectionCloseEvent<'a> {
    pub connection_id: u64,
    pub reason: PresentationConnectionCloseReason,
    pub error_message: Option<&'a str>,
    pub connection_count: u64,
}

impl<'a> PresentationConnectionCloseEvent<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(
            ApplicationMessageType::PresentationConnectionCloseEvent as u16,
            buf,
        )?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 3 or 4 fields (error_message is optional)
        let field_count = if self.error_message.is_some() { 4 } else { 3 };
        encoder
            .map(field_count)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: connection-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.connection_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: reason
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u8(self.reason as u8)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 2: error-message (optional)
        if let Some(error_message) = self.error_message {
            encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
            encoder
                .str(error_message)
                .map_err(|_| MessageError::EncodeFailed)?;
        }

        // Field 3: connection-count
        encoder.u8(3).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.connection_count)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationConnectionCloseEvent as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        let field_count = map_len.ok_or(MessageError::InvalidField)?;
        if field_count != 3 && field_count != 4 {
            return Err(MessageError::InvalidField);
        }

        let mut connection_id = None;
        let mut reason = None;
        let mut error_message = None;
        let mut connection_count = None;

        for _ in 0..field_count {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    connection_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    let reason_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                    reason = Some(PresentationConnectionCloseReason::from_u8(reason_u8)?);
                }
                2 => {
                    error_message = Some(decoder.str().map_err(|_| MessageError::DecodeFailed)?);
                }
                3 => {
                    connection_count = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            connection_id: connection_id.ok_or(MessageError::MissingField)?,
            reason: reason.ok_or(MessageError::MissingField)?,
            error_message,
            connection_count: connection_count.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Presentation connection message (type key 16)
/// CDDL:
/// presentation-connection-message = {
///   0: uint ; connection-id
///   1: bytes / text ; message
/// }

#[derive(Debug, Clone, PartialEq)]
pub struct PresentationConnectionMessage<'a> {
    pub connection_id: u64,
    pub message: &'a [u8],
}

impl<'a> PresentationConnectionMessage<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(
            ApplicationMessageType::PresentationConnectionMessage as u16,
            buf,
        )?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 2 fields
        encoder.map(2).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: connection-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.connection_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: message (bytes or text, we'll use bytes)
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .bytes(self.message)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationConnectionMessage as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        // Read the map
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(2) {
            return Err(MessageError::InvalidField);
        }

        let mut connection_id = None;
        let mut message = None;

        for _ in 0..2 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    connection_id = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    message = Some(decoder.bytes().map_err(|_| MessageError::DecodeFailed)?);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            connection_id: connection_id.ok_or(MessageError::MissingField)?,
            message: message.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Presentation change event (type key 121)
/// CDDL:
/// presentation-change-event = {
///   0: text ; presentation-id
///   1: uint ; connection-count
/// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationChangeEvent<'a> {
    pub presentation_id: &'a str,
    pub connection_count: u64,
}

impl<'a> PresentationChangeEvent<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(ApplicationMessageType::PresentationChangeEvent as u16, buf)?;

        // Write CBOR body
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 2 fields
        encoder.map(2).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: presentation-id
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .str(self.presentation_id)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: connection-count
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u64(self.connection_count)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from CBOR
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != ApplicationMessageType::PresentationChangeEvent as u16 {
            return Err(MessageError::InvalidMessageType);
        }
        Self::decode_body(&data[consumed..])
    }

    /// Decode from CBOR body (without type key)
    pub fn decode_body(body: &'a [u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(body);

        // Read the map
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(2) {
            return Err(MessageError::InvalidField);
        }

        let mut presentation_id = None;
        let mut connection_count = None;

        for _ in 0..2 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    presentation_id = Some(decoder.str().map_err(|_| MessageError::DecodeFailed)?);
                }
                1 => {
                    connection_count = Some(decoder.u64().map_err(|_| MessageError::DecodeFailed)?);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            presentation_id: presentation_id.ok_or(MessageError::MissingField)?,
            connection_count: connection_count.ok_or(MessageError::MissingField)?,
        })
    }
}

/// SPAKE2 handshake message (type key 1005)
/// CDDL:
/// auth-spake2-handshake = {
///   0: auth-initiation-token
///   1: auth-spake2-psk-status
///   2: bytes ; public-value

/// Umbrella enum for all application protocol messages
#[derive(Debug, Clone, PartialEq)]
pub enum ApplicationMessage<'a> {
    /// Agent info request message
    AgentInfoRequest(AgentInfoRequest),
    /// Agent info response message
    AgentInfoResponse(AgentInfoResponse<'a>),
    /// Agent status request message
    AgentStatusRequest(AgentStatusRequest<'a>),
    /// Agent status response message
    AgentStatusResponse(AgentStatusResponse<'a>),
    /// Agent info event message
    AgentInfoEvent(AgentInfoEvent<'a>),
    /// Presentation URL availability request message
    PresentationUrlAvailabilityRequest(PresentationUrlAvailabilityRequest<'a>),
    /// Presentation URL availability response message
    PresentationUrlAvailabilityResponse(PresentationUrlAvailabilityResponse),
    /// Presentation URL availability event message
    PresentationUrlAvailabilityEvent(PresentationUrlAvailabilityEvent),
    /// Presentation start request message
    PresentationStartRequest(PresentationStartRequest<'a>),
    /// Presentation start response message
    PresentationStartResponse(PresentationStartResponse),
    /// Presentation termination request message
    PresentationTerminationRequest(PresentationTerminationRequest<'a>),
    /// Presentation termination response message
    PresentationTerminationResponse(PresentationTerminationResponse),
    /// Presentation termination event message
    PresentationTerminationEvent(PresentationTerminationEvent<'a>),
    /// Presentation connection open request message
    PresentationConnectionOpenRequest(PresentationConnectionOpenRequest<'a>),
    /// Presentation connection open response message
    PresentationConnectionOpenResponse(PresentationConnectionOpenResponse),
    /// Presentation connection close event message
    PresentationConnectionCloseEvent(PresentationConnectionCloseEvent<'a>),
    /// Presentation connection message (data channel)
    PresentationConnectionMessage(PresentationConnectionMessage<'a>),
    /// Presentation change event message
    PresentationChangeEvent(PresentationChangeEvent<'a>),
}

impl<'a> ApplicationMessage<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        match self {
            ApplicationMessage::AgentInfoRequest(msg) => msg.encode(buf),
            ApplicationMessage::AgentInfoResponse(msg) => msg.encode(buf),
            ApplicationMessage::AgentStatusRequest(msg) => msg.encode(buf),
            ApplicationMessage::AgentStatusResponse(msg) => msg.encode(buf),
            ApplicationMessage::AgentInfoEvent(msg) => msg.encode(buf),
            ApplicationMessage::PresentationUrlAvailabilityRequest(msg) => msg.encode(buf),
            ApplicationMessage::PresentationUrlAvailabilityResponse(msg) => msg.encode(buf),
            ApplicationMessage::PresentationUrlAvailabilityEvent(msg) => msg.encode(buf),
            ApplicationMessage::PresentationStartRequest(msg) => msg.encode(buf),
            ApplicationMessage::PresentationStartResponse(msg) => msg.encode(buf),
            ApplicationMessage::PresentationTerminationRequest(msg) => msg.encode(buf),
            ApplicationMessage::PresentationTerminationResponse(msg) => msg.encode(buf),
            ApplicationMessage::PresentationTerminationEvent(msg) => msg.encode(buf),
            ApplicationMessage::PresentationConnectionOpenRequest(msg) => msg.encode(buf),
            ApplicationMessage::PresentationConnectionOpenResponse(msg) => msg.encode(buf),
            ApplicationMessage::PresentationConnectionCloseEvent(msg) => msg.encode(buf),
            ApplicationMessage::PresentationConnectionMessage(msg) => msg.encode(buf),
            ApplicationMessage::PresentationChangeEvent(msg) => msg.encode(buf),
        }
    }

    /// Decode a message from CBOR
    pub fn decode(buf: &'a [u8]) -> Result<Self, MessageError> {
        // First, peek at the message type to determine which variant to decode
        // Type key is encoded as RFC 9000 variable-length integer
        let (type_key, consumed) = decode_type_key(buf)?;

        let msg_type = ApplicationMessageType::from_u16(type_key)?;
        let body = &buf[consumed..];

        // Decode the body based on type (type key already consumed)
        match msg_type {
            ApplicationMessageType::AgentInfoRequest => Ok(ApplicationMessage::AgentInfoRequest(
                AgentInfoRequest::decode_body(body)?,
            )),
            ApplicationMessageType::AgentInfoResponse => Ok(ApplicationMessage::AgentInfoResponse(
                AgentInfoResponse::decode_body(body)?,
            )),
            ApplicationMessageType::AgentStatusRequest => Ok(
                ApplicationMessage::AgentStatusRequest(AgentStatusRequest::decode_body(body)?),
            ),
            ApplicationMessageType::AgentStatusResponse => Ok(
                ApplicationMessage::AgentStatusResponse(AgentStatusResponse::decode_body(body)?),
            ),
            ApplicationMessageType::AgentInfoEvent => Ok(ApplicationMessage::AgentInfoEvent(
                AgentInfoEvent::decode_body(body)?,
            )),
            ApplicationMessageType::PresentationUrlAvailabilityRequest => {
                Ok(ApplicationMessage::PresentationUrlAvailabilityRequest(
                    PresentationUrlAvailabilityRequest::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationUrlAvailabilityResponse => {
                Ok(ApplicationMessage::PresentationUrlAvailabilityResponse(
                    PresentationUrlAvailabilityResponse::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationUrlAvailabilityEvent => {
                Ok(ApplicationMessage::PresentationUrlAvailabilityEvent(
                    PresentationUrlAvailabilityEvent::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationStartRequest => {
                Ok(ApplicationMessage::PresentationStartRequest(
                    PresentationStartRequest::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationStartResponse => {
                Ok(ApplicationMessage::PresentationStartResponse(
                    PresentationStartResponse::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationTerminationRequest => {
                Ok(ApplicationMessage::PresentationTerminationRequest(
                    PresentationTerminationRequest::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationTerminationResponse => {
                Ok(ApplicationMessage::PresentationTerminationResponse(
                    PresentationTerminationResponse::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationTerminationEvent => {
                Ok(ApplicationMessage::PresentationTerminationEvent(
                    PresentationTerminationEvent::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationConnectionOpenRequest => {
                Ok(ApplicationMessage::PresentationConnectionOpenRequest(
                    PresentationConnectionOpenRequest::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationConnectionOpenResponse => {
                Ok(ApplicationMessage::PresentationConnectionOpenResponse(
                    PresentationConnectionOpenResponse::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationConnectionCloseEvent => {
                Ok(ApplicationMessage::PresentationConnectionCloseEvent(
                    PresentationConnectionCloseEvent::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationConnectionMessage => {
                Ok(ApplicationMessage::PresentationConnectionMessage(
                    PresentationConnectionMessage::decode_body(body)?,
                ))
            }
            ApplicationMessageType::PresentationChangeEvent => {
                Ok(ApplicationMessage::PresentationChangeEvent(
                    PresentationChangeEvent::decode_body(body)?,
                ))
            }
        }
    }
}
