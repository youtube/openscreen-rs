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

//! OpenScreen Network Protocol Message Types and Serialization
//!
//! This module implements CBOR encoding/decoding for OpenScreen Network Protocol messages
//! (authentication) based on the W3C specification's CDDL definitions.
//!
//! Message format per spec:
//! 1. Type key encoded as RFC 9000 variable-length integer
//! 2. Message body encoded as CBOR
//!
//! Reference: ref/w3c_ref/messages_appendix.cddl

use bytes::Buf;
use heapless::Vec;
use minicbor::{Decoder, Encoder};
use openscreen_common::quinn_varint::{Codec, VarInt};
use openscreen_common::MessageError;

/// A wrapper around heapless::Vec that implements minicbor's Write trait
/// This allows us to encode directly into the Vec without stack allocations
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

/// Encode a type key as RFC 9000 variable-length integer into a heapless::Vec
fn encode_type_key<const N: usize>(
    type_key: u16,
    buf: &mut Vec<u8, N>,
) -> Result<(), MessageError> {
    let varint = VarInt::from(type_key);
    let size = varint.size();

    // Ensure we have space
    if buf.len() + size > N {
        return Err(MessageError::BufferFull);
    }

    // Encode varint to a small stack buffer, then copy
    let mut temp = [0u8; 8];
    varint.encode(&mut temp.as_mut_slice());
    buf.extend_from_slice(&temp[..size])
        .map_err(|_| MessageError::BufferFull)
}

/// Decode a type key as RFC 9000 variable-length integer from a byte slice.
/// Returns the type key and the number of bytes consumed.
fn decode_type_key(data: &[u8]) -> Result<(u16, usize), MessageError> {
    let mut cursor = data;
    let varint = VarInt::decode(&mut cursor).map_err(|_| MessageError::DecodeFailed)?;
    let consumed = data.len() - cursor.remaining();
    let value = varint.into_inner();
    if value > u16::MAX as u64 {
        return Err(MessageError::InvalidMessageType);
    }
    Ok((value as u16, consumed))
}

/// Maximum size for a single CBOR message
pub const MAX_MESSAGE_SIZE: usize = 1024;

/// Maximum length for string fields (display names, model names, URLs)
pub const MAX_STRING_LEN: usize = 256;

/// Maximum size for byte arrays (public keys, tokens, etc.)
pub const MAX_BYTES_LEN: usize = 64;

/// Network Protocol message type keys as defined in CDDL
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NetworkMessageType {
    // Authentication messages (1001-1005)
    AuthCapabilities = 1001,
    AuthSpake2Need = 1002,
    AuthSpake2Confirmation = 1003,
    AuthStatus = 1004,
    AuthSpake2Handshake = 1005,
}

impl NetworkMessageType {
    pub fn from_u16(value: u16) -> Result<Self, MessageError> {
        match value {
            1001 => Ok(Self::AuthCapabilities),
            1002 => Ok(Self::AuthSpake2Need),
            1003 => Ok(Self::AuthSpake2Confirmation),
            1004 => Ok(Self::AuthStatus),
            1005 => Ok(Self::AuthSpake2Handshake),
            _ => Err(MessageError::InvalidMessageType),
        }
    }
}

/// SPAKE2 PSK status value
/// CDDL: spake2-psk-status = &(psk-needs-presentation: 0, psk-shown: 1, psk-input: 2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Spake2PskStatus {
    PskNeedsPresentation = 0,
    PskShown = 1,
    PskInput = 2,
}

impl Spake2PskStatus {
    pub fn from_u8(value: u8) -> Result<Self, MessageError> {
        match value {
            0 => Ok(Self::PskNeedsPresentation),
            1 => Ok(Self::PskShown),
            2 => Ok(Self::PskInput),
            _ => Err(MessageError::InvalidField),
        }
    }
}

/// Authentication initiation token
/// CDDL: auth-initiation-token = { ? 0: text }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthInitiationToken<'a> {
    pub token: Option<&'a str>,
}

/// PSK ease of input value
/// CDDL: auth-psk-input-ease = &(input-unknown: 0, input-simple: 1, input-moderate: 2, input-hard: 3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PskInputEase {
    Unknown = 0,
    Simple = 1,
    Moderate = 2,
    Hard = 3,
}

impl PskInputEase {
    pub fn from_u8(value: u8) -> Result<Self, MessageError> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Simple),
            2 => Ok(Self::Moderate),
            3 => Ok(Self::Hard),
            _ => Err(MessageError::InvalidField),
        }
    }
}

/// PSK input method
/// CDDL: auth-psk-input-method = &(numeric: 0, qr-code: 1, nfc: 2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PskInputMethod {
    Numeric = 0,
    QrCode = 1,
    Nfc = 2,
}

impl PskInputMethod {
    pub fn from_u8(value: u8) -> Result<Self, MessageError> {
        match value {
            0 => Ok(Self::Numeric),
            1 => Ok(Self::QrCode),
            2 => Ok(Self::Nfc),
            _ => Err(MessageError::InvalidField),
        }
    }
}

/// Authentication status code
/// CDDL: auth-status-code = &(ok: 0, authentication-failed: 1, unknown-error: 2, timeout: 3, secret-unknown: 4, proof-invalid: 5)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthStatusCode {
    Ok = 0,
    AuthenticationFailed = 1,
    UnknownError = 2,
    Timeout = 3,
    SecretUnknown = 4,
    ProofInvalid = 5,
}

impl AuthStatusCode {
    pub fn from_u8(value: u8) -> Result<Self, MessageError> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::AuthenticationFailed),
            2 => Ok(Self::UnknownError),
            3 => Ok(Self::Timeout),
            4 => Ok(Self::SecretUnknown),
            5 => Ok(Self::ProofInvalid),
            _ => Err(MessageError::InvalidField),
        }
    }
}

/// Authentication capabilities message (type key 1001)
/// CDDL:
/// auth-capabilities = {
///   0: auth-psk-input-ease
///   ? 1: [* auth-psk-input-method]
///   2: uint ; psk-min-bits-of-entropy
/// }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCapabilities {
    pub psk_input_ease: PskInputEase,
    pub psk_input_methods: Vec<PskInputMethod, 8>,
    pub psk_min_bits_of_entropy: u32,
}

impl AuthCapabilities {
    /// Encode this message to bytes per OSP spec:
    /// 1. Type key as RFC 9000 variable-length integer
    /// 2. Message body as CBOR map
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(NetworkMessageType::AuthCapabilities as u16, buf)?;

        // Write CBOR body (map only, no array wrapper)
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 2 or 3 fields (field 2 is mandatory, field 1 is optional)
        let field_count = if self.psk_input_methods.is_empty() {
            2
        } else {
            3
        };
        encoder
            .map(field_count)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: psk-input-ease
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u8(self.psk_input_ease as u8)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 1: psk-input-methods (optional)
        if !self.psk_input_methods.is_empty() {
            encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
            encoder
                .array(self.psk_input_methods.len() as u64)
                .map_err(|_| MessageError::EncodeFailed)?;
            for method in &self.psk_input_methods {
                encoder
                    .u8(*method as u8)
                    .map_err(|_| MessageError::EncodeFailed)?;
            }
        }

        // Field 2: psk-min-bits-of-entropy (mandatory)
        encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u32(self.psk_min_bits_of_entropy)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from bytes per OSP spec:
    /// 1. Type key as RFC 9000 variable-length integer
    /// 2. Message body as CBOR map
    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != NetworkMessageType::AuthCapabilities as u16 {
            return Err(MessageError::InvalidMessageType);
        }

        // Decode CBOR body (map only, no array wrapper)
        let mut decoder = Decoder::new(&data[consumed..]);

        // Body is a map with 2 or 3 fields (field 2 is mandatory, field 1 is optional)
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(2) && map_len != Some(3) {
            return Err(MessageError::InvalidField);
        }

        let field_count = map_len.unwrap();
        let mut psk_input_ease = None;
        let mut psk_input_methods = Vec::new();
        let mut psk_min_bits_of_entropy = None;

        for _ in 0..field_count {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    let ease_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                    psk_input_ease = Some(PskInputEase::from_u8(ease_u8)?);
                }
                1 => {
                    let methods_len = decoder.array().map_err(|_| MessageError::DecodeFailed)?;
                    if let Some(len) = methods_len {
                        for _ in 0..len {
                            let method_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                            let method = PskInputMethod::from_u8(method_u8)?;
                            psk_input_methods
                                .push(method)
                                .map_err(|_| MessageError::BufferFull)?;
                        }
                    }
                }
                2 => {
                    psk_min_bits_of_entropy =
                        Some(decoder.u32().map_err(|_| MessageError::DecodeFailed)?);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            psk_input_ease: psk_input_ease.ok_or(MessageError::MissingField)?,
            psk_input_methods,
            psk_min_bits_of_entropy: psk_min_bits_of_entropy.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Authentication SPAKE2 handshake message (type key 1005)
/// CDDL:
/// auth-spake2-handshake = {
///   0: auth-initiation-token
///   1: spake2-psk-status
///   2: bytes ; public-value
/// }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSpake2Handshake<'a> {
    pub initiation_token: AuthInitiationToken<'a>,
    pub psk_status: Spake2PskStatus,
    pub public_value: &'a [u8],
}

impl<'a> AuthSpake2Handshake<'a> {
    /// Encode this message to bytes per OSP spec:
    /// 1. Type key as RFC 9000 variable-length integer
    /// 2. Message body as CBOR map
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(NetworkMessageType::AuthSpake2Handshake as u16, buf)?;

        // Write CBOR body (map only, no array wrapper)
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 3 fields
        encoder.map(3).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: auth-initiation-token (map with optional token)
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        if let Some(token) = self.initiation_token.token {
            encoder.map(1).map_err(|_| MessageError::EncodeFailed)?;
            encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
            encoder.str(token).map_err(|_| MessageError::EncodeFailed)?;
        } else {
            encoder.map(0).map_err(|_| MessageError::EncodeFailed)?;
        }

        // Field 1: psk-status
        encoder.u8(1).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u8(self.psk_status as u8)
            .map_err(|_| MessageError::EncodeFailed)?;

        // Field 2: public-value
        encoder.u8(2).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .bytes(self.public_value)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from bytes per OSP spec:
    /// 1. Type key as RFC 9000 variable-length integer
    /// 2. Message body as CBOR map
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != NetworkMessageType::AuthSpake2Handshake as u16 {
            return Err(MessageError::InvalidMessageType);
        }

        // Decode CBOR body (map only, no array wrapper)
        let mut decoder = Decoder::new(&data[consumed..]);

        // Body is a map
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(3) {
            return Err(MessageError::InvalidField);
        }

        // Decode fields (CBOR map keys may appear in any order)
        let mut initiation_token = None;
        let mut psk_status = None;
        let mut public_value = None;

        for _ in 0..3 {
            let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
            match key {
                0 => {
                    // auth-initiation-token
                    let token_map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
                    if token_map_len == Some(1) {
                        let token_key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                        if token_key != 0 {
                            return Err(MessageError::InvalidField);
                        }
                        let token_str = decoder.str().map_err(|_| MessageError::DecodeFailed)?;
                        if token_str.len() > MAX_STRING_LEN {
                            return Err(MessageError::FieldTooLong);
                        }
                        initiation_token = Some(AuthInitiationToken {
                            token: Some(token_str),
                        });
                    } else if token_map_len == Some(0) {
                        initiation_token = Some(AuthInitiationToken { token: None });
                    } else {
                        return Err(MessageError::InvalidField);
                    }
                }
                1 => {
                    // psk-status
                    let status_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
                    psk_status = Some(Spake2PskStatus::from_u8(status_u8)?);
                }
                2 => {
                    // public-value
                    let bytes = decoder.bytes().map_err(|_| MessageError::DecodeFailed)?;
                    if bytes.len() > MAX_BYTES_LEN {
                        return Err(MessageError::FieldTooLong);
                    }
                    public_value = Some(bytes);
                }
                _ => return Err(MessageError::InvalidField),
            }
        }

        Ok(Self {
            initiation_token: initiation_token.ok_or(MessageError::MissingField)?,
            psk_status: psk_status.ok_or(MessageError::MissingField)?,
            public_value: public_value.ok_or(MessageError::MissingField)?,
        })
    }
}

/// Authentication SPAKE2 confirmation message (type key 1003)
/// CDDL:
/// auth-spake2-confirmation = {
///   0: bytes ; confirmation-value (64 bytes)
/// }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSpake2Confirmation<'a> {
    pub confirmation_value: &'a [u8],
}

impl<'a> AuthSpake2Confirmation<'a> {
    /// Encode this message to bytes per OSP spec:
    /// 1. Type key as RFC 9000 variable-length integer
    /// 2. Message body as CBOR map
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(NetworkMessageType::AuthSpake2Confirmation as u16, buf)?;

        // Write CBOR body (map only, no array wrapper)
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 1 field
        encoder.map(1).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: confirmation-value
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .bytes(self.confirmation_value)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from bytes per OSP spec:
    /// 1. Type key as RFC 9000 variable-length integer
    /// 2. Message body as CBOR map
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != NetworkMessageType::AuthSpake2Confirmation as u16 {
            return Err(MessageError::InvalidMessageType);
        }

        // Decode CBOR body (map only, no array wrapper)
        let mut decoder = Decoder::new(&data[consumed..]);

        // Body is a map with 1 field
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(1) {
            return Err(MessageError::InvalidField);
        }

        // Field 0: confirmation-value
        let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
        if key != 0 {
            return Err(MessageError::InvalidField);
        }
        let confirmation_value = decoder.bytes().map_err(|_| MessageError::DecodeFailed)?;

        Ok(Self { confirmation_value })
    }
}

/// Authentication status message (type key 1004)
/// CDDL:
/// auth-status = {
///   0: auth-status-code
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthStatus {
    pub status: AuthStatusCode,
}

impl AuthStatus {
    /// Encode this message to bytes per OSP spec:
    /// 1. Type key as RFC 9000 variable-length integer
    /// 2. Message body as CBOR map
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        // Write type key as RFC 9000 varint
        encode_type_key(NetworkMessageType::AuthStatus as u16, buf)?;

        // Write CBOR body (map only, no array wrapper)
        let writer = VecWriter::new(buf);
        let mut encoder = Encoder::new(writer);

        // Body is a map with 1 field
        encoder.map(1).map_err(|_| MessageError::EncodeFailed)?;

        // Field 0: status
        encoder.u8(0).map_err(|_| MessageError::EncodeFailed)?;
        encoder
            .u8(self.status as u8)
            .map_err(|_| MessageError::EncodeFailed)?;

        Ok(())
    }

    /// Decode this message from bytes per OSP spec:
    /// 1. Type key as RFC 9000 variable-length integer
    /// 2. Message body as CBOR map
    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint
        let (type_key, consumed) = decode_type_key(data)?;
        if type_key != NetworkMessageType::AuthStatus as u16 {
            return Err(MessageError::InvalidMessageType);
        }

        // Decode CBOR body (map only, no array wrapper)
        let mut decoder = Decoder::new(&data[consumed..]);

        // Body is a map with 1 field
        let map_len = decoder.map().map_err(|_| MessageError::DecodeFailed)?;
        if map_len != Some(1) {
            return Err(MessageError::InvalidField);
        }

        // Field 0: status
        let key = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
        if key != 0 {
            return Err(MessageError::InvalidField);
        }
        let status_u8 = decoder.u8().map_err(|_| MessageError::DecodeFailed)?;
        let status = AuthStatusCode::from_u8(status_u8)?;

        Ok(Self { status })
    }
}

/// Umbrella enum for all OpenScreen Network Protocol (authentication) messages
///
/// This provides an ergonomic interface for the authentication state machine
/// while wrapping the spec-compliant message types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMessage<'a> {
    /// Authentication capabilities message
    AuthCapabilities(AuthCapabilities),
    /// Authentication SPAKE2 handshake message
    AuthSpake2Handshake(AuthSpake2Handshake<'a>),
    /// Authentication SPAKE2 confirmation message
    AuthSpake2Confirmation(AuthSpake2Confirmation<'a>),
    /// Authentication status message
    AuthStatus(AuthStatus),
}

impl<'a> NetworkMessage<'a> {
    /// Encode this message to CBOR
    pub fn encode<const N: usize>(&self, buf: &mut Vec<u8, N>) -> Result<(), MessageError> {
        match self {
            NetworkMessage::AuthCapabilities(msg) => msg.encode(buf),
            NetworkMessage::AuthSpake2Handshake(msg) => msg.encode(buf),
            NetworkMessage::AuthSpake2Confirmation(msg) => msg.encode(buf),
            NetworkMessage::AuthStatus(msg) => msg.encode(buf),
        }
    }

    /// Decode a NetworkMessage from bytes by inspecting the type key
    pub fn decode(data: &'a [u8]) -> Result<Self, MessageError> {
        // Read type key as RFC 9000 varint to determine message type
        let (type_key, _consumed) = decode_type_key(data)?;

        // Now decode the full message based on type
        match NetworkMessageType::from_u16(type_key)? {
            NetworkMessageType::AuthCapabilities => Ok(NetworkMessage::AuthCapabilities(
                AuthCapabilities::decode(data)?,
            )),
            NetworkMessageType::AuthSpake2Handshake => Ok(NetworkMessage::AuthSpake2Handshake(
                AuthSpake2Handshake::decode(data)?,
            )),
            NetworkMessageType::AuthSpake2Confirmation => Ok(
                NetworkMessage::AuthSpake2Confirmation(AuthSpake2Confirmation::decode(data)?),
            ),
            NetworkMessageType::AuthStatus => {
                Ok(NetworkMessage::AuthStatus(AuthStatus::decode(data)?))
            }
            NetworkMessageType::AuthSpake2Need => {
                unimplemented!("AuthSpake2Need message not yet supported")
            }
        }
    }
}

/// Encode a NetworkMessage to bytes per W3C OpenScreen Protocol spec.
///
/// Format: [type_key][cbor_body]
/// - type_key: RFC 9000 variable-length integer
/// - cbor_body: message-specific CBOR map
pub fn encode_network_message<'a>(
    msg: &crate::NetworkMessage<'a>,
) -> Result<heapless::Vec<u8, MAX_MESSAGE_SIZE>, MessageError> {
    use crate::NetworkMessage;

    let mut buffer = heapless::Vec::new();
    let writer = VecWriter::new(&mut buffer);
    let _encoder = Encoder::new(writer);

    match msg {
        NetworkMessage::AuthCapabilities(caps) => {
            // Delegate to AuthCapabilities::encode()
            caps.encode(&mut buffer)?;
        }

        NetworkMessage::AuthStatus(status) => {
            // Delegate to AuthStatus::encode()
            status.encode(&mut buffer)?;
        }

        NetworkMessage::AuthSpake2Handshake(handshake) => {
            // Delegate to AuthSpake2Handshake::encode()
            handshake.encode(&mut buffer)?;
        }

        NetworkMessage::AuthSpake2Confirmation(confirmation) => {
            // Delegate to AuthSpake2Confirmation::encode()
            confirmation.encode(&mut buffer)?;
        }
    }

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_capabilities_encode_decode() {
        let mut methods = Vec::new();
        methods.push(PskInputMethod::Numeric).unwrap();
        methods.push(PskInputMethod::QrCode).unwrap();

        let msg = AuthCapabilities {
            psk_input_ease: PskInputEase::Simple,
            psk_input_methods: methods,
            psk_min_bits_of_entropy: 20, // Typical value for a 6-digit PIN
        };

        let mut buf = Vec::<u8, MAX_MESSAGE_SIZE>::new();
        msg.encode(&mut buf).unwrap();

        let decoded = AuthCapabilities::decode(&buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_auth_status_encode_decode() {
        let msg = AuthStatus {
            status: AuthStatusCode::Ok,
        };

        let mut buf = Vec::<u8, MAX_MESSAGE_SIZE>::new();
        msg.encode(&mut buf).unwrap();

        let decoded = AuthStatus::decode(&buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_auth_spake2_handshake_encode_decode() {
        let public_value = b"test_public_value_1234567890";

        let msg = AuthSpake2Handshake {
            initiation_token: AuthInitiationToken {
                token: Some("test-token"),
            },
            psk_status: Spake2PskStatus::PskShown,
            public_value,
        };

        let mut buf = Vec::<u8, MAX_MESSAGE_SIZE>::new();
        msg.encode(&mut buf).unwrap();

        let decoded = AuthSpake2Handshake::decode(&buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_auth_spake2_confirmation_encode_decode() {
        let confirmation = b"test_confirmation_value_64bytes_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        let msg = AuthSpake2Confirmation {
            confirmation_value: confirmation,
        };

        let mut buf = Vec::<u8, MAX_MESSAGE_SIZE>::new();
        msg.encode(&mut buf).unwrap();

        let decoded = AuthSpake2Confirmation::decode(&buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_network_message_roundtrip() {
        let msg = NetworkMessage::AuthStatus(AuthStatus {
            status: AuthStatusCode::Ok,
        });

        let mut buf = Vec::<u8, MAX_MESSAGE_SIZE>::new();
        msg.encode(&mut buf).unwrap();

        let decoded = NetworkMessage::decode(&buf).unwrap();
        assert_eq!(msg, decoded);
    }
}
