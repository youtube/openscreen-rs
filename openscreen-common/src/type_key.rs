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

//! Type key encoding/decoding using RFC 9000 variable-length integers.

use bytes::Buf;
use heapless::Vec;

use crate::error::MessageError;
use crate::quinn_varint::{Codec, VarInt};

/// Encode a type key as RFC 9000 variable-length integer into a heapless::Vec
pub fn encode_type_key<const N: usize>(
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
    let mut temp = [0u8; 4];
    let mut slice = &mut temp[..];
    varint.encode(&mut slice);
    buf.extend_from_slice(&temp[..size])
        .map_err(|_| MessageError::BufferFull)
}

/// Decode a type key as RFC 9000 variable-length integer from a byte slice.
/// Returns the type key and the number of bytes consumed.
pub fn decode_type_key(data: &[u8]) -> Result<(u16, usize), MessageError> {
    let mut cursor = data;
    let varint = VarInt::decode(&mut cursor).map_err(|_| MessageError::DecodeFailed)?;
    let consumed = data.len() - cursor.remaining();
    let value = varint.into_inner();
    let type_key = u16::try_from(value).map_err(|_| MessageError::InvalidMessageType)?;
    Ok((type_key, consumed))
}
