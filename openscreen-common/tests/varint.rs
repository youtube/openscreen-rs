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

//! Tests for the vendored VarInt (RFC 9000 variable-length integer) implementation.

use openscreen_common::quinn_varint::{Codec, VarInt};

#[test]
fn test_varint_encode_decode_roundtrip() {
    // Test various values using the vendored VarInt
    for value in [0u32, 1, 42, 63, 64, 100, 16383, 16384, 1000000] {
        let varint = VarInt::from_u32(value);
        let mut encoded = Vec::new();
        varint.encode(&mut encoded);

        let mut slice: &[u8] = &encoded;
        let decoded = VarInt::decode(&mut slice).unwrap();
        assert_eq!(
            decoded.into_inner() as u32,
            value,
            "Roundtrip failed for value {value}"
        );
    }
}

#[test]
fn test_varint_encoding_format() {
    // Value 0: single byte 0x00
    let mut buf = Vec::new();
    VarInt::from_u32(0).encode(&mut buf);
    assert_eq!(buf, vec![0x00]);

    // Value 42: single byte 0x2A
    buf.clear();
    VarInt::from_u32(42).encode(&mut buf);
    assert_eq!(buf, vec![42]);

    // Value 63: single byte 0x3F (max for 1-byte)
    buf.clear();
    VarInt::from_u32(63).encode(&mut buf);
    assert_eq!(buf, vec![0x3F]);

    // Value 64: two bytes 0x40 0x40
    buf.clear();
    VarInt::from_u32(64).encode(&mut buf);
    assert_eq!(buf, vec![0x40, 0x40]);
}
