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

//! Variable-length integer encoding as specified in RFC 9000 (QUIC).
//!
//! This module contains code vendored from the [quinn](https://github.com/quinn-rs/quinn)
//! project's `quinn-proto` crate, with minimal modifications for `no_std` compatibility.

mod varint;

pub use varint::{VarInt, VarIntBoundsExceeded};

use bytes::{Buf, BufMut};

/// Error indicating that the provided buffer was too small.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UnexpectedEnd;

impl core::fmt::Display for UnexpectedEnd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unexpected end of buffer")
    }
}

/// Coding result type.
pub type Result<T> = core::result::Result<T, UnexpectedEnd>;

/// Trait for encoding and decoding QUIC primitives.
pub trait Codec: Sized {
    /// Decode a value from the provided buffer.
    fn decode<B: Buf>(buf: &mut B) -> Result<Self>;

    /// Encode this value into the provided buffer.
    fn encode<B: BufMut>(&self, buf: &mut B);
}
