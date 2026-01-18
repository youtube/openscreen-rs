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

//! Utility functions for mDNS service handling

use openscreen_common::quinn_varint::{Codec, VarInt};
use openscreen_discovery::{Fingerprint, FingerprintError, ServiceInfo, TxtRecords};
use std::time::SystemTime;

/// Sanitize display name for mDNS instance name
///
/// Per W3C spec and DNS label limits (RFC 1035):
/// - Maximum 63 bytes
/// - If truncated, null-terminate
pub fn sanitize_instance_name(display_name: &str) -> String {
    const MAX_LEN: usize = 63;
    if display_name.len() > MAX_LEN {
        // Truncate and null-terminate
        format!("{}\0", &display_name[..MAX_LEN])
    } else {
        display_name.to_string()
    }
}

/// Convert mdns-sd ScopedIp to IpAddr by stripping scope ID if present
fn scoped_ip_to_ip_addr(host: &mdns_sd::ScopedIp) -> Result<core::net::IpAddr, ParseError> {
    let host_str = host.to_string();
    let host_clean = if let Some(idx) = host_str.find('%') {
        &host_str[..idx]
    } else {
        &host_str
    };
    host_clean.parse().map_err(|_| ParseError::NoAddress)
}

/// Build TXT record properties from TxtRecords.
///
/// Returns TxtProperty values with raw bytes, suitable for mdns-sd.
/// The `mv` field is encoded as an RFC9000 variable-length integer.
pub fn build_txt_properties(txt: &TxtRecords) -> Vec<mdns_sd::TxtProperty> {
    let varint = VarInt::from_u32(txt.mv);
    let mut mv_bytes = Vec::with_capacity(varint.size());
    varint.encode(&mut mv_bytes);

    vec![
        ("fp", txt.fp.as_str()).into(),
        ("mv", mv_bytes.as_slice()).into(),
        ("at", txt.at.as_str()).into(),
    ]
}

/// Parse TXT record properties into structured data
///
/// Extracts fp, mv, and at values from mDNS TXT records.
pub fn parse_txt_properties(
    properties: &mdns_sd::TxtProperties,
) -> Result<(Fingerprint, u32, String), ParseError> {
    let fp = properties.get("fp").ok_or(ParseError::MissingField("fp"))?;
    let fp_str = fp.val_str();
    let fingerprint = Fingerprint::from_base64(fp_str).map_err(ParseError::InvalidFingerprint)?;

    let mv = properties.get("mv").ok_or(ParseError::MissingField("mv"))?;
    // Decode mv as RFC9000 varint from the raw bytes (not val_str - bytes may not be valid UTF-8)
    let mut mv_bytes = mv.val().ok_or(ParseError::InvalidMetadataVersion)?;
    let varint = VarInt::decode(&mut mv_bytes).map_err(|_| ParseError::InvalidMetadataVersion)?;
    let metadata_version =
        u32::try_from(varint.into_inner()).map_err(|_| ParseError::InvalidMetadataVersion)?;

    let auth_token = properties
        .get("at")
        .ok_or(ParseError::MissingField("at"))?
        .val_str()
        .to_string();

    Ok((fingerprint, metadata_version, auth_token))
}

/// Build ServiceInfo from mdns-sd ResolvedService
///
/// Converts from mdns-sd types to our ServiceInfo
pub fn service_info_from_mdns_resolved(
    mdns_info: &mdns_sd::ResolvedService,
) -> Result<ServiceInfo, ParseError> {
    let (fingerprint, metadata_version, auth_token) =
        parse_txt_properties(mdns_info.get_properties())?;

    // Get host address: Prefer IPv4 over IPv6, and non-link-local over link-local
    // Link-local IPv6 addresses (fe80::...) often include zone IDs (%lo0, %eth0, etc.)
    // which can't be parsed as socket addresses. IPv4 addresses are more reliable.
    let addresses = mdns_info.get_addresses();

    // Try to find an IPv4 address first
    let host = addresses
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| {
            // If no IPv4, try to find a non-link-local IPv6 address
            addresses
                .iter()
                .find(|addr| addr.is_ipv6() && !addr.to_string().starts_with("fe80:"))
        })
        .or_else(|| {
            // Last resort: use any address and strip zone ID if present
            addresses.iter().next()
        })
        .ok_or(ParseError::NoAddress)?;

    let ip_address = scoped_ip_to_ip_addr(host)?;

    Ok(ServiceInfo {
        instance_name: mdns_info.get_fullname().to_string(),
        display_name: mdns_info.get_fullname().to_string(), // Will be cleaned up
        ip_address,
        port: mdns_info.get_port(),
        fingerprint,
        metadata_version,
        auth_token: openscreen_discovery::AuthToken::from_string(auth_token),
        discovered_at: SystemTime::now(),
    })
}

/// Build ServiceInfo from mdns-sd ServiceInfo
///
/// Converts from mdns-sd types to our ServiceInfo
#[allow(dead_code)]
pub fn service_info_from_mdns(mdns_info: &mdns_sd::ServiceInfo) -> Result<ServiceInfo, ParseError> {
    let (fingerprint, metadata_version, auth_token) =
        parse_txt_properties(mdns_info.get_properties())?;

    // Get host address: Prefer IPv4 over IPv6, and non-link-local over link-local
    // Link-local IPv6 addresses (fe80::...) often include zone IDs (%lo0, %eth0, etc.)
    // which can't be parsed as socket addresses. IPv4 addresses are more reliable.
    let addresses = mdns_info.get_addresses();

    // Try to find an IPv4 address first
    let host = addresses
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| {
            // If no IPv4, try to find a non-link-local IPv6 address
            addresses
                .iter()
                .find(|addr| addr.is_ipv6() && !addr.to_string().starts_with("fe80:"))
        })
        .or_else(|| {
            // Last resort: use any address and strip zone ID if present
            addresses.iter().next()
        })
        .ok_or(ParseError::NoAddress)?;

    let ip_address = *host;

    Ok(ServiceInfo {
        instance_name: mdns_info.get_fullname().to_string(),
        display_name: mdns_info.get_fullname().to_string(), // Will be cleaned up
        ip_address,
        port: mdns_info.get_port(),
        fingerprint,
        metadata_version,
        auth_token: openscreen_discovery::AuthToken::from_string(auth_token),
        discovered_at: SystemTime::now(),
    })
}

/// Errors that can occur when parsing mDNS service info
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Missing required TXT record field: {0}")]
    MissingField(&'static str),

    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(#[from] FingerprintError),

    #[error("Invalid metadata version (not a valid u32)")]
    InvalidMetadataVersion,

    #[error("No address found for service")]
    NoAddress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_instance_name_short() {
        let name = "Short Name";
        assert_eq!(sanitize_instance_name(name), "Short Name");
    }

    #[test]
    fn test_sanitize_instance_name_long() {
        let name = "A".repeat(100);
        let sanitized = sanitize_instance_name(&name);
        assert!(sanitized.len() <= 64); // 63 + null terminator
        assert!(sanitized.ends_with('\0'));
    }

    #[test]
    fn test_sanitize_instance_name_exactly_63() {
        let name = "A".repeat(63);
        let sanitized = sanitize_instance_name(&name);
        assert_eq!(sanitized.len(), 63);
        assert!(!sanitized.ends_with('\0'));
    }

    #[test]
    fn test_build_txt_properties() {
        let txt = TxtRecords {
            fp: "test_fingerprint".to_string(),
            mv: 42,
            at: "test_token".to_string(),
        };

        let props = build_txt_properties(&txt);
        assert_eq!(props.len(), 3);

        assert_eq!(props[0].key(), "fp");
        assert_eq!(props[0].val_str(), "test_fingerprint");

        assert_eq!(props[1].key(), "mv");
        // mv=42 is encoded as RFC9000 varint: single byte 0x2A
        assert_eq!(props[1].val(), Some([42u8].as_slice()));

        assert_eq!(props[2].key(), "at");
        assert_eq!(props[2].val_str(), "test_token");
    }

    // Note: parse_txt_properties tests require mdns-sd::TxtProperties which
    // is complex to construct in tests. These are integration-tested via
    // end-to-end mDNS tests instead.
    //
    // VarInt encode/decode tests are in openscreen-common/tests/varint.rs
}
