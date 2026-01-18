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

//! Service information types

use crate::{AuthToken, Fingerprint};
use core::net::IpAddr;
use std::time::SystemTime;

/// A discovered OpenScreen service
///
/// IMPORTANT: Two ServiceInfo instances are considered equal if they have the same
/// fingerprint, regardless of instance_name. Instance names can change due to mDNS
/// conflicts (e.g., "Living Room TV" -> "Living Room TV (2)"), but the fingerprint
/// is the stable, cryptographic identity of the device.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// Service instance name (from mDNS)
    /// NOTE: This can change if there are name conflicts on the network
    pub instance_name: String,

    /// Display name (decoded from instance name)
    pub display_name: String,

    /// IP address (v4 or v6)
    pub ip_address: IpAddr,

    /// Port number
    pub port: u16,

    /// Certificate fingerprint (SPKI SHA-256)
    /// This is the STABLE identifier for the device
    pub fingerprint: Fingerprint,

    /// Metadata version
    pub metadata_version: u32,

    /// Authentication token (for rate limiting)
    pub auth_token: AuthToken,

    /// Time when service was discovered
    pub discovered_at: SystemTime,
}

impl PartialEq for ServiceInfo {
    fn eq(&self, other: &Self) -> bool {
        // Equality based ONLY on fingerprint (stable cryptographic identity)
        self.fingerprint == other.fingerprint
    }
}

impl Eq for ServiceInfo {}

/// Information needed to advertise a service
#[derive(Debug, Clone)]
pub struct PublishInfo {
    /// Display name (becomes instance name)
    pub display_name: String,

    /// Port number for QUIC connections
    pub port: u16,

    /// Certificate fingerprint (SPKI SHA-256 base64)
    pub fingerprint: Fingerprint,

    /// Metadata version
    pub metadata_version: u32,

    /// Authentication token (for rate limiting)
    pub auth_token: AuthToken,

    /// Agent hostname per W3C spec (format: <base64Serial>.<name>.<domain>)
    pub hostname: String,
}

/// TXT record data per W3C spec
#[derive(Debug, Clone)]
pub struct TxtRecords {
    /// Fingerprint (base64-encoded SPKI SHA-256)
    pub fp: String,

    /// Metadata version
    pub mv: u32,

    /// Authentication token
    pub at: String,
}

impl TxtRecords {
    /// Create TXT records from PublishInfo
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::{TxtRecords, PublishInfo, Fingerprint, AuthToken};
    /// # let info = PublishInfo {
    /// #     display_name: "Test".to_string(),
    /// #     port: 4433,
    /// #     fingerprint: Fingerprint::from_bytes([42u8; 32]),
    /// #     metadata_version: 1,
    /// #     auth_token: AuthToken::generate(),
    /// #     hostname: "test.device.local".to_string(),
    /// # };
    /// let txt = TxtRecords::from_publish_info(&info);
    /// assert!(!txt.fp.is_empty());
    /// assert_eq!(txt.mv, 1);
    /// assert!(!txt.at.is_empty());
    /// ```
    pub fn from_publish_info(info: &PublishInfo) -> Self {
        Self {
            fp: info.fingerprint.to_base64(),
            mv: info.metadata_version,
            at: info.auth_token.as_str().to_string(),
        }
    }

    /// Format as mDNS TXT record strings
    ///
    /// Returns a vector of key=value strings suitable for mDNS registration.
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::{TxtRecords, PublishInfo, Fingerprint, AuthToken};
    /// # let info = PublishInfo {
    /// #     display_name: "Test".to_string(),
    /// #     port: 4433,
    /// #     fingerprint: Fingerprint::from_bytes([42u8; 32]),
    /// #     metadata_version: 1,
    /// #     auth_token: AuthToken::generate(),
    /// #     hostname: "test.device.local".to_string(),
    /// # };
    /// let txt = TxtRecords::from_publish_info(&info);
    /// let records = txt.to_strings();
    /// // records = ["fp=<base64>", "mv=1", "at=<token>"]
    /// ```
    pub fn to_strings(&self) -> Vec<String> {
        vec![
            format!("fp={}", self.fp),
            format!("mv={}", self.mv),
            format!("at={}", self.at),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_info_equality() {
        let fp1 = Fingerprint::from_bytes([1u8; 32]);
        let fp2 = Fingerprint::from_bytes([2u8; 32]);

        let info1 = ServiceInfo {
            instance_name: "Device 1".to_string(),
            display_name: "Device 1".to_string(),
            ip_address: "192.168.1.1".parse().unwrap(),
            port: 4433,
            fingerprint: fp1,
            metadata_version: 1,
            auth_token: AuthToken::generate(),
            discovered_at: SystemTime::now(),
        };

        let info2 = ServiceInfo {
            instance_name: "Device 1 (2)".to_string(), // Different name!
            display_name: "Device 1".to_string(),
            ip_address: "192.168.1.2".parse().unwrap(), // Different ip!
            port: 5544,                                 // Different port!
            fingerprint: fp1,                           // Same fingerprint
            metadata_version: 2,
            auth_token: AuthToken::generate(),
            discovered_at: SystemTime::now(),
        };

        let info3 = ServiceInfo {
            instance_name: "Device 1".to_string(),
            display_name: "Device 1".to_string(),
            ip_address: "192.168.1.1".parse().unwrap(),
            port: 4433,
            fingerprint: fp2, // Different fingerprint
            metadata_version: 1,
            auth_token: AuthToken::generate(),
            discovered_at: SystemTime::now(),
        };

        // Same fingerprint = equal, despite different names/hosts/ports
        assert_eq!(info1, info2);

        // Different fingerprint = not equal
        assert_ne!(info1, info3);
    }

    #[test]
    fn test_txt_records_from_publish_info() {
        let info = PublishInfo {
            display_name: "Test Device".to_string(),
            port: 4433,
            fingerprint: Fingerprint::from_bytes([42u8; 32]),
            metadata_version: 1,
            auth_token: AuthToken::from_string("0123456789abcdef".to_string()),
            hostname: "test.device.local".to_string(),
        };

        let txt = TxtRecords::from_publish_info(&info);
        assert_eq!(txt.mv, 1);
        assert_eq!(txt.at, "0123456789abcdef");
        assert!(!txt.fp.is_empty());
    }

    #[test]
    fn test_txt_records_to_strings() {
        let txt = TxtRecords {
            fp: "test_fingerprint".to_string(),
            mv: 1,
            at: "test_token".to_string(),
        };

        let strings = txt.to_strings();
        assert_eq!(strings.len(), 3);
        assert!(strings.contains(&"fp=test_fingerprint".to_string()));
        assert!(strings.contains(&"mv=1".to_string()));
        assert!(strings.contains(&"at=test_token".to_string()));
    }
}
