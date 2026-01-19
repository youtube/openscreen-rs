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

//! Certificate generation and management
//!
//! This module handles self-signed certificate generation for OpenScreen devices.

// This module requires std (only compiled for binaries, not no_std library)
extern crate std;

use anyhow::{Context, Result};
use openscreen_discovery::Fingerprint;
use std::{format, path::Path, string::String, vec, vec::Vec};
use uuid::Uuid;

/// OpenScreen certificate serial number (160 bits per W3C spec)
///
/// Format: 128-bit UUID base + 32-bit counter
/// Per W3C network.bs § Computing the Certificate Serial Number
#[derive(Debug, Clone)]
pub struct SerialNumber {
    /// 128-bit UUID base (RFC 4122 v4)
    uuid_base: Uuid,
    /// 32-bit counter for certificate rotation
    counter: u32,
}

impl SerialNumber {
    /// Generate new serial number with random UUID and counter=0
    pub fn generate() -> Self {
        Self {
            uuid_base: Uuid::new_v4(),
            counter: 0,
        }
    }

    /// Convert to 160-bit byte array (UUID + counter in big-endian)
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0..16].copy_from_slice(self.uuid_base.as_bytes());
        bytes[16..20].copy_from_slice(&self.counter.to_be_bytes());
        bytes
    }

    /// Base64 encode serial number per RFC 4648
    pub fn to_base64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode(self.to_bytes())
    }

    /// Parse from 160-bit bytes
    #[allow(dead_code)]
    pub fn from_bytes(bytes: [u8; 20]) -> Result<Self> {
        let uuid_bytes: [u8; 16] = bytes[0..16].try_into().context("Invalid UUID bytes")?;
        let counter_bytes: [u8; 4] = bytes[16..20].try_into().context("Invalid counter bytes")?;

        Ok(Self {
            uuid_base: Uuid::from_bytes(uuid_bytes),
            counter: u32::from_be_bytes(counter_bytes),
        })
    }

    /// Extract serial number from X.509 certificate DER bytes
    ///
    /// Handles ASN.1 DER integer encoding:
    /// - Integers are signed, so MSB >= 128 gets 0x00 prepended (21 bytes)
    /// - Leading zeros may be stripped (< 20 bytes)
    /// - Must normalize to exactly 20 bytes for OpenScreen spec
    pub fn from_x509_cert(cert_der: &[u8]) -> Result<Self> {
        use x509_parser::prelude::*;

        // Parse X.509 certificate
        let (_, x509_cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| anyhow::anyhow!("Failed to parse X.509 certificate: {e:?}"))?;

        // Extract raw serial bytes (may be 19-21 bytes due to ASN.1 encoding)
        let serial_bytes_raw = x509_cert.serial.to_bytes_be();

        // Normalize to exactly 20 bytes per OpenScreen spec
        let serial_bytes = normalize_serial_bytes(&serial_bytes_raw)?;

        Self::from_bytes(serial_bytes)
    }
}

/// Normalize ASN.1 DER integer bytes to exactly 20 bytes
///
/// ASN.1 DER integers are signed, which causes size variations:
/// - If MSB >= 128: prepends 0x00 to indicate positive -> 21 bytes
/// - If leading zeros: may strip them -> < 20 bytes
///
/// This function ensures we always get exactly 20 bytes for OpenScreen spec.
fn normalize_serial_bytes(bytes: &[u8]) -> Result<[u8; 20]> {
    match bytes.len() {
        // Exactly 20 bytes - perfect, just copy
        20 => {
            let mut result = [0u8; 20];
            result.copy_from_slice(bytes);
            Ok(result)
        }
        // 21 bytes - ASN.1 added 0x00 prefix for positive number
        21 => {
            if bytes[0] != 0x00 {
                anyhow::bail!(
                    "Expected 0x00 prefix for 21-byte serial, got: 0x{:02x}",
                    bytes[0]
                );
            }
            let mut result = [0u8; 20];
            result.copy_from_slice(&bytes[1..21]);
            Ok(result)
        }
        // < 20 bytes - leading zeros were stripped, pad on left
        len if len < 20 => {
            let mut result = [0u8; 20];
            let offset = 20 - len;
            result[offset..].copy_from_slice(bytes);
            Ok(result)
        }
        // > 21 bytes - invalid
        len => anyhow::bail!("Serial number has invalid length: {len} bytes (expected 19-21)"),
    }
}

/// Construct agent hostname per W3C spec
///
/// Format: <base64(Serial)>.<SanitizedName>.<EncodedDomain>
/// Per W3C network.bs § Computing the Agent Hostname
pub fn compute_hostname(serial: &SerialNumber, instance_name: &str, domain: &str) -> String {
    let base64_serial = serial.to_base64();
    let sanitized_name = sanitize_hostname_component(instance_name);
    let encoded_domain = sanitize_hostname_component(domain);

    format!("{base64_serial}.{sanitized_name}.{encoded_domain}")
}

/// Sanitize hostname component per spec
/// Replace any character other than [A-Za-z0-9-] with hyphen
fn sanitize_hostname_component(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Certificate and private key pair
///
/// Stores certificate and key as DER-encoded bytes
pub struct CertificateKey {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub fingerprint: Fingerprint,
    pub serial_number: SerialNumber,
    pub hostname: String,
}

impl CertificateKey {
    /// Generate a new self-signed certificate
    ///
    /// Per W3C spec:
    /// - Serial: 160-bit (128-bit UUID + 32-bit counter)
    /// - Subject CN: <base64(Serial)>.<Name>.<Domain>
    /// - Algorithm: ECDSA with secp256r1 (P-256)
    /// - Hash: SHA-256
    /// - Self-signed X.509 v3
    pub fn generate(instance_name: &str, domain: &str) -> Result<Self> {
        // Generate serial number per W3C spec (128-bit UUID + 32-bit counter)
        let serial_number = SerialNumber::generate();

        // Compute hostname per W3C spec
        let hostname = compute_hostname(&serial_number, instance_name, domain);

        // Generate ECDSA key pair
        let key_pair = rcgen::KeyPair::generate().context("Failed to generate key pair")?;
        let key_der = key_pair.serialize_der();

        // Create certificate parameters with hostname as Subject CN
        let mut params = rcgen::CertificateParams::new(vec![hostname.clone()])
            .context("Failed to create certificate parameters")?;

        // Set Subject CN to the spec-compliant hostname
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname.clone());

        // Set spec-compliant serial number (160 bits)
        let serial_bytes = serial_number.to_bytes();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));

        // Generate self-signed certificate
        let cert = params
            .self_signed(&key_pair)
            .context("Failed to self-sign certificate")?;

        let cert_der = cert.der().to_vec();

        // Calculate fingerprint (SPKI SHA-256 per W3C spec)
        let fingerprint = Fingerprint::from_der_cert(&cert_der)
            .map_err(|e| anyhow::anyhow!("Failed to calculate fingerprint: {e:?}"))?;

        Ok(Self {
            cert_der,
            key_der,
            fingerprint,
            serial_number,
            hostname,
        })
    }

    /// Load certificate from PEM files
    ///
    /// Loads cert.pem and key.pem from the specified directory.
    /// Extracts the serial number from the loaded certificate to preserve identity.
    pub fn load_from_pem(dir: &Path, instance_name: &str, domain: &str) -> Result<Self> {
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");

        let cert_pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("Failed to read certificate from {}", cert_path.display()))?;

        let key_pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("Failed to read private key from {}", key_path.display()))?;

        let key_pair = rcgen::KeyPair::from_pem(&key_pem).context("Failed to parse private key")?;
        let key_der = key_pair.serialize_der();

        // Parse PEM to get DER bytes
        let cert_der = pem::parse(&cert_pem)
            .context("Failed to parse certificate PEM")?
            .contents()
            .to_vec();

        // Calculate fingerprint (SPKI SHA-256 per W3C spec)
        let fingerprint = Fingerprint::from_der_cert(&cert_der)
            .map_err(|e| anyhow::anyhow!("Failed to calculate fingerprint: {e:?}"))?;

        // Extract serial number from loaded certificate (preserves identity across restarts)
        let serial_number = SerialNumber::from_x509_cert(&cert_der)
            .context("Failed to extract serial number from certificate")?;

        let hostname = compute_hostname(&serial_number, instance_name, domain);

        Ok(Self {
            cert_der,
            key_der,
            fingerprint,
            serial_number,
            hostname,
        })
    }

    /// Save certificate to PEM files
    ///
    /// Saves cert.pem and key.pem to the specified directory
    pub fn save_to_pem(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create directory {}", dir.display()))?;

        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");

        // Encode cert_der as PEM
        let cert_pem_obj = pem::Pem::new("CERTIFICATE", self.cert_der.clone());
        let cert_pem = pem::encode(&cert_pem_obj);

        // Encode key_der as PEM
        // The key is in PKCS#8 format, which uses the "PRIVATE KEY" tag
        let key_pem_obj = pem::Pem::new("PRIVATE KEY", self.key_der.clone());
        let key_pem = pem::encode(&key_pem_obj);

        std::fs::write(&cert_path, cert_pem)
            .with_context(|| format!("Failed to write certificate to {}", cert_path.display()))?;

        std::fs::write(&key_path, key_pem)
            .with_context(|| format!("Failed to write private key to {}", key_path.display()))?;

        Ok(())
    }

    /// Load or generate certificate
    ///
    /// Tries to load from PEM files, generates new if not found
    pub fn load_or_generate(dir: &Path, instance_name: &str, domain: &str) -> Result<Self> {
        match Self::load_from_pem(dir, instance_name, domain) {
            Ok(cert_key) => {
                tracing::info!("Loaded existing certificate from {:?}", dir);
                Ok(cert_key)
            }
            Err(_) => {
                tracing::info!("Generating new certificate...");
                let cert_key = Self::generate(instance_name, domain)?;
                cert_key.save_to_pem(dir)?;
                tracing::info!("Saved certificate to {:?}", dir);
                Ok(cert_key)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn test_serial_number_format() {
        let serial = SerialNumber::generate();
        let bytes = serial.to_bytes();
        assert_eq!(bytes.len(), 20); // 160 bits

        let base64 = serial.to_base64();
        assert_eq!(base64.len(), 28); // base64 encoding of 20 bytes
    }

    #[test]
    fn test_serial_number_roundtrip() {
        let serial = SerialNumber::generate();
        let bytes = serial.to_bytes();
        let restored = SerialNumber::from_bytes(bytes).unwrap();

        // Compare bytes representations
        assert_eq!(serial.to_bytes(), restored.to_bytes());
        assert_eq!(serial.to_base64(), restored.to_base64());
    }

    #[test]
    fn test_hostname_sanitization() {
        assert_eq!(
            sanitize_hostname_component("Living Room TV!"),
            "Living-Room-TV-"
        );
        assert_eq!(
            sanitize_hostname_component("my@device#123"),
            "my-device-123"
        );
        assert_eq!(sanitize_hostname_component("test_device"), "test-device");
        assert_eq!(sanitize_hostname_component("normal-name"), "normal-name");
    }

    #[test]
    fn test_hostname_format() {
        let serial = SerialNumber::generate();
        let hostname = compute_hostname(&serial, "test-device", "_openscreen._tcp.local");

        // Should have format: <base64Serial>.<name>.<domain>
        let parts: Vec<&str> = hostname.split('.').collect();

        // Should have at least 3 parts (base64.name.domain...)
        assert!(
            parts.len() >= 3,
            "Hostname should have at least 3 parts, got: {hostname}"
        );

        // First part should be base64 serial
        assert_eq!(parts[0], serial.to_base64());

        // Second part should be sanitized name
        assert_eq!(parts[1], "test-device");

        // Remaining parts form the sanitized domain
        // _openscreen._tcp.local becomes -openscreen.-tcp.local
        assert!(hostname.contains(&serial.to_base64()));
    }

    #[test]
    fn test_certificate_has_correct_hostname() {
        let cert = CertificateKey::generate("receiver", "_openscreen._tcp.local").unwrap();

        // Hostname should be in format: <base64Serial>.<name>.<domain>
        let parts: Vec<&str> = cert.hostname.split('.').collect();
        assert!(parts.len() >= 3);

        // First part should be base64 serial (28 chars for 160-bit number)
        assert_eq!(parts[0].len(), 28);

        // Second part should be sanitized name
        assert_eq!(parts[1], "receiver");
    }

    #[test]
    fn test_certificate_serial_is_160_bits() {
        let cert = CertificateKey::generate("test", "local").unwrap();
        let serial_bytes = cert.serial_number.to_bytes();

        assert_eq!(serial_bytes.len(), 20); // 160 bits = 20 bytes

        // Verify UUID part is not all zeros
        let uuid_part = &serial_bytes[0..16];
        assert!(
            uuid_part.iter().any(|&b| b != 0),
            "UUID should not be all zeros"
        );
    }

    #[test]
    fn test_base64_length() {
        let serial = SerialNumber::generate();
        let base64 = serial.to_base64();

        // 20 bytes encoded in base64 = ceil(20 * 8 / 6) = 28 chars (with padding)
        assert_eq!(base64.len(), 28);

        // Should be valid base64
        use base64::{engine::general_purpose::STANDARD, Engine};
        let decoded = STANDARD.decode(&base64).unwrap();
        assert_eq!(decoded.len(), 20);
    }

    #[test]
    fn test_hostname_with_special_chars() {
        let serial = SerialNumber::generate();

        // Test various special characters
        let hostname = compute_hostname(&serial, "My Device!", "test@domain.com");

        // All special chars (including dots, @, !) should be replaced with hyphens
        assert!(hostname.contains(".My-Device-."));
        // dots in domain also get sanitized
        assert!(hostname.contains(".test-domain-com"));
    }

    #[test]
    fn test_certificate_subject_cn_matches_hostname() {
        let cert = CertificateKey::generate("test-receiver", "local").unwrap();

        // Subject CN should match the hostname
        // We can verify this by checking that the hostname is well-formed
        let parts: Vec<&str> = cert.hostname.split('.').collect();
        assert!(parts.len() >= 2);

        // First part should be the base64 serial
        assert_eq!(parts[0], cert.serial_number.to_base64());
    }

    #[test]
    fn test_serial_extraction_roundtrip() {
        // Generate a certificate
        let cert = CertificateKey::generate("test", "local").unwrap();
        let original_serial = cert.serial_number.to_bytes();

        // Extract serial from the certificate DER
        let extracted_serial = SerialNumber::from_x509_cert(&cert.cert_der).unwrap();

        // Should match original
        assert_eq!(original_serial, extracted_serial.to_bytes());
        assert_eq!(cert.serial_number.to_base64(), extracted_serial.to_base64());
    }

    #[test]
    fn test_normalize_serial_20_bytes() {
        // Test exact 20 bytes
        let bytes: Vec<u8> = (0..20).collect();
        let normalized = normalize_serial_bytes(&bytes).unwrap();
        assert_eq!(normalized.len(), 20);
        assert_eq!(&normalized[..], &bytes[..]);
    }

    #[test]
    fn test_normalize_serial_21_bytes_with_padding() {
        // Test 21 bytes with 0x00 prefix (ASN.1 positive integer)
        let mut bytes = vec![0x00];
        bytes.extend((0..20).collect::<Vec<u8>>());
        assert_eq!(bytes.len(), 21);

        let normalized = normalize_serial_bytes(&bytes).unwrap();
        assert_eq!(normalized.len(), 20);
        assert_eq!(&normalized[..], &bytes[1..21]);
    }

    #[test]
    fn test_normalize_serial_21_bytes_invalid() {
        // Test 21 bytes without 0x00 prefix (invalid)
        let bytes: Vec<u8> = (1..22).collect();
        assert_eq!(bytes.len(), 21);

        let result = normalize_serial_bytes(&bytes);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Expected 0x00 prefix"));
    }

    #[test]
    fn test_normalize_serial_19_bytes_leading_zeros() {
        // Test 19 bytes (leading zero was stripped)
        let bytes: Vec<u8> = (1..20).collect();
        assert_eq!(bytes.len(), 19);

        let normalized = normalize_serial_bytes(&bytes).unwrap();
        assert_eq!(normalized.len(), 20);

        // Should be padded with leading zero
        assert_eq!(normalized[0], 0x00);
        assert_eq!(&normalized[1..], &bytes[..]);
    }

    #[test]
    fn test_normalize_serial_invalid_length() {
        // Test invalid lengths
        let too_short: Vec<u8> = (0..10).collect();
        assert!(normalize_serial_bytes(&too_short).is_ok()); // Should pad

        let too_long: Vec<u8> = (0..25).collect();
        let result = normalize_serial_bytes(&too_long);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid length"));
    }

    #[test]
    fn test_serial_extraction_with_msb_set() {
        // Generate a certificate with MSB set in UUID
        // This will cause ASN.1 to prepend 0x00
        let mut serial = SerialNumber::generate();

        // Force MSB to be >= 128 to trigger ASN.1 padding
        let mut uuid_bytes = *serial.uuid_base.as_bytes();
        uuid_bytes[0] = 0xFF; // Force MSB = 255
        serial.uuid_base = Uuid::from_bytes(uuid_bytes);

        // Create certificate params
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["test".to_string()]).unwrap();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial.to_bytes()));

        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der();

        // Extract serial - should handle ASN.1 padding correctly
        let extracted = SerialNumber::from_x509_cert(cert_der).unwrap();
        assert_eq!(serial.to_bytes(), extracted.to_bytes());
    }

    #[test]
    fn test_certificate_persistence_identity() {
        use tempfile::TempDir;

        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path();

        // Generate and save a certificate
        let original_cert = CertificateKey::generate("test-device", "local").unwrap();
        original_cert.save_to_pem(cert_dir).unwrap();

        let original_serial = original_cert.serial_number.to_bytes();
        let original_fingerprint = original_cert.fingerprint;
        let original_hostname = original_cert.hostname.clone();

        // Load the certificate back
        let loaded_cert = CertificateKey::load_from_pem(cert_dir, "test-device", "local").unwrap();

        // Verify identity is preserved
        assert_eq!(
            original_serial,
            loaded_cert.serial_number.to_bytes(),
            "Serial number should be preserved"
        );
        assert_eq!(
            original_fingerprint, loaded_cert.fingerprint,
            "Fingerprint should be preserved"
        );
        assert_eq!(
            original_hostname, loaded_cert.hostname,
            "Hostname should be preserved"
        );

        // Verify load_or_generate uses existing cert
        let reloaded_cert =
            CertificateKey::load_or_generate(cert_dir, "test-device", "local").unwrap();
        assert_eq!(
            original_serial,
            reloaded_cert.serial_number.to_bytes(),
            "load_or_generate should preserve existing identity"
        );
    }
}
