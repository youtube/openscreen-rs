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

//! Common test utilities for openscreen-quinn tests

/// Helper to generate test certificates (tests only - not W3C compliant)
///
/// This generates simple self-signed certificates with Subject CN set.
/// For production use, use `openscreen_application::cert::CertificateKey` instead.
pub fn generate_test_cert(hostname: &str) -> (Vec<u8>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().expect("Failed to generate key pair");
    let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()])
        .expect("Failed to create certificate params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    let cert = params
        .self_signed(&key_pair)
        .expect("Failed to self-sign certificate");
    (cert.der().to_vec(), key_pair.serialize_der())
}
