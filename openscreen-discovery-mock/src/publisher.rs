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

//! Mock discovery publisher implementation

use crate::backend::MockBackend;
use async_trait::async_trait;
use openscreen_discovery::{
    DiscoveryError, DiscoveryPublisher, PublishInfo, ServiceInfo, TxtRecords,
};
use std::time::SystemTime;

/// Mock implementation of DiscoveryPublisher
///
/// This publisher stores services in an in-memory backend shared with MockBrowser instances.
pub struct MockPublisher {
    backend: MockBackend,
    current_service: Option<ServiceInfo>,
}

impl MockPublisher {
    /// Create a new mock publisher
    ///
    /// # Example
    ///
    /// ```
    /// use openscreen_discovery_mock::{MockPublisher, MockBackend};
    ///
    /// let backend = MockBackend::new();
    /// let publisher = MockPublisher::new(backend);
    /// ```
    pub fn new(backend: MockBackend) -> Self {
        Self {
            backend,
            current_service: None,
        }
    }
}

#[async_trait]
impl DiscoveryPublisher for MockPublisher {
    async fn publish(&mut self, info: PublishInfo) -> Result<(), DiscoveryError> {
        // Convert PublishInfo to ServiceInfo
        let service_info = ServiceInfo {
            instance_name: info.display_name.clone(),
            display_name: info.display_name,
            hostname: info.hostname,
            ip_address: std::net::Ipv4Addr::LOCALHOST.into(), // Mock always uses localhost
            port: info.port,
            fingerprint: info.fingerprint,
            metadata_version: info.metadata_version,
            auth_token: info.auth_token,
            discovered_at: SystemTime::now(),
        };

        // Store in backend
        self.backend.publish(service_info.clone()).await;
        self.current_service = Some(service_info);

        Ok(())
    }

    async fn unpublish(&mut self) -> Result<(), DiscoveryError> {
        if let Some(service) = &self.current_service {
            self.backend.unpublish(&service.instance_name).await;
            self.current_service = None;
        }
        Ok(())
    }

    async fn update_txt_records(&mut self, txt: TxtRecords) -> Result<(), DiscoveryError> {
        // In mock implementation, we simulate the mDNS "blink" behavior:
        // unpublish, update records, re-publish

        if let Some(mut service) = self.current_service.take() {
            // Unpublish
            self.backend.unpublish(&service.instance_name).await;

            // Update TXT records
            // Note: In mock, we only update the fields that come from TXT records
            // In real mDNS, fingerprint and auth_token would change
            service.metadata_version = txt.mv;

            // Re-publish
            self.backend.publish(service.clone()).await;
            self.current_service = Some(service);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openscreen_discovery::{AuthToken, Fingerprint};

    #[tokio::test]
    async fn test_mock_publisher_publish() {
        let backend = MockBackend::new();
        let mut publisher = MockPublisher::new(backend.clone());

        let info = PublishInfo {
            display_name: "Test Device".to_string(),
            hostname: "test-device._openscreen._tcp.local".to_string(),
            port: 4433,
            fingerprint: Fingerprint::from_bytes([1u8; 32]),
            metadata_version: 1,
            auth_token: AuthToken::generate(),
        };

        publisher.publish(info).await.unwrap();

        // Verify service was published to backend
        assert_eq!(backend.service_count().await, 1);

        let services = backend.get_services().await;
        assert_eq!(services[0].display_name, "Test Device");
        assert_eq!(services[0].port, 4433);
    }

    #[tokio::test]
    async fn test_mock_publisher_unpublish() {
        let backend = MockBackend::new();
        let mut publisher = MockPublisher::new(backend.clone());

        let info = PublishInfo {
            display_name: "Test Device".to_string(),
            hostname: "test-device._openscreen._tcp.local".to_string(),
            port: 4433,
            fingerprint: Fingerprint::from_bytes([1u8; 32]),
            metadata_version: 1,
            auth_token: AuthToken::generate(),
        };

        publisher.publish(info).await.unwrap();
        assert_eq!(backend.service_count().await, 1);

        publisher.unpublish().await.unwrap();
        assert_eq!(backend.service_count().await, 0);
    }

    #[tokio::test]
    async fn test_mock_publisher_update_txt_records() {
        let backend = MockBackend::new();
        let mut publisher = MockPublisher::new(backend.clone());

        let info = PublishInfo {
            display_name: "Test Device".to_string(),
            hostname: "test-device._openscreen._tcp.local".to_string(),
            port: 4433,
            fingerprint: Fingerprint::from_bytes([1u8; 32]),
            metadata_version: 1,
            auth_token: AuthToken::generate(),
        };

        publisher.publish(info).await.unwrap();

        // Update TXT records
        let new_txt = TxtRecords {
            fp: Fingerprint::from_bytes([2u8; 32]).to_base64(),
            mv: 2,
            at: "new_token".to_string(),
        };

        publisher.update_txt_records(new_txt).await.unwrap();

        // Verify metadata version was updated
        let services = backend.get_services().await;
        assert_eq!(services[0].metadata_version, 2);
    }
}
