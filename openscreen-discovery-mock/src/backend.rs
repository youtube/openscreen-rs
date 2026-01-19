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

//! Shared mock backend for in-memory service registry

use openscreen_discovery::ServiceInfo;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Event types for the mock backend
#[derive(Debug, Clone)]
pub enum BackendEvent {
    /// A service was published
    ServicePublished(ServiceInfo),
    /// A service was unpublished
    ServiceUnpublished(String), // instance_name
}

/// Shared in-memory service registry
///
/// This backend is shared between `MockPublisher` and `MockBrowser` instances
/// to simulate mDNS service discovery in memory.
#[derive(Clone)]
pub struct MockBackend {
    inner: Arc<MockBackendInner>,
}

struct MockBackendInner {
    /// Registry of published services
    services: RwLock<HashMap<String, ServiceInfo>>,
    /// Event broadcast channel
    event_tx: broadcast::Sender<BackendEvent>,
}

impl MockBackend {
    /// Create a new mock backend
    ///
    /// # Example
    ///
    /// ```
    /// use openscreen_discovery_mock::MockBackend;
    ///
    /// let backend = MockBackend::new();
    /// ```
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(100);
        Self {
            inner: Arc::new(MockBackendInner {
                services: RwLock::new(HashMap::new()),
                event_tx,
            }),
        }
    }

    /// Publish a service (called by MockPublisher)
    pub(crate) async fn publish(&self, info: ServiceInfo) {
        let instance_name = info.instance_name.clone();
        self.inner
            .services
            .write()
            .await
            .insert(instance_name, info.clone());

        // Notify browsers
        let _ = self
            .inner
            .event_tx
            .send(BackendEvent::ServicePublished(info));
    }

    /// Unpublish a service (called by MockPublisher)
    pub(crate) async fn unpublish(&self, instance_name: &str) {
        self.inner.services.write().await.remove(instance_name);

        // Notify browsers
        let _ = self
            .inner
            .event_tx
            .send(BackendEvent::ServiceUnpublished(instance_name.to_string()));
    }

    /// Get all published services (called by MockBrowser)
    pub(crate) async fn get_services(&self) -> Vec<ServiceInfo> {
        self.inner.services.read().await.values().cloned().collect()
    }

    /// Subscribe to backend events (called by MockBrowser)
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<BackendEvent> {
        self.inner.event_tx.subscribe()
    }

    /// Get count of published services (for testing)
    pub async fn service_count(&self) -> usize {
        self.inner.services.read().await.len()
    }

    /// Clear all services (for testing)
    pub async fn clear(&self) {
        self.inner.services.write().await.clear();
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openscreen_discovery::{AuthToken, Fingerprint};
    use std::time::SystemTime;

    fn create_test_service(name: &str) -> ServiceInfo {
        ServiceInfo {
            instance_name: name.to_string(),
            display_name: name.to_string(),
            hostname: format!("{name}.local"),
            ip_address: std::net::Ipv4Addr::LOCALHOST.into(),
            port: 4433,
            fingerprint: Fingerprint::from_bytes([1u8; 32]),
            metadata_version: 1,
            auth_token: AuthToken::generate(),
            discovered_at: SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn test_backend_publish_and_get() {
        let backend = MockBackend::new();
        let service = create_test_service("test");

        backend.publish(service.clone()).await;

        let services = backend.get_services().await;
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].instance_name, "test");
    }

    #[tokio::test]
    async fn test_backend_unpublish() {
        let backend = MockBackend::new();
        let service = create_test_service("test");

        backend.publish(service).await;
        assert_eq!(backend.service_count().await, 1);

        backend.unpublish("test").await;
        assert_eq!(backend.service_count().await, 0);
    }

    #[tokio::test]
    async fn test_backend_multiple_services() {
        let backend = MockBackend::new();

        backend.publish(create_test_service("device1")).await;
        backend.publish(create_test_service("device2")).await;
        backend.publish(create_test_service("device3")).await;

        assert_eq!(backend.service_count().await, 3);
    }

    #[tokio::test]
    async fn test_backend_clear() {
        let backend = MockBackend::new();

        backend.publish(create_test_service("device1")).await;
        backend.publish(create_test_service("device2")).await;

        backend.clear().await;
        assert_eq!(backend.service_count().await, 0);
    }
}
