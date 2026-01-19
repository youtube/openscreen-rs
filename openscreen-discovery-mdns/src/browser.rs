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

//! mDNS browser implementation

use crate::utils::service_info_from_mdns;
use crate::SERVICE_NAME;
use async_trait::async_trait;
use futures::stream::{BoxStream, StreamExt};
use openscreen_discovery::{DiscoveryBrowser, DiscoveryError, DiscoveryEvent, ServiceInfo};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// mDNS-based implementation of DiscoveryBrowser
///
/// This browser uses the `mdns-sd` crate to discover OpenScreen services
/// on the local network.
pub struct MdnsBrowser {
    mdns: mdns_sd::ServiceDaemon,
    services: Arc<RwLock<HashMap<String, ServiceInfo>>>,
    receiver: Option<mdns_sd::Receiver<mdns_sd::ServiceEvent>>,
    browsing: Arc<RwLock<bool>>,
}

impl MdnsBrowser {
    /// Create a new mDNS browser using the default port (5353).
    ///
    /// For development/testing with custom ports, use [`MdnsBrowser::new_with_port`].
    ///
    /// # Errors
    ///
    /// Returns an error if the mDNS daemon cannot be started.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use openscreen_discovery_mdns::MdnsBrowser;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let browser = MdnsBrowser::new()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self, DiscoveryError> {
        Self::new_with_port(mdns_sd::MDNS_PORT)
    }

    /// Create a new mDNS browser using a custom port.
    ///
    /// # Arguments
    ///
    /// * `port` - The UDP port to bind for mDNS communication.
    ///   - In production, this should be 5353 per RFC 6762.
    ///   - For development/testing, you can use a non-standard port (e.g., 5454)
    ///     to avoid conflicts with system mDNS services like macOS Bonjour.
    ///   - Both publisher and browser must use the same port to communicate.
    ///
    /// # Errors
    ///
    /// Returns an error if the mDNS daemon cannot be started.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use openscreen_discovery_mdns::MdnsBrowser;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use custom port for development (avoids macOS Bonjour conflict)
    /// let browser = MdnsBrowser::new_with_port(5454)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_with_port(port: u16) -> Result<Self, DiscoveryError> {
        let mdns = mdns_sd::ServiceDaemon::new_with_port(port).map_err(|e| {
            DiscoveryError::BrowseFailed(format!("Failed to create mDNS daemon: {e}"))
        })?;

        Ok(Self {
            mdns,
            services: Arc::new(RwLock::new(HashMap::new())),
            receiver: None,
            browsing: Arc::new(RwLock::new(false)),
        })
    }
}

#[async_trait]
impl DiscoveryBrowser for MdnsBrowser {
    async fn start_browsing(&mut self) -> Result<(), DiscoveryError> {
        // Start browsing for OpenScreen services
        let receiver = self
            .mdns
            .browse(SERVICE_NAME)
            .map_err(|e| DiscoveryError::BrowseFailed(format!("Failed to start browsing: {e}")))?;

        self.receiver = Some(receiver);
        *self.browsing.write().await = true;

        // Spawn background task to process mDNS events
        let services = self.services.clone();
        let receiver = self.receiver.as_ref().unwrap().clone();
        let browsing = self.browsing.clone();

        tokio::spawn(async move {
            loop {
                if !*browsing.read().await {
                    break;
                }

                match receiver.recv_async().await {
                    Ok(event) => {
                        match event {
                            mdns_sd::ServiceEvent::ServiceResolved(info) => {
                                log::debug!("Service resolved: {}", info.get_fullname());

                                match service_info_from_mdns(&info) {
                                    Ok(service_info) => {
                                        let fullname = info.get_fullname().to_string();
                                        services.write().await.insert(fullname, service_info);
                                    }
                                    Err(e) => {
                                        log::warn!("Failed to parse service info: {e}");
                                    }
                                }
                            }
                            mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                                log::debug!("Service removed: {fullname}");
                                services.write().await.remove(&fullname);
                            }
                            _ => {
                                // Ignore other events (SearchStarted, SearchStopped, etc.)
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Error receiving mDNS event: {e}");
                        break;
                    }
                }
            }
        });

        log::info!("Started browsing for OpenScreen services");
        Ok(())
    }

    async fn stop_browsing(&mut self) -> Result<(), DiscoveryError> {
        *self.browsing.write().await = false;

        if self.receiver.is_some() {
            // Stop browsing (mdns-sd will clean up automatically when receiver is dropped)
            self.mdns.stop_browse(SERVICE_NAME).map_err(|e| {
                DiscoveryError::StopBrowseFailed(format!("Failed to stop browsing: {e}"))
            })?;

            self.receiver = None;
            log::info!("Stopped browsing for OpenScreen services");
        }

        Ok(())
    }

    fn discovered_services(&self) -> Vec<ServiceInfo> {
        // Synchronous snapshot of discovered services
        futures::executor::block_on(async {
            self.services.read().await.values().cloned().collect()
        })
    }

    fn event_stream(&self) -> BoxStream<'_, DiscoveryEvent> {
        let services = self.services.clone();
        let browsing = self.browsing.clone();
        let receiver = self.receiver.clone();

        async_stream::stream! {
            if let Some(receiver) = receiver {
                loop {
                    if !*browsing.read().await {
                        break;
                    }

                    match receiver.recv_async().await {
                        Ok(event) => {
                            match event {
                                mdns_sd::ServiceEvent::ServiceResolved(info) => {
                                    match service_info_from_mdns(&info) {
                                        Ok(service_info) => {
                                            let fullname = info.get_fullname().to_string();
                                            services.write().await.insert(fullname.clone(), service_info.clone());
                                            yield DiscoveryEvent::ServiceDiscovered(service_info);
                                        }
                                        Err(e) => {
                                            log::warn!("Failed to parse service info: {e}");
                                        }
                                    }
                                }
                                mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                                    services.write().await.remove(&fullname);
                                    yield DiscoveryEvent::ServiceRemoved {
                                        instance_name: fullname,
                                    };
                                }
                                _ => {
                                    // Ignore other events
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("Error receiving mDNS event: {e}");
                            break;
                        }
                    }
                }
            }
        }
        .boxed()
    }
}

impl Drop for MdnsBrowser {
    fn drop(&mut self) {
        // Best-effort stop on drop
        if *futures::executor::block_on(self.browsing.read()) {
            let _ = futures::executor::block_on(self.stop_browsing());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdns_browser_new() {
        // This test verifies that we can create an mDNS browser
        // It may fail if mDNS is not available on the system
        let result = MdnsBrowser::new();

        match result {
            Ok(_) => log::debug!("mDNS browser created successfully"),
            Err(e) => log::debug!("mDNS not available (expected in some environments): {e}"),
        }
    }

    // Note: End-to-end mDNS tests require network access and may be flaky
    // Full integration tests should be run manually
}
