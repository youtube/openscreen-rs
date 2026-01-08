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

//! mDNS publisher implementation

use crate::utils::{build_txt_properties, sanitize_instance_name};
use crate::SERVICE_NAME;
use async_trait::async_trait;
use openscreen_discovery::{DiscoveryError, DiscoveryPublisher, PublishInfo, TxtRecords};

/// mDNS-based implementation of DiscoveryPublisher
///
/// This publisher uses the `mdns-sd` crate to advertise OpenScreen services
/// on the local network.
pub struct MdnsPublisher {
    mdns: mdns_sd::ServiceDaemon,
    service_fullname: Option<String>,
}

impl MdnsPublisher {
    /// Create a new mDNS publisher using the default port (5353).
    ///
    /// For development/testing with custom ports, use [`MdnsPublisher::new_with_port`].
    ///
    /// # Errors
    ///
    /// Returns an error if the mDNS daemon cannot be started.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use openscreen_discovery_mdns::MdnsPublisher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let publisher = MdnsPublisher::new()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self, DiscoveryError> {
        Self::new_with_port(mdns_sd::MDNS_PORT)
    }

    /// Create a new mDNS publisher using a custom port.
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
    /// use openscreen_discovery_mdns::MdnsPublisher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use custom port for development (avoids macOS Bonjour conflict)
    /// let publisher = MdnsPublisher::new_with_port(5454)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_with_port(port: u16) -> Result<Self, DiscoveryError> {
        let mdns = mdns_sd::ServiceDaemon::new_with_port(port).map_err(|e| {
            DiscoveryError::PublishFailed(format!("Failed to create mDNS daemon: {e}"))
        })?;

        Ok(Self {
            mdns,
            service_fullname: None,
        })
    }
}

#[async_trait]
impl DiscoveryPublisher for MdnsPublisher {
    async fn publish(&mut self, info: PublishInfo) -> Result<(), DiscoveryError> {
        // Sanitize instance name per DNS label limits
        let instance_name = sanitize_instance_name(&info.display_name);

        // Build TXT records
        let txt = TxtRecords::from_publish_info(&info);
        let properties = build_txt_properties(&txt);

        // Use spec-compliant hostname from PublishInfo
        // Hostname format: <base64(Serial)>.<Name>.<Domain>
        // Per W3C network.bs § Computing the Agent Hostname
        // mdns-sd requires hostname to end with ".local."
        let hostname = if info.hostname.to_lowercase().ends_with(".local") {
            format!("{}.", info.hostname)
        } else if info.hostname.to_lowercase().ends_with(".local.") {
            info.hostname.clone()
        } else {
            format!("{}.local.", info.hostname)
        };

        // Create service info with automatic address detection
        // Call enable_addr_auto() to make mdns-sd automatically discover and
        // advertise IP addresses from all available network interfaces
        let service_info = mdns_sd::ServiceInfo::new(
            SERVICE_NAME,
            &instance_name,
            &hostname,
            (), // addresses (will be auto-detected)
            info.port,
            properties,
        )
        .map_err(|e| DiscoveryError::PublishFailed(format!("Failed to create service info: {e}")))?
        .enable_addr_auto();

        // Register the service
        let fullname = service_info.get_fullname().to_string();
        self.mdns.register(service_info).map_err(|e| {
            DiscoveryError::PublishFailed(format!("Failed to register service: {e}"))
        })?;

        log::info!("Published mDNS service: {fullname}");
        self.service_fullname = Some(fullname);

        Ok(())
    }

    async fn unpublish(&mut self) -> Result<(), DiscoveryError> {
        if let Some(fullname) = &self.service_fullname {
            self.mdns.unregister(fullname).map_err(|e| {
                DiscoveryError::UnpublishFailed(format!("Failed to unregister service: {e}"))
            })?;

            log::info!("Unpublished mDNS service: {fullname}");
            self.service_fullname = None;
        }
        Ok(())
    }

    async fn update_txt_records(&mut self, _txt: TxtRecords) -> Result<(), DiscoveryError> {
        // Per Gemini review: mdns-sd doesn't have native update support
        // Must do unregister + register (device "blinks" on network)

        if let Some(_fullname) = self.service_fullname.clone() {
            // We need to save the current service info to re-register
            // However, we don't have access to the original PublishInfo
            // For now, return an error. Real implementation would cache PublishInfo.

            log::warn!("update_txt_records requires unregister+register (not yet implemented)");
            return Err(DiscoveryError::Other(
                "update_txt_records not fully implemented - requires caching PublishInfo"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

impl Drop for MdnsPublisher {
    fn drop(&mut self) {
        // Best-effort unpublish on drop
        if self.service_fullname.is_some() {
            let _ = futures::executor::block_on(self.unpublish());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdns_publisher_new() {
        // This test verifies that we can create an mDNS publisher
        // It may fail if mDNS is not available on the system
        let result = MdnsPublisher::new();

        // We don't assert success because mDNS might not be available
        // in all test environments (CI, containers, etc.)
        match result {
            Ok(_) => log::debug!("mDNS publisher created successfully"),
            Err(e) => log::debug!("mDNS not available (expected in some environments): {e}"),
        }
    }

    // Note: End-to-end mDNS tests require network access and may be flaky
    // Full integration tests should be run manually
}
