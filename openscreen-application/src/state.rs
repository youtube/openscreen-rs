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

//! State machine types for the OpenScreen Application Protocol

/// Application protocol state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApplicationState {
    /// Not authenticated (waiting for network layer to authenticate)
    #[default]
    Idle,
    /// Authentication complete, no active presentation
    Authenticated,
    /// Active presentation running
    Presenting,
}

impl ApplicationState {
    /// Check if we're authenticated
    pub fn is_authenticated(&self) -> bool {
        matches!(
            self,
            ApplicationState::Authenticated | ApplicationState::Presenting
        )
    }

    /// Check if we have an active presentation
    pub fn is_presenting(&self) -> bool {
        matches!(self, ApplicationState::Presenting)
    }
}
