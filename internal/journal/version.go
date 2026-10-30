// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"fmt"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
)

type storageScope struct {
	SchemaVersion  int
	DeploymentID   string
	DeviceID       string
	ProfileID      string
	ProfileVersion int
	ProfileDigest  string
}

func (s storageScope) validate() error {
	if !device.ValidDeviceID(s.DeviceID) || !device.ValidDeviceID(s.DeploymentID) || s.SchemaVersion != profileSchemaVersion {
		return fmt.Errorf("invalid version-two journal scope")
	}
	if _, err := credentialprofile.Resolve(s.ProfileID, s.ProfileVersion, s.ProfileDigest); err != nil {
		return fmt.Errorf("unsupported journal credential profile: %w", device.ErrUnsupported)
	}
	return nil
}

func (s storageScope) initial() device.State {
	return device.State{SchemaVersion: s.SchemaVersion, DeploymentID: s.DeploymentID, DeviceID: s.DeviceID, ProfileID: s.ProfileID, ProfileVersion: s.ProfileVersion, ProfileDigest: s.ProfileDigest, Revision: 1, Fence: 1}
}

func (s storageScope) matches(state device.State) bool {
	return state.SchemaVersion == s.SchemaVersion && state.DeviceID == s.DeviceID && state.DeploymentID == s.DeploymentID && state.ProfileID == s.ProfileID && state.ProfileVersion == s.ProfileVersion && state.ProfileDigest == s.ProfileDigest
}

func (s storageScope) matchesBinding(b device.Binding) bool {
	return b.DeviceID == s.DeviceID && b.DeploymentID == s.DeploymentID && b.ProfileID == s.ProfileID && b.ProfileVersion == s.ProfileVersion && b.ProfileDigest == s.ProfileDigest
}
