// SPDX-License-Identifier: Apache-2.0

package process

import (
	"time"

	"github.com/knowndevice/knowndevice/sdk/device"
)

// ValidateActivation applies the existing complete process success contract to
// an authenticated role result, including native HTTP results. It performs no
// effects or authentication; the caller must authenticate the response channel.
// The controller still owns its conservative clock assessment and activation CAS.
func ValidateActivation(snapshot *device.PublicSnapshot, plan device.Plan, target device.Credential, activation device.Activation) error {
	if snapshot == nil || snapshot.Validate() != nil || snapshot.ValidatePlan(plan) != nil || plan.Validate(time.Now().UTC()) != nil || validateTarget(snapshot, plan, target) != nil {
		return device.ErrUnknown
	}
	return validateActivation(snapshot, plan, target, activation)
}

// ValidateRetirement checks the complete bound denial/session/current-application
// proof using the unchanged process validator. A receipt cannot authenticate
// itself; unknown proof never authorizes revocation or previous-key destruction.
func ValidateRetirement(snapshot *device.PublicSnapshot, plan device.Plan, previous, target device.Credential, retirement device.Retirement) error {
	if snapshot == nil || snapshot.Validate() != nil || snapshot.ValidatePlan(plan) != nil || plan.Validate(time.Now().UTC()) != nil || validatePair(snapshot, plan, previous, target) != nil {
		return device.ErrUnknown
	}
	return validateRetirement(snapshot, plan, previous, target, retirement)
}
