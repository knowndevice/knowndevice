// SPDX-License-Identifier: Apache-2.0

package device

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
	"regexp"
	"time"
)

var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
var operationID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func ValidDeviceID(id string) bool { return identifier.MatchString(id) }

func (b Binding) Validate() error {
	if !ValidDeviceID(b.DeviceID) || !operationID.MatchString(b.OperationID) || b.Generation == 0 || (b.Slot != "A" && b.Slot != "B") {
		return fmt.Errorf("invalid slot binding")
	}
	if b.ProfileID != "" {
		if !ValidDeviceID(b.DeploymentID) || !digest.MatchString(b.ConfigDigest) || !digest.MatchString(b.PlanDigest) || !digest.MatchString(b.SnapshotDigest) {
			return fmt.Errorf("invalid version-two slot binding")
		}
		if _, e := credentialprofile.Resolve(b.ProfileID, b.ProfileVersion, b.ProfileDigest); e != nil {
			return e
		}
	} else if b.DeploymentID != "" || b.ProfileVersion != 0 || b.ProfileDigest != "" || b.ConfigDigest != "" || b.PlanDigest != "" || b.SnapshotDigest != "" {
		return fmt.Errorf("partial profile binding")
	}
	return nil
}

func (h Handle) Validate() error {
	if err := h.Binding.Validate(); err != nil {
		return err
	}
	if !digest.MatchString(h.PublicKeyDigest) {
		return fmt.Errorf("invalid public key digest")
	}
	return nil
}

func Subject(deviceID string, generation uint64) string {
	return fmt.Sprintf("g%d.%s.known-device.invalid", generation, deviceID)
}

func RecoverySubject(deviceID string) string { return "recovery." + deviceID + ".known-device.invalid" }

func RandomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (p Plan) CalculateDigest() (string, error) {
	p.Digest = ""
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return Hash(b), nil
}

func (p Plan) Validate(now time.Time) error {
	if (p.APIVersion != "knowndevice/v1alpha1" && p.APIVersion != V2) || !operationID.MatchString(p.OperationID) || !ValidDeviceID(p.DeviceID) || !digest.MatchString(p.ConfigDigest) {
		return fmt.Errorf("invalid plan identity or configuration binding")
	}
	if p.APIVersion == V2 {
		if p.DigestEncodingVersion != 2 || p.Binding().Validate() != nil || !digest.MatchString(p.CompositionDigest) || !digest.MatchString(p.ControlTrustDigest) || !digest.MatchString(p.ApplicationTrustDigest) || !digest.MatchString(p.IssuanceTrustDigest) || !digest.MatchString(p.RecoveryTrustDigest) || !digest.MatchString(p.TransportTrustDigest) {
			return fmt.Errorf("invalid v1alpha2 profile/trust binding")
		}
	} else if p.DigestEncodingVersion != 0 || p.DeploymentID != "" || p.ProfileID != "" || p.ProfileVersion != 0 || p.ProfileDigest != "" || p.CompositionDigest != "" || p.SnapshotDigest != "" || p.ControlTrustDigest != "" || p.ApplicationTrustDigest != "" || p.IssuanceTrustDigest != "" || p.RecoveryTrustDigest != "" || p.TransportTrustDigest != "" {
		return fmt.Errorf("v1alpha1 cannot carry v1alpha2 bindings")
	}
	if p.TargetGeneration == 0 || p.TargetGeneration > 1<<53-1 || p.ExpectedGeneration >= p.TargetGeneration || (p.TargetSlot != "A" && p.TargetSlot != "B") {
		return fmt.Errorf("invalid plan generation or slot")
	}
	if (p.Mode != "enroll" && p.Mode != "rotate" && p.Mode != "recover") || (p.Mode == "enroll" && p.ExpectedGeneration != 0) || (p.Mode != "enroll" && p.ExpectedGeneration == 0) {
		return fmt.Errorf("invalid plan mode")
	}
	if !p.ExpiresAt.After(now) || p.ExpiresAt.Sub(now) > 10*time.Minute {
		return fmt.Errorf("plan deadline expired or exceeds ten minutes")
	}
	want, err := p.CalculateDigest()
	if err != nil {
		return err
	}
	if p.Digest != want {
		return fmt.Errorf("plan digest mismatch")
	}
	return nil
}

func (p Plan) Binding() Binding {
	return Binding{DeviceID: p.DeviceID, OperationID: p.OperationID, Generation: p.TargetGeneration, Slot: p.TargetSlot, DeploymentID: p.DeploymentID, ProfileID: p.ProfileID, ProfileVersion: p.ProfileVersion, ProfileDigest: p.ProfileDigest, ConfigDigest: func() string {
		if p.APIVersion == V2 {
			return p.ConfigDigest
		}
		return ""
	}(), PlanDigest: func() string {
		if p.APIVersion == V2 {
			return p.Digest
		}
		return ""
	}(), SnapshotDigest: p.SnapshotDigest}
}

func MatchProbe(request, response Probe, now time.Time) error {
	request.Deadline = request.Deadline.UTC()
	response.Deadline = response.Deadline.UTC()
	if request != response || len(request.Nonce) != 32 || !operationID.MatchString(request.Nonce) || !request.Deadline.After(now) || request.Deadline.Sub(now) > time.Minute {
		return fmt.Errorf("stale or mismatched application probe: %w", ErrDenied)
	}
	return nil
}
