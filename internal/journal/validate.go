// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"knowndevice.local/knowndevice/internal/credentialprofile"
	"knowndevice.local/knowndevice/internal/device"
)

var phases = map[device.Phase]int{
	device.Planned: 0, device.KeyReady: 1, device.IssueIntent: 2, device.Issued: 3,
	device.RegisterIntent: 4, device.Registered: 5, device.Verified: 6,
	device.ActivateIntent: 7, device.Activated: 8, device.Committed: 9,
	device.BrokerRetireIntent: 10, device.BrokerRetired: 11, device.CARevokeIntent: 12,
	device.CARevoked: 13, device.DestroyIntent: 14, device.Retired: 15,
}

func validateState(s device.State, deviceID string) error {
	return validateScopedState(s, storageScope{SchemaVersion: schemaVersion, DeviceID: deviceID})
}

func validateScopedState(s device.State, scope storageScope) error {
	deviceID := scope.DeviceID
	if !scope.matches(s) || s.Revision == 0 || s.Fence == 0 || s.Revision > maxCounter || s.Fence > maxCounter || s.Counter > maxCounter {
		return fmt.Errorf("invalid journal version, identity or counters")
	}
	if s.Active != nil {
		if err := validateHandle(*s.Active, deviceID, s.Counter); err != nil {
			return err
		}
		if !scope.matchesBinding(s.Active.Binding) {
			return fmt.Errorf("journal active handle differs from immutable profile scope")
		}
	}
	if s.Operation == nil {
		return nil
	}
	o := s.Operation
	var snapshot *device.PublicSnapshot
	if scope.SchemaVersion == profileSchemaVersion {
		if err := scope.validate(); err != nil {
			return err
		}
		if o.Plan.APIVersion != device.V2 || !scope.matchesBinding(o.Plan.Binding()) || len(o.Snapshot) == 0 || device.Hash(o.Snapshot) != o.Plan.SnapshotDigest {
			return fmt.Errorf("journal operation has a different profile or public snapshot")
		}
		var err error
		snapshot, err = device.DecodeSnapshot(o.Snapshot)
		if err != nil {
			return err
		}
		if err := snapshot.ValidatePlan(o.Plan); err != nil {
			return err
		}
	} else if o.Plan.APIVersion != "knowndevice/v1alpha1" || len(o.Snapshot) != 0 {
		return fmt.Errorf("legacy journal refuses profile-aware operations: %w", device.ErrUnsupported)
	}
	if snapshot == nil && (len(o.PreviousCSR) != 0 || len(o.PreviousCertificate) != 0) {
		return fmt.Errorf("legacy journal refuses profile-aware previous artifacts: %w", device.ErrUnsupported)
	}
	if snapshot == nil && ((o.Activation != nil && o.Activation.Evidence != nil) || (o.Retirement != nil && o.Retirement.Evidence != nil)) {
		return fmt.Errorf("legacy journal refuses profile-aware role evidence: %w", device.ErrUnsupported)
	}
	// Expiry controls new effects in the engine. Persisted intent must remain
	// readable after its deadline so an uncertain effect can be reconciled.
	if err := o.Plan.Validate(o.Plan.ExpiresAt.Add(-time.Second)); err != nil {
		return fmt.Errorf("invalid persisted plan: %w", err)
	}
	if o.Plan.DeviceID != deviceID || o.Plan.TargetGeneration > s.Counter {
		return fmt.Errorf("journal operation has a different device or unreserved generation")
	}
	if _, ok := phases[o.Phase]; !ok {
		return fmt.Errorf("unknown journal checkpoint")
	}
	if len(o.Reason) > 512 || strings.Contains(o.Reason, "PRIVATE KEY") || len(o.Outcome) > 32 || strings.Contains(o.Outcome, "PRIVATE KEY") {
		return fmt.Errorf("journal reason exceeds public metadata limits")
	}
	if o.Target != nil {
		if err := validateHandle(*o.Target, deviceID, s.Counter); err != nil {
			return err
		}
		if !scope.matchesBinding(o.Target.Binding) {
			return fmt.Errorf("journal target differs from immutable profile scope")
		}
		if o.Target.Binding != o.Plan.Binding() {
			return fmt.Errorf("journal target does not match its plan")
		}
	}
	if o.Previous != nil {
		if err := validateHandle(*o.Previous, deviceID, s.Counter); err != nil {
			return err
		}
		if !scope.matchesBinding(o.Previous.Binding) {
			return fmt.Errorf("journal previous handle differs from immutable profile scope")
		}
		if o.Previous.Binding.Generation != o.Plan.ExpectedGeneration {
			return fmt.Errorf("journal previous handle does not match its precondition")
		}
		if snapshot != nil {
			if snapshot.ValidateBinding(o.Previous.Binding) != nil || len(o.PreviousCSR) == 0 || len(o.PreviousCertificate) == 0 {
				return fmt.Errorf("journal previous handle requires its original public artifacts/snapshot")
			}
			certs, err := credentialprofile.ParseChain(o.PreviousCertificate)
			if err != nil {
				return err
			}
			at := certs[0].NotBefore.Add(certs[0].NotAfter.Sub(certs[0].NotBefore) / 2)
			validation, err := snapshot.Validation(at, at, false, true)
			if err != nil {
				return err
			}
			if err := snapshot.Profile.ValidateChain(o.PreviousCertificate, o.PreviousCSR, o.Previous.PublicKeyDigest, deviceID, o.Previous.Binding.Generation, validation); err != nil {
				return err
			}
			if o.Target != nil && o.Target.PublicKeyDigest == o.Previous.PublicKeyDigest {
				return fmt.Errorf("journal generations cannot reuse a public key")
			}
		}
	} else if snapshot != nil && (o.Plan.ExpectedGeneration != 0 || len(o.PreviousCSR) != 0 || len(o.PreviousCertificate) != 0) {
		return fmt.Errorf("journal operation lacks its expected previous public binding")
	}
	if len(o.CSR) != 0 {
		if o.Target == nil {
			return fmt.Errorf("journal CSR has no target handle")
		}
		if snapshot != nil {
			csr, err := snapshot.Profile.ValidateCSR(o.CSR, deviceID, o.Plan.TargetGeneration)
			if err != nil || device.Hash(csr.RawSubjectPublicKeyInfo) != o.Target.PublicKeyDigest {
				return fmt.Errorf("journal original CSR differs from profile/target binding")
			}
		} else {
			subject := device.Subject(deviceID, o.Plan.TargetGeneration)
			csr, err := credentialprofile.ValidateReferenceCSR(o.CSR, subject)
			if err != nil || device.Hash(csr.RawSubjectPublicKeyInfo) != o.Target.PublicKeyDigest {
				return fmt.Errorf("journal CSR binding does not match its target")
			}
		}
	}
	if len(o.Certificate) != 0 {
		if o.Target == nil {
			return fmt.Errorf("journal certificate has no target handle")
		}
		if snapshot != nil {
			certs, err := credentialprofile.ParseChain(o.Certificate)
			if err != nil || len(o.CSR) == 0 {
				return fmt.Errorf("journal certificate requires bounded chain and original CSR")
			}
			at := certs[0].NotBefore.Add(certs[0].NotAfter.Sub(certs[0].NotBefore) / 2)
			validation, err := snapshot.Validation(at, at, false, true)
			if err != nil {
				return err
			}
			if err := snapshot.Profile.ValidateChain(o.Certificate, o.CSR, o.Target.PublicKeyDigest, deviceID, o.Plan.TargetGeneration, validation); err != nil {
				return err
			}
		} else {
			certs, err := credentialprofile.ParseChain(o.Certificate)
			if err != nil {
				return err
			}
			leaf := certs[0]
			if err := credentialprofile.ValidateReferenceIdentity(leaf, device.Subject(deviceID, o.Plan.TargetGeneration)); err != nil {
				return err
			}
			if device.Hash(leaf.RawSubjectPublicKeyInfo) != o.Target.PublicKeyDigest {
				return fmt.Errorf("journal certificate binding does not match its target")
			}
			if len(o.CSR) != 0 {
				csr, err := credentialprofile.ValidateReferenceCSR(o.CSR, device.Subject(deviceID, o.Plan.TargetGeneration))
				if err != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
					return fmt.Errorf("journal certificate SPKI differs from original CSR")
				}
			}
		}
	}
	if snapshot != nil && phases[o.Phase] >= phases[device.KeyReady] && (o.Target == nil || len(o.CSR) == 0) {
		return fmt.Errorf("journal checkpoint requires immutable target and original CSR")
	}
	if snapshot != nil && phases[o.Phase] >= phases[device.Issued] && len(o.Certificate) == 0 {
		return fmt.Errorf("journal checkpoint requires verified public certificate")
	}
	if snapshot != nil {
		return validateOperationEvidence(o, snapshot)
	}
	return nil
}

func validateHandle(h device.Handle, deviceID string, counter uint64) error {
	if err := h.Validate(); err != nil {
		return err
	}
	if h.Binding.DeviceID != deviceID || h.Binding.Generation > counter {
		return fmt.Errorf("journal handle has a different device or unreserved generation")
	}
	return nil
}

func validateUpdate(old, next device.State) error {
	if next.Counter < old.Counter || next.ClockFloor.Before(old.ClockFloor) {
		return fmt.Errorf("journal counter or clock floor would regress: %w", device.ErrConflict)
	}
	if old.Active != nil {
		if next.Active == nil || next.Active.Binding.Generation < old.Active.Binding.Generation {
			return fmt.Errorf("journal active generation would regress: %w", device.ErrConflict)
		}
		if next.Active.Binding.Generation == old.Active.Binding.Generation && *next.Active != *old.Active {
			return fmt.Errorf("journal active binding is immutable: %w", device.ErrConflict)
		}
	}
	if old.Operation == nil || (next.Operation != nil && next.Operation.Plan.OperationID != old.Operation.Plan.OperationID) {
		if old.Operation != nil && old.Operation.Phase != device.Retired {
			return fmt.Errorf("unfinished operation requires reconciliation: %w", device.ErrConflict)
		}
		if next.Operation != nil && (next.Operation.Plan.TargetGeneration <= old.Counter || next.Operation.Plan.TargetGeneration != next.Counter) {
			return fmt.Errorf("new operation must reserve a fresh generation: %w", device.ErrConflict)
		}
		if next.Operation == nil && next.Counter != old.Counter {
			return fmt.Errorf("generation reservation requires an operation: %w", device.ErrConflict)
		}
		if next.Operation != nil {
			expected := uint64(0)
			if old.Active != nil {
				expected = old.Active.Binding.Generation
				if next.Operation.Plan.TargetSlot == old.Active.Binding.Slot {
					return fmt.Errorf("operation cannot replace the active slot: %w", device.ErrConflict)
				}
			}
			if next.Operation.Phase != device.Planned || next.Operation.Plan.ExpectedGeneration != expected {
				return fmt.Errorf("operation must begin planned against the active generation: %w", device.ErrConflict)
			}
			if next.Operation.Previous != nil && (old.Active == nil || *next.Operation.Previous != *old.Active) {
				return fmt.Errorf("operation previous handle must match the active generation: %w", device.ErrConflict)
			}
		}
	} else {
		if next.Operation == nil {
			return fmt.Errorf("journal operation cannot disappear: %w", device.ErrConflict)
		}
		before, after := old.Operation, next.Operation
		if before.Plan.Digest != after.Plan.Digest || phases[after.Phase] < phases[before.Phase] || next.Counter != old.Counter {
			return fmt.Errorf("journal operation plan or checkpoint would change: %w", device.ErrConflict)
		}
		if (before.Target != nil && (after.Target == nil || *before.Target != *after.Target)) || (before.Previous != nil && (after.Previous == nil || *before.Previous != *after.Previous)) || (len(before.CSR) > 0 && !bytes.Equal(before.CSR, after.CSR)) || (len(before.Certificate) > 0 && !bytes.Equal(before.Certificate, after.Certificate)) || (len(before.Snapshot) > 0 && !bytes.Equal(before.Snapshot, after.Snapshot)) || (len(before.PreviousCSR) > 0 && !bytes.Equal(before.PreviousCSR, after.PreviousCSR)) || (len(before.PreviousCertificate) > 0 && !bytes.Equal(before.PreviousCertificate, after.PreviousCertificate)) {
			return fmt.Errorf("journal operation material is immutable: %w", device.ErrConflict)
		}
		if old.SchemaVersion == profileSchemaVersion {
			if before.Activation != nil && (after.Activation == nil || before.Activation.Evidence == nil || after.Activation.Evidence == nil || before.Activation.Evidence.ActivationRevision != after.Activation.Evidence.ActivationRevision) {
				return fmt.Errorf("journal durable activation selection cannot disappear or change: %w", device.ErrConflict)
			}
			if before.Retirement != nil && (after.Retirement == nil || before.Retirement.Evidence == nil || after.Retirement.Evidence == nil || before.Retirement.Evidence.PolicyRevision != after.Retirement.Evidence.PolicyRevision) {
				return fmt.Errorf("journal effective withdrawal policy cannot disappear or change: %w", device.ErrConflict)
			}
		}
	}
	if next.Active != nil && (old.Active == nil || *next.Active != *old.Active) {
		if next.Operation == nil || next.Operation.Target == nil || *next.Active != *next.Operation.Target || phases[next.Operation.Phase] < phases[device.Committed] {
			return fmt.Errorf("journal active generation requires target commit: %w", device.ErrConflict)
		}
	}
	return nil
}
