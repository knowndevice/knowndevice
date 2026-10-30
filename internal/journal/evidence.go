// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"encoding/hex"
	"fmt"
	"time"

	"knowndevice.local/knowndevice/internal/credentialprofile"
	"knowndevice.local/knowndevice/internal/device"
)

func exactHex(value string, bytes int) bool {
	if len(value) != bytes*2 {
		return false
	}
	data, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(data) == value
}

func sourceAllowed(s *device.PublicSnapshot, role, source string) bool {
	r, err := s.Role(role)
	if err != nil {
		return false
	}
	for _, pin := range append(r.LeafPins, r.SPKIPins...) {
		if pin == source {
			return true
		}
	}
	return false
}

func validateEnvelope(e device.Evidence, plan device.Plan, role, peer string, subject device.CredentialBinding, snapshot *device.PublicSnapshot) error {
	if e.APIVersion != device.V2 || e.Plan != plan || e.Role != role || e.Subject != subject || !exactHex(e.RequestID, 16) || e.Revision == 0 || e.Revision > maxCounter || e.Reference == "" || len(e.Reference) > 128 || !sourceAllowed(snapshot, peer, e.Source) || e.ObservedAt.IsZero() || !e.ObservedAt.Before(e.Deadline) || e.Deadline.After(plan.ExpiresAt) {
		return fmt.Errorf("journal role evidence differs from authenticated immutable binding")
	}
	return nil
}

func matchesCredentialHandle(b device.CredentialBinding, h device.Handle) bool {
	i := h.Binding
	return b.DeploymentID == i.DeploymentID && b.DeviceID == i.DeviceID && b.OperationID == i.OperationID && b.PlanDigest == i.PlanDigest && b.ConfigDigest == i.ConfigDigest && b.SnapshotDigest == i.SnapshotDigest && b.ProfileID == i.ProfileID && b.ProfileVersion == i.ProfileVersion && b.ProfileDigest == i.ProfileDigest && b.Generation == i.Generation && b.PublicKeyDigest == h.PublicKeyDigest && exactHex(b.CSRDigest, 32) && exactHex(b.CertificateFingerprint, 32)
}

func validateApplicationEvidence(a device.ApplicationEvidence, plan device.Plan, target device.CredentialBinding, snapshot *device.PublicSnapshot) error {
	if err := validateEnvelope(a.Evidence, plan, "application", "application", target, snapshot); err != nil {
		return err
	}
	endpoint, err := snapshot.Role("transport")
	if err != nil {
		return err
	}
	probe := a.Challenge
	if a.Active != target || a.Phase != "activated" || a.ActivationRevision == 0 || a.ActivationRevision != a.Evidence.Revision || a.ApplicationID != snapshot.Composition.ApplicationID || a.Evidence.Action != "observe" || a.Evidence.Status != "completed" || a.InstanceID == "" || len(a.InstanceID) > 128 || a.ConnectionID == "" || len(a.ConnectionID) > 128 || a.SessionID == "" || len(a.SessionID) > 128 || len(a.AcceptedScope) != 1 || a.AcceptedScope[0] != "fresh-challenge" || probe.OperationID != plan.OperationID || probe.DeviceID != plan.DeviceID || probe.Generation != plan.TargetGeneration || probe.Endpoint != endpoint.Endpoint || !exactHex(probe.Nonce, 16) || probe.Deadline != a.Evidence.Deadline || !a.Evidence.ObservedAt.Before(probe.Deadline) || probe.Deadline.Sub(a.Evidence.ObservedAt) > time.Duration(snapshot.Limits.ChallengeSeconds)*time.Second {
		return fmt.Errorf("journal activation requires durable selection and a new bound observation")
	}
	return nil
}

func validateOperationEvidence(o *device.Operation, snapshot *device.PublicSnapshot) error {
	if o.Target == nil || len(o.Certificate) == 0 || len(o.CSR) == 0 {
		if o.Activation != nil || o.Retirement != nil {
			return fmt.Errorf("journal evidence requires an issued target")
		}
		return nil
	}
	csr, err := snapshot.Profile.ValidateCSR(o.CSR, o.Plan.DeviceID, o.Plan.TargetGeneration)
	if err != nil {
		return err
	}
	certs, err := credentialprofile.ParseChain(o.Certificate)
	if err != nil {
		return err
	}
	target := device.CredentialBinding{DeploymentID: o.Plan.DeploymentID, DeviceID: o.Plan.DeviceID, OperationID: o.Plan.OperationID, PlanDigest: o.Plan.Digest, ConfigDigest: o.Plan.ConfigDigest, SnapshotDigest: o.Plan.SnapshotDigest, ProfileID: o.Plan.ProfileID, ProfileVersion: o.Plan.ProfileVersion, ProfileDigest: o.Plan.ProfileDigest, Generation: o.Plan.TargetGeneration, PublicKeyDigest: o.Target.PublicKeyDigest, CertificateFingerprint: device.Hash(certs[0].Raw), CSRDigest: device.Hash(csr.Raw)}
	if o.Activation != nil {
		a := o.Activation
		if a.Evidence == nil || a.OperationID != o.Plan.OperationID || a.PlanDigest != o.Plan.Digest || a.DeviceID != o.Plan.DeviceID || a.Generation != o.Plan.TargetGeneration || a.ApplicationID != snapshot.Composition.ApplicationID || a.CertificateFingerprint != target.CertificateFingerprint || a.SessionID != a.Evidence.SessionID || a.Probe != a.Evidence.Challenge || (o.Probe != nil && a.Probe.Nonce == o.Probe.Nonce) {
			return fmt.Errorf("journal activation metadata differs from post-switch evidence")
		}
		if err := validateApplicationEvidence(*a.Evidence, o.Plan, target, snapshot); err != nil {
			return err
		}
	} else if phases[o.Phase] >= phases[device.Activated] {
		return fmt.Errorf("journal checkpoint requires durable application activation evidence")
	}
	if o.Retirement != nil {
		r := o.Retirement
		if r.Evidence == nil || o.Previous == nil || r.OperationID != o.Plan.OperationID || r.PlanDigest != o.Plan.Digest || r.Generation != o.Plan.ExpectedGeneration || !r.PolicyDurable || !r.SessionsTerminated || !r.ApplicationAccessDenied || (r.TLSObservation != "accepted" && r.TLSObservation != "denied") {
			return fmt.Errorf("journal retirement lacks effective withdrawal evidence")
		}
		w := r.Evidence
		previousCSR, err := snapshot.Profile.ValidateCSR(o.PreviousCSR, o.Plan.DeviceID, o.Previous.Binding.Generation)
		if err != nil {
			return err
		}
		previousChain, err := credentialprofile.ParseChain(o.PreviousCertificate)
		if err != nil {
			return err
		}
		previous := w.Previous
		if w.Target != target || !matchesCredentialHandle(previous, *o.Previous) || previous.CSRDigest != device.Hash(previousCSR.Raw) || previous.CertificateFingerprint != device.Hash(previousChain[0].Raw) || previous.Generation != o.Plan.ExpectedGeneration || previous.PublicKeyDigest == target.PublicKeyDigest || previous.CertificateFingerprint == target.CertificateFingerprint || w.PolicyRevision == 0 || w.Evidence.Revision < w.PolicyRevision || w.Scope != snapshot.Composition.WithdrawalScope || !w.SessionsTerminated || w.Denial.Kind != "denied" || w.Denial.ConnectionID == "" || len(w.Denial.ConnectionID) > 128 || w.Denial.Challenge.Generation != previous.Generation || w.Denial.Challenge.OperationID != o.Plan.OperationID || w.Denial.Challenge.DeviceID != o.Plan.DeviceID || w.Denial.Challenge.Deadline != w.Denial.Evidence.Deadline || !exactHex(w.Denial.Challenge.Nonce, 16) || w.Denial.Evidence.Action != "challenge" || w.Denial.Evidence.Status != "denied" || w.Evidence.Action != "withdraw" || (w.Evidence.Status != "ok" && w.Evidence.Status != "completed") || w.Current.Evidence.ObservedAt.Before(w.Denial.Evidence.ObservedAt) || w.Current.Challenge.Nonce == w.Denial.Challenge.Nonce {
			return fmt.Errorf("journal withdrawal conflates previous and target or lacks denial")
		}
		if err := validateEnvelope(w.Evidence, o.Plan, "withdrawal", "control", w.Previous, snapshot); err != nil {
			return err
		}
		if err := validateEnvelope(w.Denial.Evidence, o.Plan, "transport", "transport", w.Previous, snapshot); err != nil {
			return err
		}
		if err := validateApplicationEvidence(w.Current, o.Plan, target, snapshot); err != nil {
			return err
		}
	} else if o.Previous != nil && phases[o.Phase] >= phases[device.BrokerRetired] {
		return fmt.Errorf("journal checkpoint requires effective previous withdrawal evidence")
	}
	return nil
}
