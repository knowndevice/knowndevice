// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math"
	"reflect"
	"time"

	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
	"github.com/knowndevice/knowndevice/sdk/device"
)

func publicBinding(k device.Credential) (device.CredentialBinding, error) {
	b := k.Handle.Binding
	p, err := credentialprofile.Resolve(b.ProfileID, b.ProfileVersion, b.ProfileDigest)
	if err != nil || k.Recovery || k.Handle.Validate() != nil || len(k.TLS.Certificate) == 0 {
		return device.CredentialBinding{}, device.ErrDenied
	}
	csr, err := p.ValidateCSR(k.CSR, b.DeviceID, b.Generation)
	if err != nil {
		return device.CredentialBinding{}, device.ErrDenied
	}
	leaf, err := x509.ParseCertificate(k.TLS.Certificate[0])
	if err != nil || p.ValidateLeaf(leaf, b.DeviceID, b.Generation) != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) || device.Hash(leaf.RawSubjectPublicKeyInfo) != k.Handle.PublicKeyDigest {
		return device.CredentialBinding{}, device.ErrDenied
	}
	signer, ok := k.TLS.PrivateKey.(crypto.Signer)
	if !ok || nilValue(signer) {
		return device.CredentialBinding{}, device.ErrDenied
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(spki, leaf.RawSubjectPublicKeyInfo) {
		return device.CredentialBinding{}, device.ErrDenied
	}
	return device.CredentialBinding{DeploymentID: b.DeploymentID, DeviceID: b.DeviceID, OperationID: b.OperationID, PlanDigest: b.PlanDigest, ConfigDigest: b.ConfigDigest, SnapshotDigest: b.SnapshotDigest, ProfileID: b.ProfileID, ProfileVersion: b.ProfileVersion, ProfileDigest: b.ProfileDigest, Generation: b.Generation, PublicKeyDigest: k.Handle.PublicKeyDigest, CertificateFingerprint: device.Hash(leaf.Raw), CSRDigest: device.Hash(csr.Raw)}, nil
}

func exactHex(s string, n int) bool {
	decoded, err := hex.DecodeString(s)
	return err == nil && len(decoded) == n && hex.EncodeToString(decoded) == s
}

func has(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// The transport authenticates Evidence.Source. Checking its content alone never
// authenticates a service; these assertions inspect the adapter's typed result.
func evidence(s *device.PublicSnapshot, p device.Plan, e device.Evidence, subject device.CredentialBinding, role, sourceRole, action, status string, latest time.Time) bool {
	source, err := s.Role(sourceRole)
	return err == nil && e.APIVersion == device.V2 && e.Plan == p && e.Subject == subject && e.Role == role && e.Action == action && e.Status == status && e.Revision > 0 && exactHex(e.RequestID, 16) && e.Reference != "" && has(source.LeafPins, e.Source) && !e.ObservedAt.IsZero() && !e.ObservedAt.After(latest) && latest.Sub(e.ObservedAt) <= 5*time.Second && latest.Before(e.Deadline) && !e.Deadline.After(p.ExpiresAt)
}

func challenge(s *device.PublicSnapshot, p device.Plan, probe device.Probe, generation uint64, observed, latest time.Time) bool {
	role, err := s.Role("transport")
	return err == nil && probe.OperationID == p.OperationID && probe.DeviceID == p.DeviceID && probe.Generation == generation && probe.Endpoint == role.Endpoint && exactHex(probe.Nonce, 16) && observed.Before(probe.Deadline) && probe.Deadline.Sub(observed) <= time.Duration(s.Limits.ChallengeSeconds)*time.Second && latest.Before(probe.Deadline) && !probe.Deadline.After(p.ExpiresAt)
}

func assessedInterval(ctx context.Context, h *Harness) (time.Time, time.Time, error) {
	a, err := h.Adapters.Clock.Assess(ctx, time.Time{})
	if err != nil || a.Source != h.Snapshot.ClockTrust || a.MaximumAge > time.Duration(h.Snapshot.Limits.MaximumAssessmentAgeSeconds)*time.Second || math.IsNaN(a.DriftPPM) || math.IsInf(a.DriftPPM, 0) || a.DriftPPM > float64(h.Snapshot.Limits.DriftPPM) {
		return time.Time{}, time.Time{}, device.ErrDenied
	}
	early, late, err := a.Interval(time.Now(), time.Time{})
	if err != nil || late.Sub(early) > 2*time.Duration(h.Snapshot.Limits.MaximumUncertaintyMillis)*time.Millisecond || !late.Before(h.Plan.ExpiresAt) {
		return time.Time{}, time.Time{}, device.ErrDenied
	}
	return early, late, nil
}

func validChainAt(h *Harness, k device.Credential, chain []byte, activation bool, early, late time.Time) bool {
	v, err := h.Snapshot.Validation(early, late, activation, false)
	if err != nil {
		return false
	}
	return h.Snapshot.Profile.ValidateChain(chain, k.CSR, k.Handle.PublicKeyDigest, k.Handle.Binding.DeviceID, k.Handle.Binding.Generation, v) == nil
}

func chainBytes(k device.Credential) []byte {
	var out []byte
	for _, der := range k.TLS.Certificate {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

func validActivation(ctx context.Context, h *Harness, a device.Activation) bool {
	s, p := h.Snapshot, h.Plan
	b, err := publicBinding(h.Target)
	early, late, clockErr := assessedInterval(ctx, h)
	if err != nil || clockErr != nil || a.Evidence == nil || !validChainAt(h, h.Target, chainBytes(h.Target), true, early, late) {
		return false
	}
	e := a.Evidence
	return a.OperationID == p.OperationID && a.PlanDigest == p.Digest && a.DeviceID == p.DeviceID && a.ApplicationID == s.Composition.ApplicationID && a.Generation == p.TargetGeneration && a.CertificateFingerprint == b.CertificateFingerprint && a.SessionID != "" && a.SessionID == e.SessionID && a.Probe == e.Challenge && e.Phase == "activated" && e.ApplicationID == a.ApplicationID && e.Active == b && e.InstanceID != "" && e.ConnectionID != "" && e.ActivationRevision != 0 && e.ActivationRevision == e.Evidence.Revision && len(e.AcceptedScope) == 1 && e.AcceptedScope[0] == "fresh-challenge" && e.Evidence.Deadline.Equal(e.Challenge.Deadline) && evidence(s, p, e.Evidence, b, "application", "application", "observe", "completed", late) && challenge(s, p, e.Challenge, p.TargetGeneration, e.Evidence.ObservedAt, late)
}

func validRetirement(ctx context.Context, h *Harness, r device.Retirement) bool {
	s, p := h.Snapshot, h.Plan
	old, e1 := publicBinding(h.Previous)
	target, e2 := publicBinding(h.Target)
	_, late, clockErr := assessedInterval(ctx, h)
	if e1 != nil || e2 != nil || clockErr != nil || r.Evidence == nil {
		return false
	}
	w := r.Evidence
	a := w.Current
	activation := device.Activation{OperationID: p.OperationID, PlanDigest: p.Digest, DeviceID: p.DeviceID, ApplicationID: a.ApplicationID, Generation: a.Active.Generation, CertificateFingerprint: a.Active.CertificateFingerprint, SessionID: a.SessionID, Probe: a.Challenge, Evidence: &a}
	return r.OperationID == p.OperationID && r.PlanDigest == p.Digest && r.Generation == p.ExpectedGeneration && r.PolicyDurable && r.SessionsTerminated && r.ApplicationAccessDenied && r.TLSObservation == "accepted" && w.Previous == old && w.Target == target && w.Scope == s.Composition.WithdrawalScope && w.PolicyRevision != 0 && w.PolicyRevision <= w.Evidence.Revision && w.SessionsTerminated && w.Evidence.Deadline.Equal(p.ExpiresAt) && evidence(s, p, w.Evidence, old, "withdrawal", "control", "withdraw", "ok", late) && w.Denial.Kind == "denied" && w.Denial.ConnectionID != "" && evidence(s, p, w.Denial.Evidence, old, "transport", "transport", "challenge", "denied", late) && w.Denial.Evidence.Deadline.Equal(w.Denial.Challenge.Deadline) && challenge(s, p, w.Denial.Challenge, p.ExpectedGeneration, w.Denial.Evidence.ObservedAt, late) && !a.Evidence.ObservedAt.Before(w.Denial.Evidence.ObservedAt) && a.Challenge.Nonce != w.Denial.Challenge.Nonce && validActivation(ctx, h, activation)
}

func refusal(err error) bool {
	return errors.Is(err, device.ErrDenied) || errors.Is(err, device.ErrConflict) || errors.Is(err, device.ErrUnsupported) || errors.Is(err, device.ErrUnknown)
}

func nilValue(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
