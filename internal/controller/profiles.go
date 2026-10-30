// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
)

// CompletedHistory reports exact V2 history without authentication or new effects.
func CompletedHistory(s device.State, p device.Plan) (Receipt, error) {
	if p.APIVersion != device.V2 || s.Operation == nil || s.Operation.Plan != p || s.Operation.Phase != device.Retired {
		return Report(s), device.ErrConflict
	}
	snap, decodeErr := device.DecodeSnapshot(s.Operation.Snapshot)
	digest, digestErr := p.CalculateDigest()
	if s.SchemaVersion != 2 || p.DeviceID != s.DeviceID || p.DeploymentID != s.DeploymentID || p.ProfileID != s.ProfileID || p.ProfileVersion != s.ProfileVersion || p.ProfileDigest != s.ProfileDigest || decodeErr != nil || digestErr != nil || digest != p.Digest || snap.ValidatePlan(p) != nil {
		return Report(s), device.ErrConflict
	}
	return Report(s), nil
}

func policyFor(b device.Binding) (credentialprofile.Policy, error) {
	if b.ProfileID == "" {
		return credentialprofile.Find(credentialprofile.ReferenceID, 1)
	}
	return credentialprofile.Resolve(b.ProfileID, b.ProfileVersion, b.ProfileDigest)
}
func (e *Engine) snapshot() (*device.PublicSnapshot, error) {
	if e.Snapshot != nil {
		return e.Snapshot, nil
	}
	return e.Config.ResolveSnapshot()
}
func (e *Engine) interval(ctx context.Context, floor time.Time) (time.Time, time.Time, error) {
	if e.Config.APIVersion != device.V2 {
		now := e.now()
		if now.Before(floor) || e.Config.ClockTrust != "trusted-system-clock" {
			return time.Time{}, time.Time{}, device.ErrDenied
		}
		return now, now, nil
	}
	s, err := e.snapshot()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if e.Clock == nil {
		return time.Time{}, time.Time{}, device.ErrUnsupported
	}
	if e.assessment == nil || time.Since(e.assessment.AssessedAt) > e.assessment.MaximumAge {
		a, err := e.Clock.Assess(ctx, floor)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		e.assessment = &a
	}
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	early, late, err := e.assessment.Interval(now, floor)
	if err != nil {
		return early, late, err
	}
	if late.Sub(early) > time.Duration(2*s.Limits.MaximumUncertaintyMillis)*time.Millisecond || e.assessment.DriftPPM > float64(s.Limits.DriftPPM) || e.assessment.MaximumAge > time.Duration(s.Limits.MaximumAssessmentAgeSeconds)*time.Second {
		return early, late, device.ErrDenied
	}
	return early, late, nil
}
func (e *Engine) decision(ctx context.Context, p device.Plan, floor time.Time) (time.Time, time.Time, error) {
	early, late, err := e.interval(ctx, floor)
	if err != nil {
		return early, late, err
	}
	if !late.Before(p.ExpiresAt) {
		return early, late, device.ErrPlanExpired
	}
	if e.Config.APIVersion == device.V2 {
		snap, err := e.snapshot()
		if err != nil {
			return early, late, err
		}
		if err = snap.ValidatePlan(p); err != nil {
			return early, late, err
		}
		d, err := e.Config.Digest()
		if err != nil || d != p.ConfigDigest {
			return early, late, device.ErrConflict
		}
	}
	return early, late, nil
}
func (e *Engine) validateV2Credential(ctx context.Context, h device.Handle, signer crypto.Signer, chain []byte, historical, activation bool) (tls.Certificate, error) {
	snap, err := e.snapshot()
	if err != nil || snap.ValidateBinding(h.Binding) != nil {
		return tls.Certificate{}, device.ErrConflict
	}
	policy, err := policyFor(h.Binding)
	if err != nil {
		return tls.Certificate{}, err
	}
	certs, err := credentialprofile.ParseChain(chain)
	if err != nil {
		return tls.Certificate{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(spki, certs[0].RawSubjectPublicKeyInfo) || device.Hash(spki) != h.PublicKeyDigest {
		return tls.Certificate{}, device.ErrDenied
	}
	early, late, err := e.interval(ctx, time.Time{})
	if err != nil {
		return tls.Certificate{}, err
	}
	if historical {
		early = certs[0].NotBefore
		late = early
	}
	v, err := snap.Validation(early, late, activation, historical)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err = policy.ValidatePublicChain(certs, h.Binding.DeviceID, h.Binding.Generation, v); err != nil {
		return tls.Certificate{}, device.ErrDenied
	}
	var ders [][]byte
	for _, cert := range certs {
		ders = append(ders, cert.Raw)
	}
	return tls.Certificate{Certificate: ders, PrivateKey: signer, Leaf: certs[0]}, nil
}
func (e *Engine) prepareSnapshot(s *device.State, p device.Plan) error {
	if p.APIVersion != device.V2 {
		if s.SchemaVersion > 1 {
			return device.ErrUnsupported
		}
		return nil
	}
	if s.SchemaVersion != 2 || s.DeploymentID != p.DeploymentID || s.ProfileID != p.ProfileID || s.ProfileVersion != p.ProfileVersion || s.ProfileDigest != p.ProfileDigest {
		return device.ErrConflict
	}
	snap, err := e.Config.ResolveSnapshot()
	if err != nil {
		return err
	}
	if err = snap.ValidatePlan(p); err != nil {
		return err
	}
	if s.Operation != nil && s.Operation.Plan.OperationID == p.OperationID {
		original, err := device.DecodeSnapshot(s.Operation.Snapshot)
		if err != nil || original.Digest() != snap.Digest() {
			return device.ErrConflict
		}
		e.Snapshot = original
	} else {
		e.Snapshot = snap
	}
	return nil
}

type publicStore interface {
	StoreSnapshot(context.Context, device.Handle, []byte) error
	StoreCSR(context.Context, device.Handle, []byte) error
	CSR(context.Context, device.Handle) ([]byte, error)
	ActivateV2(context.Context, device.Handle, time.Time, time.Time) error
}

func (e *Engine) v2Credential(ctx context.Context, h device.Handle, signer crypto.Signer, chain []byte, historical bool) (device.Credential, error) {
	cert, err := e.validateV2Credential(ctx, h, signer, chain, historical, false)
	if err != nil {
		return device.Credential{}, err
	}
	store, ok := e.Keys.(publicStore)
	if !ok {
		return device.Credential{}, device.ErrUnsupported
	}
	csr, err := store.CSR(ctx, h)
	if err != nil {
		return device.Credential{}, err
	}
	policy, err := policyFor(h.Binding)
	if err != nil {
		return device.Credential{}, err
	}
	request, err := policy.ValidateCSR(csr, h.Binding.DeviceID, h.Binding.Generation)
	if err != nil || !bytes.Equal(request.RawSubjectPublicKeyInfo, cert.Leaf.RawSubjectPublicKeyInfo) || device.Hash(request.RawSubjectPublicKeyInfo) != h.PublicKeyDigest {
		return device.Credential{}, device.ErrDenied
	}
	return device.Credential{Handle: h, TLS: cert, CSR: csr}, nil
}

func (e *Engine) stageCSR(ctx context.Context, h device.Handle) ([]byte, error) {
	signer, err := e.Keys.Signer(ctx, h)
	if err != nil {
		return nil, err
	}
	policy, err := policyFor(h.Binding)
	if err != nil {
		return nil, err
	}
	if h.Binding.ProfileID == "" {
		return policy.CreateCSR(signer, h.Binding.DeviceID, h.Binding.Generation)
	}
	store, ok := e.Keys.(publicStore)
	if !ok {
		return nil, device.ErrUnsupported
	}
	if err = store.StoreSnapshot(ctx, h, e.Snapshot.Bytes()); err != nil {
		return nil, err
	}
	original, err := store.CSR(ctx, h)
	if err == nil {
		if _, err = policy.ValidateCSR(original, h.Binding.DeviceID, h.Binding.Generation); err != nil {
			return nil, err
		}
		if err = store.StoreCSR(ctx, h, original); err != nil {
			return nil, err
		}
		return store.CSR(ctx, h)
	}
	if !errorsIsNotExist(err) {
		return nil, err
	}
	csr, err := policy.CreateCSR(signer, h.Binding.DeviceID, h.Binding.Generation)
	if err != nil {
		return nil, err
	}
	if err = store.StoreCSR(ctx, h, csr); err != nil {
		return nil, err
	}
	return store.CSR(ctx, h)
}
func (e *Engine) activatePointer(ctx context.Context, h device.Handle, p device.Plan, floor time.Time) error {
	if p.APIVersion != device.V2 {
		return e.Keys.Activate(ctx, h)
	}
	early, late, err := e.decision(ctx, p, floor)
	if err != nil {
		return err
	}
	chain, err := e.Keys.Certificate(ctx, h)
	if err != nil {
		return err
	}
	signer, err := e.Keys.Signer(ctx, h)
	if err != nil {
		return err
	}
	if _, err = e.validateV2Credential(ctx, h, signer, chain, false, true); err != nil {
		return err
	}
	store, ok := e.Keys.(publicStore)
	if !ok {
		return device.ErrUnsupported
	}
	return store.ActivateV2(ctx, h, early, late)
}
func (e *Engine) checkV2Activation(p device.Plan, a device.Activation, c device.Credential) error {
	if a.Evidence == nil {
		return device.ErrDenied
	}
	v := a.Evidence
	snap, err := e.snapshot()
	if err != nil {
		return err
	}
	if v.Phase != "activated" || v.ApplicationID != snap.Composition.ApplicationID || v.ActivationRevision == 0 || v.ActivationRevision > 1<<53-1 || v.ActivationRevision != v.Evidence.Revision || v.Evidence.APIVersion != device.V2 || v.Evidence.Role != "application" || v.Evidence.Plan != p || v.Evidence.Status != "completed" || v.Evidence.Reference == "" || len(v.Evidence.Reference) > 128 || v.InstanceID == "" || len(v.InstanceID) > 128 || v.ConnectionID == "" || len(v.ConnectionID) > 128 || v.SessionID == "" || len(v.SessionID) > 128 || a.SessionID != v.SessionID || len(v.AcceptedScope) != 1 || v.AcceptedScope[0] != "fresh-challenge" {
		return device.ErrDenied
	}
	appRole, err := snap.Role("application")
	if err != nil || !hasPin(appRole.LeafPins, v.Evidence.Source) || v.Evidence.Action != "observe" || !challengeID(v.Evidence.RequestID) || !challengeID(v.Challenge.Nonce) {
		return device.ErrDenied
	}
	if e.Journal == nil {
		return device.ErrDenied
	}
	state, err := e.Journal.Load(context.Background())
	if err != nil || state.Operation == nil || state.Operation.Plan != p {
		return device.ErrDenied
	}
	csr, err := snap.Profile.ValidateCSR(state.Operation.CSR, p.DeviceID, p.TargetGeneration)
	if err != nil || device.Hash(csr.Raw) != v.Active.CSRDigest {
		return device.ErrDenied
	}
	if stored := state.Operation.Activation; stored != nil && (stored.Evidence == nil || stored.Evidence.ActivationRevision != v.ActivationRevision) {
		return device.ErrDenied
	}
	used := []*device.ApplicationEvidence{}
	if stored := state.Operation.Activation; stored != nil {
		used = append(used, stored.Evidence)
	}
	if retired := state.Operation.Retirement; retired != nil && retired.Evidence != nil {
		used = append(used, &retired.Evidence.Current)
	}
	for _, previous := range used {
		if previous == nil || previous.Challenge.Nonce == v.Challenge.Nonce || previous.Evidence.RequestID == v.Evidence.RequestID || !v.Evidence.ObservedAt.After(previous.Evidence.ObservedAt) {
			return device.ErrDenied
		}
	}
	if staged := state.Operation.Probe; staged != nil && staged.Nonce == v.Challenge.Nonce {
		return device.ErrDenied
	}
	b := v.Active
	h := c.Handle
	if b.DeploymentID != p.DeploymentID || b.DeviceID != p.DeviceID || b.OperationID != p.OperationID || b.PlanDigest != p.Digest || b.ConfigDigest != p.ConfigDigest || b.SnapshotDigest != p.SnapshotDigest || b.ProfileID != p.ProfileID || b.ProfileVersion != p.ProfileVersion || b.ProfileDigest != p.ProfileDigest || b.Generation != p.TargetGeneration || b.PublicKeyDigest != h.PublicKeyDigest || b.CertificateFingerprint != fingerprint(c) || v.Evidence.Subject != b {
		return device.ErrDenied
	}
	_, late, err := e.interval(context.Background(), state.ClockFloor)
	if err != nil || v.Evidence.ObservedAt.IsZero() || !late.Before(v.Evidence.Deadline) || !late.Before(v.Challenge.Deadline) || !late.Before(p.ExpiresAt) || v.Evidence.ObservedAt.After(late) || late.Sub(v.Evidence.ObservedAt) > 5*time.Second {
		return device.ErrDenied
	}
	probe := v.Challenge
	if probe != a.Probe || probe.OperationID != p.OperationID || probe.DeviceID != p.DeviceID || probe.Generation != p.TargetGeneration || probe.Endpoint != e.Config.TransportEndpoint || !probe.Deadline.Equal(v.Evidence.Deadline) || probe.Deadline.After(p.ExpiresAt) || !v.Evidence.ObservedAt.Before(probe.Deadline) || probe.Deadline.Sub(v.Evidence.ObservedAt) > time.Duration(snap.Limits.ChallengeSeconds)*time.Second {
		return device.ErrDenied
	}
	return nil
}

// Remember the consumed observation before its dependent effect. Restart must
// obtain a new challenge rather than reuse this still-recent historical proof.
func (e *Engine) rememberActivation(ctx context.Context, s device.State, a device.Activation) (device.State, error) {
	if s.SchemaVersion != 2 {
		return s, nil
	}
	operation := *s.Operation
	candidate := s
	candidate.Operation = &operation
	candidate.Operation.Activation = &a
	next, err := e.save(ctx, candidate, candidate.Operation.Phase)
	if err != nil && next.Revision == s.Revision {
		return s, err
	}
	return next, err
}

func challengeID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == value
}
func errorsIsNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }

func hasPin(pins []string, actual string) bool {
	for _, pin := range pins {
		if pin == actual {
			return true
		}
	}
	return false
}
func (e *Engine) retirement(ctx context.Context, p device.Plan, r device.Retirement, target device.Credential) error {
	if err := checkRetirement(p, r); err != nil {
		return err
	}
	if p.APIVersion != device.V2 {
		return nil
	}
	w := r.Evidence
	if w == nil {
		return device.ErrUnknown
	}
	snap, err := e.snapshot()
	if err != nil {
		return err
	}
	control, err := snap.Role("control")
	if err != nil {
		return err
	}
	transport, err := snap.Role("transport")
	if err != nil {
		return err
	}
	if w.Evidence.APIVersion != device.V2 || w.Evidence.Role != "withdrawal" || w.Evidence.Plan != p || !hasPin(control.LeafPins, w.Evidence.Source) || w.PolicyRevision == 0 || w.Scope != snap.Composition.WithdrawalScope || !w.SessionsTerminated || w.Denial.Kind != "denied" || w.Denial.Evidence.Role != "transport" || w.Denial.Evidence.Plan != p || !hasPin(transport.LeafPins, w.Denial.Evidence.Source) || w.Denial.Evidence.Subject != w.Previous || w.Previous.Generation != p.ExpectedGeneration || w.Target.Generation != p.TargetGeneration || w.Previous.PublicKeyDigest == w.Target.PublicKeyDigest || w.Previous.CertificateFingerprint == w.Target.CertificateFingerprint {
		return device.ErrUnknown
	}
	state, err := e.Journal.Load(ctx)
	if err != nil || state.Operation == nil {
		return device.ErrUnknown
	}
	op := state.Operation
	if op.Previous == nil || op.Previous.PublicKeyDigest != w.Previous.PublicKeyDigest {
		return device.ErrUnknown
	}
	oldCerts, err := credentialprofile.ParseChain(op.PreviousCertificate)
	if err != nil || device.Hash(oldCerts[0].Raw) != w.Previous.CertificateFingerprint {
		return device.ErrUnknown
	}
	oldCSR, err := snap.Profile.ValidateCSR(op.PreviousCSR, p.DeviceID, p.ExpectedGeneration)
	if err != nil || device.Hash(oldCSR.Raw) != w.Previous.CSRDigest || !bytes.Equal(oldCSR.RawSubjectPublicKeyInfo, oldCerts[0].RawSubjectPublicKeyInfo) {
		return device.ErrUnknown
	}
	_, latest, err := e.decision(ctx, p, state.ClockFloor)
	if err != nil {
		return err
	}
	if !latest.Before(w.Denial.Evidence.Deadline) || !latest.Before(w.Current.Evidence.Deadline) {
		return device.ErrUnknown
	}
	current := w.Current
	a := device.Activation{OperationID: p.OperationID, PlanDigest: p.Digest, DeviceID: p.DeviceID, ApplicationID: current.ApplicationID, Generation: current.Active.Generation, CertificateFingerprint: current.Active.CertificateFingerprint, SessionID: current.SessionID, Probe: current.Challenge, Evidence: &current}
	return e.checkActivation(p, a, target)
}
