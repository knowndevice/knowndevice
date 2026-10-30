// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
)

func publicBindingFixture(t *testing.T, h device.Handle, csrData, chainData []byte) device.CredentialBinding {
	t.Helper()
	profile, err := credentialprofile.Resolve(h.Binding.ProfileID, h.Binding.ProfileVersion, h.Binding.ProfileDigest)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := profile.ValidateCSR(csrData, h.Binding.DeviceID, h.Binding.Generation)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := credentialprofile.ParseChain(chainData)
	if err != nil {
		t.Fatal(err)
	}
	b := h.Binding
	return device.CredentialBinding{DeploymentID: b.DeploymentID, DeviceID: b.DeviceID, OperationID: b.OperationID, PlanDigest: b.PlanDigest, ConfigDigest: b.ConfigDigest, SnapshotDigest: b.SnapshotDigest, ProfileID: b.ProfileID, ProfileVersion: b.ProfileVersion, ProfileDigest: b.ProfileDigest, Generation: b.Generation, PublicKeyDigest: h.PublicKeyDigest, CertificateFingerprint: device.Hash(chain[0].Raw), CSRDigest: device.Hash(csr.Raw)}
}

func (f journalProfileFixture) envelope(t *testing.T, plan device.Plan, subject device.CredentialBinding, role, peer, action, status string, revision uint64) device.Evidence {
	t.Helper()
	r, err := f.snapshot.Role(peer)
	if err != nil {
		t.Fatal(err)
	}
	return device.Evidence{APIVersion: device.V2, Role: role, Action: action, RequestID: strings.Repeat("f", 32), Plan: plan, Subject: subject, Revision: revision, Reference: plan.OperationID, Source: r.LeafPins[0], ObservedAt: time.Now().UTC(), Deadline: plan.ExpiresAt, Status: status}
}

func (f journalProfileFixture) activation(t *testing.T, o *device.Operation, nonce string) *device.Activation {
	t.Helper()
	target := publicBindingFixture(t, *o.Target, o.CSR, o.Certificate)
	r, err := f.snapshot.Role("transport")
	if err != nil {
		t.Fatal(err)
	}
	probe := device.Probe{OperationID: o.Plan.OperationID, DeviceID: o.Plan.DeviceID, Generation: o.Plan.TargetGeneration, Endpoint: r.Endpoint, Nonce: strings.Repeat(nonce, 32), Deadline: time.Now().UTC().Add(20 * time.Second)}
	e := f.envelope(t, o.Plan, target, "application", "application", "observe", "completed", 2)
	e.Deadline = probe.Deadline
	app := &device.ApplicationEvidence{Evidence: e, Phase: "activated", ApplicationID: f.snapshot.Composition.ApplicationID, ActivationRevision: 2, Active: target, InstanceID: "application-instance", ConnectionID: "new-target-connection", SessionID: "new-application-session", Challenge: probe, AcceptedScope: []string{"fresh-challenge"}}
	return &device.Activation{OperationID: o.Plan.OperationID, PlanDigest: o.Plan.Digest, DeviceID: o.Plan.DeviceID, ApplicationID: app.ApplicationID, Generation: target.Generation, CertificateFingerprint: target.CertificateFingerprint, SessionID: app.SessionID, Probe: probe, Evidence: app}
}

func TestV2JournalActivationRequiresDurableNewObservation(t *testing.T) {
	f := newJournalProfileFixture(t, credentialprofile.StableID)
	s := f.open(t, journalPath(t))
	state := snapshot(t, s)
	state.Counter, state.Operation = 1, f.operation(t, 1)
	state, err := s.Save(context.Background(), state, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*device.Operation)
	}{{"no-application-evidence", func(o *device.Operation) { o.Activation.Evidence = nil }}, {"candidate-verified", func(o *device.Operation) { o.Activation.Evidence.Phase = "candidate-verified" }}, {"zero-revision", func(o *device.Operation) { o.Activation.Evidence.ActivationRevision = 0 }}, {"mismatched-revision", func(o *device.Operation) { o.Activation.Evidence.ActivationRevision++ }}, {"status-as-live-observation", func(o *device.Operation) { o.Activation.Evidence.Evidence.Action = "status" }}, {"staged-nonce", func(o *device.Operation) {
		o.Probe = &o.Activation.Probe
	}}, {"wrong-key", func(o *device.Operation) {
		o.Activation.Evidence.Active.PublicKeyDigest = device.Hash([]byte("different-key"))
	}}, {"wrong-csr", func(o *device.Operation) {
		o.Activation.Evidence.Active.CSRDigest = device.Hash([]byte("different-csr"))
	}}, {"wrong-role-source", func(o *device.Operation) {
		role, _ := f.snapshot.Role("control")
		o.Activation.Evidence.Evidence.Source = role.LeafPins[0]
	}}, {"missing-connection", func(o *device.Operation) { o.Activation.Evidence.ConnectionID = "" }}, {"deadline-crossing", func(o *device.Operation) { o.Activation.Evidence.Evidence.ObservedAt = o.Activation.Probe.Deadline }}} {
		t.Run(test.name, func(t *testing.T) {
			next := snapshot(t, s)
			f.material(t, next.Operation)
			next.Operation.Phase = device.Activated
			next.Operation.Activation = f.activation(t, next.Operation, "b")
			test.edit(next.Operation)
			if _, err := s.Save(context.Background(), next, next.Revision); err == nil {
				t.Fatal("invalid activation evidence advanced the journal")
			}
			if !reflect.DeepEqual(state, snapshot(t, s)) {
				t.Fatal("refused activation changed original intent")
			}
		})
	}
	next := snapshot(t, s)
	f.material(t, next.Operation)
	next.Operation.Phase = device.Activated
	next.Operation.Activation = f.activation(t, next.Operation, "b")
	next, err = s.Save(context.Background(), next, next.Revision)
	if err != nil {
		t.Fatalf("bound durable activation was refused: %v", err)
	}
	candidate := snapshot(t, s)
	candidate.Operation.Activation.Evidence.ActivationRevision++
	candidate.Operation.Activation.Evidence.Evidence.Revision++
	if _, err := s.Save(context.Background(), candidate, candidate.Revision); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("durable active selection revision changed: %v", err)
	}
	if !reflect.DeepEqual(next, snapshot(t, s)) {
		t.Fatal("selection conflict changed journal")
	}
}

func (f journalProfileFixture) retirement(t *testing.T, o *device.Operation) *device.Retirement {
	t.Helper()
	previous := publicBindingFixture(t, *o.Previous, o.PreviousCSR, o.PreviousCertificate)
	target := publicBindingFixture(t, *o.Target, o.CSR, o.Certificate)
	transport, _ := f.snapshot.Role("transport")
	probe := device.Probe{OperationID: o.Plan.OperationID, DeviceID: o.Plan.DeviceID, Generation: previous.Generation, Endpoint: transport.Endpoint, Nonce: strings.Repeat("d", 32), Deadline: time.Now().UTC().Add(20 * time.Second)}
	denied := f.envelope(t, o.Plan, previous, "transport", "transport", "challenge", "denied", 3)
	denied.Deadline, denied.Reference = probe.Deadline, "old-key-connection"
	current := f.activation(t, o, "c").Evidence
	entry := f.envelope(t, o.Plan, previous, "withdrawal", "control", "withdraw", "ok", 3)
	w := &device.WithdrawalEvidence{Evidence: entry, Previous: previous, Target: target, PolicyRevision: 3, Scope: f.snapshot.Composition.WithdrawalScope, SessionsTerminated: true, Denial: device.AccessObservation{Evidence: denied, Kind: "denied", ConnectionID: "old-key-connection", Challenge: probe}, Current: *current}
	return &device.Retirement{OperationID: o.Plan.OperationID, PlanDigest: o.Plan.Digest, Generation: o.Plan.ExpectedGeneration, PolicyDurable: true, SessionsTerminated: true, TLSObservation: "accepted", ApplicationAccessDenied: true, Evidence: w}
}

func TestV2JournalWithdrawalRequiresExactPreviousArtifacts(t *testing.T) {
	f := newJournalProfileFixture(t, credentialprofile.StableID)
	s := f.open(t, journalPath(t))
	state := snapshot(t, s)
	state.Counter, state.Operation = 1, f.operation(t, 1)
	state, err := s.Save(context.Background(), state, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	f.material(t, state.Operation)
	state.Operation.Activation = f.activation(t, state.Operation, "b")
	state.Operation.Phase = device.Retired
	state.Active = state.Operation.Target
	state, err = s.Save(context.Background(), state, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	previous := *state.Active
	previousCSR, previousChain := state.Operation.CSR, state.Operation.Certificate
	f.signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operation := f.operation(t, 2)
	operation.Plan.Mode, operation.Plan.ExpectedGeneration, operation.Plan.TargetSlot = "rotate", 1, "B"
	operation.Plan.Digest, _ = operation.Plan.CalculateDigest()
	operation.Previous, operation.PreviousCSR, operation.PreviousCertificate = &previous, previousCSR, previousChain
	state.Counter, state.Operation = 2, operation
	state, err = s.Save(context.Background(), state, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*device.Operation)
	}{{"missing-previous-csr", func(o *device.Operation) { o.PreviousCSR = nil }}, {"missing-previous-chain", func(o *device.Operation) { o.PreviousCertificate = nil }}, {"target-as-previous", func(o *device.Operation) { o.Retirement.Evidence.Previous = o.Retirement.Evidence.Target }}, {"wrong-old-csr", func(o *device.Operation) {
		o.Retirement.Evidence.Previous.CSRDigest = device.Hash([]byte("wrong-old-csr"))
	}}, {"wrong-old-leaf", func(o *device.Operation) {
		o.Retirement.Evidence.Previous.CertificateFingerprint = device.Hash([]byte("wrong-old-leaf"))
	}}, {"target-denial", func(o *device.Operation) {
		o.Retirement.Evidence.Denial.Evidence.Subject = o.Retirement.Evidence.Target
	}}, {"closed-socket", func(o *device.Operation) { o.Retirement.Evidence.Denial.Kind = "unknown" }}, {"zero-policy-revision", func(o *device.Operation) { o.Retirement.Evidence.PolicyRevision = 0 }}, {"staged-current", func(o *device.Operation) { o.Retirement.Evidence.Current.Phase = "candidate-verified" }}, {"old-current-observation", func(o *device.Operation) {
		o.Retirement.Evidence.Current.Evidence.ObservedAt = o.Retirement.Evidence.Denial.Evidence.ObservedAt.Add(-time.Second)
	}}, {"wrong-denial-source", func(o *device.Operation) {
		role, _ := f.snapshot.Role("application")
		o.Retirement.Evidence.Denial.Evidence.Source = role.LeafPins[0]
	}}} {
		t.Run(test.name, func(t *testing.T) {
			next := snapshot(t, s)
			f.material(t, next.Operation)
			next.Operation.Activation = f.activation(t, next.Operation, "b")
			next.Operation.Retirement = f.retirement(t, next.Operation)
			next.Operation.Phase, next.Active = device.BrokerRetired, next.Operation.Target
			test.edit(next.Operation)
			if _, err := s.Save(context.Background(), next, next.Revision); err == nil {
				t.Fatal("invalid effective withdrawal evidence was accepted")
			}
			if !reflect.DeepEqual(state, snapshot(t, s)) {
				t.Fatal("refused withdrawal changed active generation or intent")
			}
		})
	}
	next := snapshot(t, s)
	f.material(t, next.Operation)
	next.Operation.Activation = f.activation(t, next.Operation, "b")
	next.Operation.Retirement = f.retirement(t, next.Operation)
	next.Operation.Phase, next.Active = device.BrokerRetired, next.Operation.Target
	if _, err := s.Save(context.Background(), next, next.Revision); err != nil {
		t.Fatalf("exact withdrawal evidence was refused: %v", err)
	}
}
