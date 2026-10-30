// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/internal/device"
	"knowndevice.local/knowndevice/internal/journal"
	"knowndevice.local/knowndevice/internal/keystore"
)

func TestLiveApplicationProofCannotReuseStoredActivationAuthority(t *testing.T) {
	snapshot := historySnapshot(t)
	now := time.Now().UTC()
	p := device.Plan{APIVersion: device.V2, DigestEncodingVersion: 2, DeploymentID: snapshot.DeploymentID, DeviceID: snapshot.DeviceID, OperationID: strings.Repeat("a", 32), Mode: "rotate", ExpectedGeneration: 1, TargetGeneration: 2, TargetSlot: "B", ProfileID: snapshot.Profile.ID, ProfileVersion: snapshot.Profile.Version, ProfileDigest: snapshot.Profile.PolicyDigest, ConfigDigest: snapshot.Digest(), CompositionDigest: snapshot.Composition.Digest(), SnapshotDigest: snapshot.Digest(), ExpiresAt: now.Add(time.Minute)}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := snapshot.Profile.CreateCSR(key, p.DeviceID, p.TargetGeneration)
	if err != nil {
		t.Fatal(err)
	}
	request, err := snapshot.Profile.ValidateCSR(csr, p.DeviceID, p.TargetGeneration)
	if err != nil {
		t.Fatal(err)
	}
	target := device.Credential{Handle: device.Handle{Binding: p.Binding(), PublicKeyDigest: device.Hash(request.RawSubjectPublicKeyInfo)}, TLS: tls.Certificate{Certificate: [][]byte{[]byte("already validated target leaf")}, PrivateKey: key}, CSR: csr}
	binding := device.CredentialBinding{DeploymentID: p.DeploymentID, DeviceID: p.DeviceID, OperationID: p.OperationID, PlanDigest: p.Digest, ConfigDigest: p.ConfigDigest, SnapshotDigest: p.SnapshotDigest, ProfileID: p.ProfileID, ProfileVersion: p.ProfileVersion, ProfileDigest: p.ProfileDigest, Generation: p.TargetGeneration, PublicKeyDigest: target.Handle.PublicKeyDigest, CertificateFingerprint: fingerprint(target), CSRDigest: device.Hash(request.Raw)}
	transport, _ := snapshot.Role("transport")
	application, _ := snapshot.Role("application")
	probe := device.Probe{OperationID: p.OperationID, DeviceID: p.DeviceID, Generation: p.TargetGeneration, Endpoint: transport.Endpoint, Nonce: strings.Repeat("b", 32), Deadline: now.Add(20 * time.Second)}
	valid := device.Activation{OperationID: p.OperationID, PlanDigest: p.Digest, DeviceID: p.DeviceID, ApplicationID: snapshot.Composition.ApplicationID, Generation: p.TargetGeneration, CertificateFingerprint: fingerprint(target), SessionID: "target-session", Probe: probe, Evidence: &device.ApplicationEvidence{Evidence: device.Evidence{APIVersion: device.V2, Role: "application", Action: "observe", RequestID: strings.Repeat("c", 32), Plan: p, Subject: binding, Revision: 2, Reference: p.OperationID, Source: application.LeafPins[0], ObservedAt: now, Deadline: probe.Deadline, Status: "completed"}, Phase: "activated", ApplicationID: snapshot.Composition.ApplicationID, ActivationRevision: 2, Active: binding, InstanceID: "application-instance", ConnectionID: "target-connection", SessionID: "target-session", Challenge: probe, AcceptedScope: []string{"fresh-challenge"}}}
	stored := valid
	storedProof := *valid.Evidence
	stored.Evidence = &storedProof
	stored.Probe.Nonce = strings.Repeat("f", 32)
	stored.Evidence.Challenge = stored.Probe
	stored.Evidence.Evidence.RequestID = strings.Repeat("e", 32)
	stored.Evidence.Evidence.ObservedAt = now.Add(-time.Second)
	staged := probe
	staged.Nonce = strings.Repeat("d", 32)
	for _, phase := range []device.Phase{device.Activated, device.Committed, device.BrokerRetired, device.CARevoked, device.DestroyIntent} {
		t.Run(string(phase), func(t *testing.T) {
			// These checkpoints already retain a valid selection. A fresh role
			// result must earn authority again before pointer/revoke/destruction.
			j := &terminalWriter{state: device.State{SchemaVersion: 2, Operation: &device.Operation{Plan: p, Phase: phase, CSR: csr, Probe: &staged, Activation: &stored}}}
			e := &Engine{Config: device.Config{APIVersion: device.V2, TransportEndpoint: transport.Endpoint}, Snapshot: snapshot, Journal: j, Clock: device.SystemClock{Uncertainty: time.Second, MaximumAge: 10 * time.Second}}
			if err := e.checkV2Activation(p, valid, target); err != nil {
				t.Fatalf("new observation of the unchanged selection refused: %v", err)
			}
			cases := map[string]func(*device.Activation){
				"replayed-observation":        func(a *device.Activation) { *a = stored },
				"reused-request-id":           func(a *device.Activation) { a.Evidence.Evidence.RequestID = stored.Evidence.Evidence.RequestID },
				"observation-regression":      func(a *device.Activation) { a.Evidence.Evidence.ObservedAt = now.Add(-2 * time.Second) },
				"unchanged-observation-time":  func(a *device.Activation) { a.Evidence.Evidence.ObservedAt = stored.Evidence.Evidence.ObservedAt },
				"revision-mismatch":           func(a *device.Activation) { a.Evidence.Evidence.Revision++ },
				"different-durable-selection": func(a *device.Activation) { a.Evidence.Evidence.Revision++; a.Evidence.ActivationRevision++ },
				"stale-observation":           func(a *device.Activation) { a.Evidence.Evidence.ObservedAt = now.Add(-10 * time.Second) },
				"wrong-session":               func(a *device.Activation) { a.SessionID = "another-session" },
				"wrong-challenge-operation": func(a *device.Activation) {
					a.Probe.OperationID = strings.Repeat("e", 32)
					a.Evidence.Challenge = a.Probe
				},
				"wrong-challenge-generation": func(a *device.Activation) { a.Probe.Generation--; a.Evidence.Challenge = a.Probe },
				"malformed-nonce":            func(a *device.Activation) { a.Probe.Nonce = "not-a-random-id"; a.Evidence.Challenge = a.Probe },
				"staged-nonce":               func(a *device.Activation) { a.Probe.Nonce = staged.Nonce; a.Evidence.Challenge = a.Probe },
				"different-deadlines":        func(a *device.Activation) { a.Evidence.Evidence.Deadline = p.ExpiresAt },
				"oversized-challenge-window": func(a *device.Activation) {
					a.Probe.Deadline = now.Add(40 * time.Second)
					a.Evidence.Challenge = a.Probe
					a.Evidence.Evidence.Deadline = a.Probe.Deadline
				},
			}
			for name, change := range cases {
				t.Run(name, func(t *testing.T) {
					candidate := valid
					proof := *valid.Evidence
					candidate.Evidence = &proof
					change(&candidate)
					if err := e.checkV2Activation(p, candidate, target); err == nil {
						t.Fatal("invalid live proof borrowed authority from the retained valid activation")
					}
					state, err := j.Load(context.Background())
					if err != nil || state.Operation.Activation.Evidence.ActivationRevision != 2 || j.saves != 0 {
						t.Fatal("validation changed the retained selection or durable intent")
					}
				})
			}
			j.state.Operation.Retirement = &device.Retirement{Evidence: &device.WithdrawalEvidence{Current: *valid.Evidence}}
			if err := e.checkV2Activation(p, valid, target); err == nil {
				t.Fatal("retirement's already consumed current observation was replayed")
			}
		})
	}
}

type liveProofPlatform struct {
	device.Platform
	activation device.Activation
}

func (p *liveProofPlatform) ActivationStatus(context.Context, device.Plan, device.Credential) (device.Activation, error) {
	return p.activation, nil
}

type liveProofKeys struct {
	*keystore.Store
	journal   device.Journal
	wantNonce string
	activated int
}

func (k *liveProofKeys) ActivateV2(ctx context.Context, h device.Handle, early, late time.Time) error {
	k.activated++
	s, err := k.journal.Load(ctx)
	if err != nil || s.Operation.Activation.Probe.Nonce != k.wantNonce {
		return errors.New("pointer change preceded durable fresh observation")
	}
	return k.Store.ActivateV2(ctx, h, early, late)
}

type failingObservationJournal struct {
	device.Journal
	oldNonce string
}

func (j failingObservationJournal) Save(ctx context.Context, s device.State, revision uint64) (device.State, error) {
	if s.Operation.Activation != nil && s.Operation.Activation.Probe.Nonce != j.oldNonce {
		return device.State{}, device.ErrUnknown
	}
	return j.Journal.Save(ctx, s, revision)
}

func liveProofFixture(t *testing.T) (*Engine, device.Plan, *journal.Store, *liveProofKeys, device.Activation) {
	t.Helper()
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := historySnapshot(t)
	now := time.Now().UTC()
	var issuer *x509.Certificate
	var issuerKey *ecdsa.PrivateKey
	for i := range snapshot.Trust {
		role := &snapshot.Trust[i]
		if role.Role != "operational" && role.Role != "recovery" {
			continue
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := &x509.Certificate{SerialNumber: big.NewInt(20), Subject: pkix.Name{CommonName: role.Role}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		ca, err = x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		role.Anchors = [][]byte{der}
		if role.Role == "operational" {
			issuer, issuerKey = ca, key
			role.AllowedIssuers = []string{device.Hash(der)}
			continue
		}
		recovery := &x509.Certificate{SerialNumber: big.NewInt(21), Subject: pkix.Name{CommonName: snapshot.RecoveryIdentity}, DNSNames: []string{snapshot.RecoveryIdentity}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err = x509.CreateCertificate(rand.Reader, recovery, ca, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(base, "recovery-leaf.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := device.Config{APIVersion: device.V2, DeviceID: snapshot.DeviceID, DeploymentID: snapshot.DeploymentID, StateDir: filepath.Join(base, "state"), ApplicationID: snapshot.Composition.ApplicationID, ClockTrust: snapshot.ClockTrust, RequestTimeoutSeconds: 5, PlanTTLSeconds: 600, RecoveryCertificate: filepath.Join(base, "recovery-leaf.pem"), RecoveryKey: filepath.Join(base, "opaque-recovery-handle"), CredentialProfile: &snapshot.Profile, Composition: &snapshot.Composition, Limits: &snapshot.Limits, Trust: &device.TrustConfig{}}
	for _, role := range snapshot.Trust {
		path := filepath.Join(base, role.Role+".pem")
		if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: role.Anchors[0]}), 0600); err != nil {
			t.Fatal(err)
		}
		cfg.Trust.Roles = append(cfg.Trust.Roles, device.RoleConfig{Role: role.Role, Endpoint: role.Endpoint, PeerName: role.PeerName, RootCertificates: []string{path}, LeafPins: role.LeafPins, SPKIPins: role.SPKIPins, AllowedIssuers: role.AllowedIssuers, CallerLeafPins: role.CallerLeafPins, CallerSPKIPins: role.CallerSPKIPins})
		switch role.Role {
		case "control":
			cfg.ControlURL = role.Endpoint
		case "application":
			cfg.ApplicationURL = role.Endpoint
		case "transport":
			cfg.TransportEndpoint = role.Endpoint
		}
	}
	snapshot, err = cfg.ResolveSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	j, err := journal.OpenV2(ctx, filepath.Join(cfg.StateDir, "journal.db"), cfg.DeploymentID, cfg.DeviceID, snapshot.Profile.ID, snapshot.Profile.Version, snapshot.Profile.PolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	store, err := keystore.OpenV2(filepath.Join(cfg.StateDir, "slots"), cfg.DeploymentID, cfg.DeviceID, snapshot.Profile.ID, snapshot.Profile.Version, snapshot.Profile.PolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	state, err := j.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPlan(cfg, state, "enroll", now)
	if err != nil {
		t.Fatal(err)
	}
	state.Counter = p.TargetGeneration
	state.Operation = &device.Operation{Plan: p, Phase: device.Planned, Outcome: "running", Snapshot: snapshot.Bytes()}
	save := func(phase device.Phase) {
		t.Helper()
		state.Operation.Phase = phase
		state, err = j.Save(ctx, state, state.Revision)
		if err != nil {
			t.Fatal(err)
		}
	}
	save(device.Planned)
	handle, err := store.Stage(ctx, p.Binding())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := store.Signer(ctx, handle)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := snapshot.Profile.CreateCSR(signer, p.DeviceID, p.TargetGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.StoreSnapshot(ctx, handle, snapshot.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err = store.StoreCSR(ctx, handle, csr); err != nil {
		t.Fatal(err)
	}
	state.Operation.Target, state.Operation.CSR = &handle, csr
	save(device.KeyReady)
	save(device.IssueIntent)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(22), Subject: pkix.Name{CommonName: snapshot.Profile.Subject(p.DeviceID, p.TargetGeneration)}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(1170 * time.Second), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, signer.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})...)
	state.Operation.Certificate = chain
	save(device.Issued)
	if err = store.StoreCertificate(ctx, handle, chain); err != nil {
		t.Fatal(err)
	}
	save(device.RegisterIntent)
	save(device.Registered)
	probe := device.Probe{OperationID: p.OperationID, DeviceID: p.DeviceID, Generation: p.TargetGeneration, Endpoint: cfg.TransportEndpoint, Nonce: strings.Repeat("a", 32), Deadline: now.Add(20 * time.Second)}
	state.Operation.Probe = &probe
	save(device.Verified)
	save(device.ActivateIntent)
	parsedCSR, err := snapshot.Profile.ValidateCSR(csr, p.DeviceID, p.TargetGeneration)
	if err != nil {
		t.Fatal(err)
	}
	bound := device.CredentialBinding{DeploymentID: p.DeploymentID, DeviceID: p.DeviceID, OperationID: p.OperationID, PlanDigest: p.Digest, ConfigDigest: p.ConfigDigest, SnapshotDigest: p.SnapshotDigest, ProfileID: p.ProfileID, ProfileVersion: p.ProfileVersion, ProfileDigest: p.ProfileDigest, Generation: p.TargetGeneration, PublicKeyDigest: handle.PublicKeyDigest, CertificateFingerprint: device.Hash(der), CSRDigest: device.Hash(parsedCSR.Raw)}
	app, _ := snapshot.Role("application")
	live := probe
	live.Nonce = strings.Repeat("b", 32)
	activation := device.Activation{OperationID: p.OperationID, PlanDigest: p.Digest, DeviceID: p.DeviceID, ApplicationID: cfg.ApplicationID, Generation: p.TargetGeneration, CertificateFingerprint: bound.CertificateFingerprint, SessionID: "session", Probe: live, Evidence: &device.ApplicationEvidence{Evidence: device.Evidence{APIVersion: device.V2, Role: "application", Action: "observe", RequestID: strings.Repeat("c", 32), Plan: p, Subject: bound, Revision: 1, Reference: p.OperationID, Source: app.LeafPins[0], ObservedAt: now, Deadline: live.Deadline, Status: "completed"}, Phase: "activated", ApplicationID: cfg.ApplicationID, ActivationRevision: 1, Active: bound, InstanceID: "instance", ConnectionID: "connection", SessionID: "session", Challenge: live, AcceptedScope: []string{"fresh-challenge"}}}
	state.Operation.Activation = &activation
	save(device.Activated)
	keys := &liveProofKeys{Store: store, journal: j}
	e := &Engine{Config: cfg, Journal: j, Keys: keys, Snapshot: snapshot, Clock: device.SystemClock{Uncertainty: time.Second, MaximumAge: 10 * time.Second}, Platform: &liveProofPlatform{activation: activation}, Checkpoint: func(phase string) error {
		if phase == "pointer-written" {
			return device.ErrUnknown
		}
		return nil
	}}
	return e, p, j, keys, activation
}

func TestFreshObservationIsDurableBeforePointerAndReplayFailsAfterReopen(t *testing.T) {
	ctx := context.Background()
	e, p, j, keys, stored := liveProofFixture(t)
	if _, err := e.Apply(ctx, p); !errors.Is(err, device.ErrDenied) || keys.activated != 0 {
		t.Fatal("stored proof authorized a pointer effect")
	}
	fresh := stored
	proof := *stored.Evidence
	fresh.Evidence = &proof
	fresh.Probe.Nonce = strings.Repeat("d", 32)
	fresh.Evidence.Challenge = fresh.Probe
	fresh.Evidence.Evidence.RequestID = strings.Repeat("e", 32)
	fresh.Evidence.Evidence.ObservedAt = time.Now().UTC()
	keys.wantNonce = fresh.Probe.Nonce
	e.Platform = &liveProofPlatform{activation: fresh}
	if _, err := e.Apply(ctx, p); !errors.Is(err, device.ErrUnknown) || keys.activated != 1 {
		t.Fatalf("new observation was not durable before the controlled pointer checkpoint: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	newJournal, err := journal.OpenV2(ctx, filepath.Join(e.Config.StateDir, "journal.db"), p.DeploymentID, p.DeviceID, p.ProfileID, p.ProfileVersion, p.ProfileDigest)
	if err != nil {
		t.Fatal(err)
	}
	defer newJournal.Close()
	e.Journal, keys.journal = newJournal, newJournal
	e.assessment = nil
	if _, err = e.Apply(ctx, p); !errors.Is(err, device.ErrDenied) || keys.activated != 1 {
		t.Fatal("reopened journal allowed its last observation to be consumed again")
	}
}

func TestObservationSaveFailureStopsBeforePointer(t *testing.T) {
	e, p, j, keys, stored := liveProofFixture(t)
	fresh := stored
	proof := *stored.Evidence
	fresh.Evidence = &proof
	fresh.Probe.Nonce = strings.Repeat("d", 32)
	fresh.Evidence.Challenge = fresh.Probe
	fresh.Evidence.Evidence.RequestID = strings.Repeat("e", 32)
	fresh.Evidence.Evidence.ObservedAt = time.Now().UTC()
	e.Platform = &liveProofPlatform{activation: fresh}
	e.Journal = failingObservationJournal{Journal: j, oldNonce: stored.Probe.Nonce}
	if _, err := e.Apply(context.Background(), p); !errors.Is(err, device.ErrUnknown) || keys.activated != 0 {
		t.Fatal("failed observation write permitted a pointer effect")
	}
	state, err := j.Load(context.Background())
	if err != nil || state.Operation.Activation.Probe.Nonce != stored.Probe.Nonce || state.Operation.Phase != device.Activated {
		t.Fatal("failed observation write changed durable proof or intent")
	}
}
