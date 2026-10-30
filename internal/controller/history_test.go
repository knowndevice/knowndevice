// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
)

func historySnapshot(t *testing.T) *device.PublicSnapshot {
	t.Helper()
	policy, _ := credentialprofile.Find(credentialprofile.StableID, 1)
	s := &device.PublicSnapshot{APIVersion: device.V2, EncodingVersion: 2, DeploymentID: "history-lab", DeviceID: "gateway-1", Profile: policy, RecoveryIdentity: device.RecoverySubject("gateway-1"), RecoveryLeafPin: device.Hash([]byte("recovery-leaf")), RecoverySPKIPin: device.Hash([]byte("recovery-spki")), Limits: device.DefaultLimits(), RequestTimeoutSeconds: 5, PlanTTLSeconds: 600, ClockTrust: "trusted-system-clock"}
	s.Composition = device.Composition{ID: "local-http-lab", Version: 1, AuthorityTemplateDigest: device.Hash([]byte("template")), ApplicationID: "worker", SessionPolicy: "new-connection-no-state-transfer", ObservationRoute: "authenticated-application-callback", WithdrawalScope: "whole-service-lab"}
	caps := map[string]string{"entitlement": "current-entitlement", "authority": "bounded-unknown-issuance", "platform": "exact-peer-binding", "transport": "explicit-access-observation", "application": "durable-activation-and-fresh-observation", "clock": "bounded-interval", "withdrawal": "durable-deny-and-session-inventory"}
	for role, cap := range caps {
		s.Composition.Adapters = append(s.Composition.Adapters, device.AdapterSpec{Role: role, ID: "local-http-lab-" + role, Version: "1", ArtifactDigest: device.Hash([]byte(role)), Capabilities: []string{cap}})
	}
	sort.Slice(s.Composition.Adapters, func(i, j int) bool { return s.Composition.Adapters[i].Role < s.Composition.Adapters[j].Role })
	for i, role := range []string{"application", "authority-transport", "control", "issuance", "observer", "operational", "recovery", "transport"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: role}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		r := device.RoleSnapshot{Role: role, Anchors: [][]byte{der}}
		switch role {
		case "operational":
			r.AllowedIssuers = []string{device.Hash(der)}
		case "recovery":
		case "observer":
			r.PeerName = "observer.invalid"
			r.LeafPins = []string{device.Hash([]byte(role))}
		default:
			r.Endpoint, r.PeerName = "https://"+role+".invalid", role+".invalid"
			r.LeafPins = []string{device.Hash([]byte(role))}
			if role == "issuance" {
				r.CallerLeafPins = []string{device.Hash([]byte("authority-caller"))}
			}
		}
		s.Trust = append(s.Trust, r)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestP19CompletedV2HistoryIgnoresMutableTrustWithoutWriting(t *testing.T) {
	snap := historySnapshot(t)
	p := device.Plan{APIVersion: device.V2, DigestEncodingVersion: 2, DeploymentID: snap.DeploymentID, DeviceID: snap.DeviceID, OperationID: strings.Repeat("a", 32), Mode: "enroll", TargetGeneration: 1, TargetSlot: "A", ProfileID: snap.Profile.ID, ProfileVersion: snap.Profile.Version, ProfileDigest: snap.Profile.PolicyDigest, CompositionDigest: snap.Composition.Digest(), ConfigDigest: snap.Digest(), SnapshotDigest: snap.Digest(), ExpiresAt: time.Now().UTC().Add(-time.Minute)}
	for _, field := range []struct {
		role string
		to   *string
	}{{"control", &p.ControlTrustDigest}, {"application", &p.ApplicationTrustDigest}, {"issuance", &p.IssuanceTrustDigest}, {"recovery", &p.RecoveryTrustDigest}, {"transport", &p.TransportTrustDigest}} {
		r, _ := snap.Role(field.role)
		*field.to = r.Digest()
	}
	p.Digest, _ = p.CalculateDigest()
	s := device.State{SchemaVersion: 2, DeploymentID: snap.DeploymentID, DeviceID: snap.DeviceID, ProfileID: snap.Profile.ID, ProfileVersion: snap.Profile.Version, ProfileDigest: snap.Profile.PolicyDigest, Counter: 1, Operation: &device.Operation{Plan: p, Phase: device.Retired, Outcome: "succeeded", Snapshot: snap.Bytes()}}
	j := &completedSnapshot{state: s}
	e := Engine{Config: device.Config{APIVersion: device.V2, RecoveryCertificate: "/absent/replaced-recovery.pem", ClockTrust: "untrusted", DeviceID: "changed-device"}, Journal: j}
	r, err := e.Apply(context.Background(), p)
	if err != nil || r.Outcome != "succeeded" || r.Health != "unknown" || r.Phase != device.Retired || j.state.Operation.Outcome != "succeeded" {
		t.Fatalf("completed V2 history changed with mutable trust: %+v, %v", r, err)
	}
	j.state.Operation.Outcome = "running"
	r, err = e.Apply(context.Background(), p)
	if err != nil || r.Outcome != "succeeded" || r.Health != "unknown" || j.state.Operation.Outcome != "running" {
		t.Fatalf("durable terminal checkpoint did not report completion without writes: %+v, %v", r, err)
	}
	r, err = e.failure(context.Background(), j.state, device.ErrDenied)
	if err != device.ErrDenied || r.Outcome != "succeeded" || j.state.Operation.Outcome != "running" {
		t.Fatal("failure after terminal checkpoint rewrote completed history")
	}
	j.state.Operation.Snapshot = []byte("corrupt public snapshot")
	if _, err = e.Apply(context.Background(), p); err == nil {
		t.Fatal("corrupt retained snapshot accepted as historical evidence")
	}
}

type terminalWriter struct {
	state device.State
	fail  bool
	saves int
}

func (j *terminalWriter) Load(context.Context) (device.State, error) { return j.state, nil }
func (j *terminalWriter) Close() error                               { return nil }
func (j *terminalWriter) Save(_ context.Context, s device.State, _ uint64) (device.State, error) {
	j.saves++
	if j.fail {
		return j.state, device.ErrUnknown
	}
	j.state = s
	return s, nil
}

func TestP18TerminalSaveFailureCannotReportUnsavedCompletion(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	// Exercise only the journal transaction; no credential or remote role is invoked.
	p := device.Plan{ExpiresAt: now.Add(time.Minute)}
	original := device.State{SchemaVersion: 2, Operation: &device.Operation{Plan: p, Phase: device.DestroyIntent, Outcome: "running"}}
	j := &terminalWriter{state: original, fail: true}
	e := Engine{Config: device.Config{ClockTrust: "trusted-system-clock"}, Journal: j, Now: func() time.Time { return now }}
	s, err := e.save(ctx, original, device.Retired)
	if err != device.ErrUnknown || s.Operation.Phase != device.DestroyIntent || original.Operation.Phase != device.DestroyIntent || s.Operation.Outcome != "running" {
		t.Fatal("rejected terminal write mutated the last confirmed checkpoint")
	}
	r, _ := e.failure(ctx, s, err)
	if r.Outcome == "succeeded" || j.state.Operation.Phase != device.DestroyIntent {
		t.Fatal("protected write failure claimed unsaved completion")
	}
	j.fail = false
	e.Checkpoint = func(string) error { return device.ErrUnknown }
	s, err = e.save(ctx, j.state, device.Retired)
	if err != device.ErrUnknown || j.state.Operation.Phase != device.Retired || j.state.Operation.Outcome != "succeeded" {
		t.Fatal("terminal checkpoint was acknowledged before durable success")
	}
	saves := j.saves
	r, _ = e.failure(ctx, s, err)
	if r.Outcome != "succeeded" || j.saves != saves {
		t.Fatal("post-commit checkpoint error rewrote durable completion")
	}
}
