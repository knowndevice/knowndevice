// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/internal/device"
	"github.com/knowndevice/knowndevice/internal/journal"
)

type diagnosticJournal struct {
	device.Journal
	reject       device.Phase
	writeErr     error
	latched      bool
	rejected     int
	latchedSaves int
}

func (j *diagnosticJournal) Save(ctx context.Context, s device.State, revision uint64) (device.State, error) {
	if j.latched {
		j.latchedSaves++
		return device.State{}, j.writeErr
	}
	if s.Operation.Phase == j.reject {
		j.latched = true
		j.rejected++
		return device.State{}, j.writeErr
	}
	return j.Journal.Save(ctx, s, revision)
}

type diagnosticKeys struct {
	device.KeyStore
	signer crypto.Signer
	chain  []byte
	active *device.Handle
}

func (k *diagnosticKeys) Signer(context.Context, device.Handle) (crypto.Signer, error) {
	return k.signer, nil
}
func (k *diagnosticKeys) Certificate(context.Context, device.Handle) ([]byte, error) {
	return k.chain, nil
}
func (k *diagnosticKeys) Active(context.Context) (*device.Handle, error) { return k.active, nil }

type diagnosticAuthority struct {
	device.Authority
	issues int
}

func (a *diagnosticAuthority) Issue(context.Context, device.IssueRequest) ([]byte, error) {
	a.issues++
	return nil, device.ErrDenied
}

type diagnosticPlatform struct {
	device.Platform
	observations int
}

func (p *diagnosticPlatform) ActivationStatus(context.Context, device.Plan, device.Credential) (device.Activation, error) {
	p.observations++
	return device.Activation{}, device.ErrDenied
}

func diagnosticFixture(t *testing.T, phase device.Phase) (*Engine, device.Plan, *journal.Store, device.State) {
	t.Helper()
	ctx := context.Background()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "diagnostic test root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := device.Config{DeviceID: "gateway-1", RootCertificate: rootPath, ClockTrust: "trusted-system-clock", PlanTTLSeconds: 600}
	j, err := journal.Open(ctx, filepath.Join(dir, "journal.db"), cfg.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := j.Close(); err != nil {
			t.Error(err)
		}
	})
	s, err := j.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPlan(cfg, s, "enroll", now)
	if err != nil {
		t.Fatal(err)
	}
	s.Counter = p.TargetGeneration
	s.ClockFloor = now.Add(-time.Second)
	s.Operation = &device.Operation{Plan: p, Phase: device.Planned, Outcome: "running"}
	s, err = j.Save(ctx, s, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	h := device.Handle{Binding: p.Binding(), PublicKeyDigest: device.Hash(publicKey)}
	csr, err := CSR(signer, h.Binding)
	if err != nil {
		t.Fatal(err)
	}
	s.Operation.Target = &h
	s.Operation.CSR = csr
	s.Operation.Phase = device.KeyReady
	s, err = j.Save(ctx, s, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	keys := &diagnosticKeys{signer: signer}
	if phase != device.KeyReady {
		subject := device.Subject(p.DeviceID, p.TargetGeneration)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: subject}, DNSNames: []string{subject}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, signer.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		keys.chain = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keys.active = &h
		s.Active = &h
		s.Operation.Certificate = keys.chain
		s.Operation.Phase = phase
		s, err = j.Save(ctx, s, s.Revision)
		if err != nil {
			t.Fatal(err)
		}
	}
	e := &Engine{Config: cfg, Journal: j, Keys: keys, Recovery: &device.Credential{DeviceID: p.DeviceID, Recovery: true}, Now: func() time.Time { return now }}
	return e, p, j, s
}

func TestV1CheckpointSaveFailureReportsDurablePhaseAndStopsEffects(t *testing.T) {
	for _, test := range []struct {
		name   string
		before device.Phase
		after  device.Phase
	}{{"intermediate", device.KeyReady, device.IssueIntent}, {"terminal", device.Committed, device.Retired}} {
		t.Run(test.name, func(t *testing.T) {
			e, p, durable, before := diagnosticFixture(t, test.before)
			writeErr := errors.New("checkpoint write failed")
			j := &diagnosticJournal{Journal: durable, reject: test.after, writeErr: writeErr}
			e.Journal = j
			authority := &diagnosticAuthority{}
			platform := &diagnosticPlatform{}
			e.Authority, e.Platform = authority, platform
			var checkpoints []string
			e.Checkpoint = func(name string) error { checkpoints = append(checkpoints, name); return nil }
			r, err := e.Apply(context.Background(), p)
			if !errors.Is(err, writeErr) || r.Phase != test.before || r.Outcome != "intervention_required" || r.Reason != "local-or-adapter-failure" || r.Health != "unknown" || r.PreviousRetired {
				t.Fatalf("failed checkpoint reported unconfirmed state: %+v, %v", r, err)
			}
			if j.rejected != 1 || j.latchedSaves != 1 || authority.issues != 0 || platform.observations != 0 || !reflect.DeepEqual(checkpoints, []string{string(test.before)}) {
				t.Fatalf("failed checkpoint advanced execution: rejected=%d latched=%d issues=%d observations=%d checkpoints=%v", j.rejected, j.latchedSaves, authority.issues, platform.observations, checkpoints)
			}
			after, err := durable.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			// Apply's initial write confirms the current clock floor and revision.
			before.ClockFloor = e.now()
			before.Revision++
			if !reflect.DeepEqual(after, before) || r.ActiveGeneration != Report(after).ActiveGeneration || r.TargetGeneration != p.TargetGeneration || r.OperationID != p.OperationID || r.PlanDigest != p.Digest {
				t.Fatal("failed writes changed the durable binding, checkpoint or outcome")
			}
		})
	}
}

func TestV1RejectedCheckpointAndFailureResultPreserveConfirmedSnapshot(t *testing.T) {
	e, _, durable, original := diagnosticFixture(t, device.KeyReady)
	confirmed, err := durable.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	writeErr := errors.New("checkpoint write failed")
	j := &diagnosticJournal{Journal: durable, reject: device.IssueIntent, writeErr: writeErr}
	e.Journal = j
	s, err := e.save(context.Background(), original, device.IssueIntent)
	if !errors.Is(err, writeErr) || !reflect.DeepEqual(s, confirmed) || !reflect.DeepEqual(original, confirmed) {
		t.Fatal("rejected checkpoint mutated or returned an unconfirmed snapshot")
	}
	r, err := e.failure(context.Background(), s, err)
	if !errors.Is(err, writeErr) || !reflect.DeepEqual(s, confirmed) || !reflect.DeepEqual(original, confirmed) || j.latchedSaves != 1 {
		t.Fatal("latched failure-result write mutated the confirmed snapshot")
	}
	after, err := durable.Load(context.Background())
	if err != nil || !reflect.DeepEqual(after, confirmed) || r.Phase != confirmed.Operation.Phase || r.Outcome != "intervention_required" || r.Reason != "local-or-adapter-failure" || Report(after).Outcome != "running" {
		t.Fatalf("receipt confused the failed attempt with durable history: %+v, %v", r, err)
	}
}
