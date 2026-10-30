// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
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
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/internal/device"
	"knowndevice.local/knowndevice/internal/journal"
)

func TestRecoveredPEMWhitespaceAndBinding(t *testing.T) {
	now := time.Now().UTC()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	subject := device.Subject("gateway-1", 2)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: subject}, DNSNames: []string{subject}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err = x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if _, err := ValidateChain(append(append([]byte("\n"), chain...), '\n', '\n'), key, subject, roots, now); err != nil {
		t.Fatalf("valid recovered PEM whitespace rejected: %v", err)
	}
	for _, invalid := range [][]byte{append([]byte("junk\n"), chain...), append(append([]byte(nil), chain...), []byte("junk")...)} {
		if _, err := ValidateChain(invalid, key, subject, roots, now); !errors.Is(err, device.ErrDenied) {
			t.Fatal("non-PEM data accepted")
		}
	}
	if _, err := ValidateChain(chain, rootKey, subject, roots, now); !errors.Is(err, device.ErrDenied) {
		t.Fatal("different signer accepted")
	}
	if _, err := ValidateChain(chain, key, device.Subject("gateway-1", 1), roots, now); !errors.Is(err, device.ErrDenied) {
		t.Fatal("different generation accepted")
	}
	if _, err := ValidateChain(chain, key, subject, nil, now); !errors.Is(err, device.ErrDenied) {
		t.Fatal("implicit system roots accepted")
	}
}

func TestExpiredUnfinishedPlanPreservesIntentWithoutEffects(t *testing.T) {
	ctx := context.Background()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := journal.Open(ctx, filepath.Join(dir, "journal.db"), "gateway-1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	p := device.Plan{APIVersion: "knowndevice/v1alpha1", OperationID: strings.Repeat("a", 32), DeviceID: s.DeviceID, Mode: "enroll", TargetGeneration: 1, TargetSlot: "A", ConfigDigest: strings.Repeat("b", 64), ExpiresAt: now.Add(time.Second)}
	p.Digest, _ = p.CalculateDigest()
	s.Counter = 1
	s.ClockFloor = now
	s.Operation = &device.Operation{Plan: p, Phase: device.Planned, Outcome: "running"}
	s, err = store.Save(ctx, s, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	e := Engine{Config: device.Config{ClockTrust: "trusted-system-clock"}, Journal: store, Now: func() time.Time { return p.ExpiresAt.Add(time.Second) }}
	r, err := e.Apply(ctx, p)
	if !errors.Is(err, device.ErrPlanExpired) || r.Outcome != "intervention_required" || r.Reason != "plan-expired-intervention-required" || r.Phase != device.Planned {
		t.Fatalf("expired operation reported %v, %+v", err, r)
	}
	after, err := store.Load(ctx)
	if err != nil || after.Counter != s.Counter || after.Operation.Plan != p || after.Operation.Target != nil || after.Active != nil {
		t.Fatal("expired plan lost intent or created material")
	}
	if _, err := NewPlan(device.Config{DeviceID: s.DeviceID}, after, "enroll", now); err == nil {
		t.Fatal("expired unfinished operation was superseded")
	}
}

type completedSnapshot struct{ state device.State }

func (s *completedSnapshot) Load(context.Context) (device.State, error) { return s.state, nil }
func (*completedSnapshot) Save(context.Context, device.State, uint64) (device.State, error) {
	panic("completed history must not be mutated after its deadline")
}
func (*completedSnapshot) Close() error { return nil }

func TestCompletedPlanExpiryKeepsHistoricalOutcomeAndUnknownHealth(t *testing.T) {
	now := time.Now().UTC()
	p := device.Plan{APIVersion: "knowndevice/v1alpha1", OperationID: strings.Repeat("a", 32), DeviceID: "gateway-1", Mode: "enroll", TargetGeneration: 1, TargetSlot: "A", ConfigDigest: strings.Repeat("b", 64), ExpiresAt: now.Add(-time.Second)}
	p.Digest, _ = p.CalculateDigest()
	j := &completedSnapshot{state: device.State{DeviceID: p.DeviceID, Counter: 1, Operation: &device.Operation{Plan: p, Phase: device.Retired, Outcome: "succeeded"}}}
	e := Engine{Config: device.Config{ClockTrust: "trusted-system-clock"}, Journal: j, Now: func() time.Time { return now }}
	r, err := e.Apply(context.Background(), p)
	if err != nil || r.Outcome != "succeeded" || r.Phase != device.Retired || r.Health != "unknown" || r.Reason != "" || j.state.Operation.Outcome != "succeeded" {
		t.Fatalf("completed history changed on expiry: %+v, %v", r, err)
	}
}
