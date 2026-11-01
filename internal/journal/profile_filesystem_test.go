// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
	"github.com/knowndevice/knowndevice/internal/keystore"
	"modernc.org/sqlite"
)

func currentV2FilesystemDevice(t *testing.T, root string) (*Store, *keystore.Store, device.Handle) {
	t.Helper()
	ctx := context.Background()
	f := newJournalProfileFixture(t, credentialprofile.StableID)
	s := f.open(t, filepath.Join(root, "state.db"))
	state := snapshot(t, s)
	state.Counter, state.Operation = 1, f.operation(t, 1)
	var err error
	state, err = s.Save(ctx, state, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keystore.OpenV2(filepath.Join(root, "keys"), f.snapshot.DeploymentID, f.snapshot.DeviceID, f.snapshot.Profile.ID, f.snapshot.Profile.Version, f.snapshot.Profile.PolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.Close() })
	h, err := keys.Stage(ctx, state.Operation.Plan.Binding())
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.StoreSnapshot(ctx, h, f.snapshot.Bytes()); err != nil {
		t.Fatal(err)
	}
	signer, err := keys.Signer(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := f.snapshot.Profile.CreateCSR(signer, h.Binding.DeviceID, h.Binding.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.StoreCSR(ctx, h, csr); err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: f.snapshot.Profile.Subject(h.Binding.DeviceID, h.Binding.Generation)}, NotBefore: time.Now().Add(-time.Second), NotAfter: time.Now().Add(10 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, f.ca, signer.Public(), f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})...)
	if err := keys.StoreCertificate(ctx, h, chain); err != nil {
		t.Fatal(err)
	}
	if err := keys.ActivateV2(ctx, h, time.Now().Add(-100*time.Millisecond), time.Now().Add(100*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	state.Operation.Target, state.Operation.CSR, state.Operation.Certificate = &h, csr, chain
	state.Operation.Activation = f.activation(t, state.Operation, "b")
	state.Operation.Phase, state.Active = device.Committed, &h
	if _, err := s.Save(ctx, state, state.Revision); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "snapshot.json"), f.snapshot.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return s, keys, h
}

func TestV2FilesystemFaultMount(t *testing.T) {
	mode, root := filesystemEnvironment(t)
	ctx := context.Background()
	if mode == "setup" {
		currentV2FilesystemDevice(t, root)
		return
	}
	path := filepath.Join(root, "state.db")
	if mode == "erofs" {
		data, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := device.DecodeSnapshot(data)
		if err != nil {
			t.Fatal(err)
		}
		p := snapshot.Profile
		before, err := ReadV2(ctx, path, snapshot.DeploymentID, snapshot.DeviceID, p.ID, p.Version, p.PolicyDigest)
		if err != nil || before.Active == nil || before.Active.Binding.Generation != 1 {
			t.Fatalf("read-only V2 journal lost the current snapshot: %v", err)
		}
		if _, err := OpenV2(ctx, path, snapshot.DeploymentID, snapshot.DeviceID, p.ID, p.Version, p.PolicyDigest); !errors.Is(err, syscall.EROFS) {
			t.Fatalf("expected actual Linux V2 EROFS, got %v", err)
		}
		after, err := ReadV2(ctx, path, snapshot.DeploymentID, snapshot.DeviceID, p.ID, p.Version, p.PolicyDigest)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("EROFS changed V2 counters, fence or immutable intent: %v", err)
		}
		t.Log("observed actual Linux EROFS; V2 journal and its public artifacts remain unchanged/readable")
		return
	}
	s, keys, current := currentV2FilesystemDevice(t, root)
	before := snapshot(t, s)
	filler := filepath.Join(root, "filler-v2-journal")
	exhaustFilesystem(t, filler)
	next := before
	next.ClockFloor = time.Now().UTC()
	_, err := s.Save(ctx, next, next.Revision)
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) || sqliteErr.Code()&255 != 13 {
		t.Fatalf("expected actual SQLite V2 FULL on exhausted Linux tmpfs, got %v", err)
	}
	if !reflect.DeepEqual(before, snapshot(t, s)) {
		t.Fatal("FULL changed V2 active generation, intent or counters")
	}
	if active, err := keys.Active(ctx); err != nil || active == nil || *active != current {
		t.Fatalf("FULL lost the V2 active signer: %v", err)
	}
	if err := os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(ctx, next, next.Revision); err == nil {
		t.Fatal("failed V2 writer resumed without reopening")
	}
	t.Log("observed Linux ENOSPC plus SQLite V2 FULL; current generation remains usable and writes stay stopped")
}
