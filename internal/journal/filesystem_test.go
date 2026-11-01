// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/internal/device"
	"github.com/knowndevice/knowndevice/internal/keystore"
	"modernc.org/sqlite"
)

func filesystemEnvironment(t *testing.T) (string, string) {
	t.Helper()
	mode, root := os.Getenv("KD_FS_FAULT"), os.Getenv("KD_FS_ROOT")
	if mode == "" {
		t.Skip("requires KD_FS_FAULT and an isolated Linux tmpfs or read-only bind mount")
	}
	if runtime.GOOS != "linux" || !filepath.IsAbs(root) || root == "/" || (mode != "setup" && mode != "enospc" && mode != "erofs") {
		t.Fatal("invalid filesystem fault environment")
	}
	return mode, root
}

func currentFilesystemDevice(t *testing.T, root string) (*Store, *keystore.Store, device.Handle) {
	t.Helper()
	ctx := context.Background()
	s := openTest(t, filepath.Join(root, "state.db"))
	state := snapshot(t, s)
	state.Counter = 1
	state.Operation = planned(t, 1)
	var err error
	state, err = s.Save(ctx, state, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keystore.Open(filepath.Join(root, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.Close() })
	h, err := keys.Stage(ctx, state.Operation.Plan.Binding())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := keys.Signer(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	subject := device.Subject(h.Binding.DeviceID, h.Binding.Generation)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: subject}, DNSNames: []string{subject}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := keys.StoreCertificate(ctx, h, chain); err != nil {
		t.Fatal(err)
	}
	if err := keys.Activate(ctx, h); err != nil {
		t.Fatal(err)
	}
	state.Operation.Target = &h
	state.Operation.Certificate = chain
	state.Operation.Phase = device.Committed
	state.Active = &h
	if _, err := s.Save(ctx, state, state.Revision); err != nil {
		t.Fatal(err)
	}
	return s, keys, h
}

func exhaustFilesystem(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	block := make([]byte, 4096)
	for written := 0; written < 16<<20; written += len(block) {
		_, err = f.Write(block)
		if err != nil {
			break
		}
	}
	f.Close()
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("expected an actual bounded tmpfs ENOSPC, got %v", err)
	}
	t.Log("observed Linux write errno ENOSPC on the bounded tmpfs")
}

func TestFilesystemFaultMount(t *testing.T) {
	mode, root := filesystemEnvironment(t)
	ctx := context.Background()
	path := filepath.Join(root, "state.db")
	if mode == "setup" {
		currentFilesystemDevice(t, root)
		return
	}
	if mode == "erofs" {
		before, err := Read(ctx, path, "device-one")
		if err != nil || before.Active == nil || before.Active.Binding.Generation != 1 {
			t.Fatalf("read-only mount lost current journal: %v", err)
		}
		if _, err := Open(ctx, path, "device-one"); !errors.Is(err, syscall.EROFS) {
			t.Fatalf("expected actual read-only mount EROFS, got %v", err)
		}
		after, err := Read(ctx, path, "device-one")
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("EROFS changed journal revision/fence: %v", err)
		}
		keys, err := keystore.OpenReadOnly(filepath.Join(root, "keys"))
		if err != nil {
			t.Fatal(err)
		}
		defer keys.Close()
		if _, err := keys.Signer(ctx, *before.Active); err != nil {
			t.Fatal("read-only mount lost the current signer")
		}
		t.Log("observed Linux open errno EROFS; current journal and signer remain readable")
		return
	}
	s, keys, current := currentFilesystemDevice(t, root)
	before := snapshot(t, s)
	filler := filepath.Join(root, "filler")
	exhaustFilesystem(t, filler)
	candidate := before
	candidate.ClockFloor = time.Now().UTC()
	_, err := s.Save(ctx, candidate, before.Revision)
	var sqliteError *sqlite.Error
	if !errors.As(err, &sqliteError) || sqliteError.Code()&255 != 13 {
		t.Fatalf("expected actual SQLite FULL on exhausted tmpfs, got %v", err)
	}
	if got := snapshot(t, s); !reflect.DeepEqual(got, before) {
		t.Fatal("filesystem ENOSPC changed the journal snapshot")
	}
	if err := os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(ctx, candidate, before.Revision); err == nil {
		t.Fatal("failed writer continued after ENOSPC without reopening")
	}
	active, err := keys.Active(ctx)
	if err != nil || active == nil || *active != current {
		t.Fatalf("ENOSPC lost the current active signer: %v", err)
	}
	signer, err := keys.Signer(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("current signer after filesystem failure"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatal("current signer stopped signing after journal ENOSPC")
	}
	s.Close()
	restarted := openTest(t, path)
	after := snapshot(t, restarted)
	if after.Active == nil || *after.Active != current || after.Revision != before.Revision+1 || after.Fence != before.Fence+1 {
		t.Fatal("ENOSPC restart lost the current generation or fencing")
	}
	t.Log("observed SQLite FULL on actual tmpfs ENOSPC; writer stopped and restart preserved generation one")
}
