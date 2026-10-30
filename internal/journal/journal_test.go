// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/internal/device"
	"modernc.org/sqlite"
)

func journalPath(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "state.db")
}

func openTest(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), path, "device-one")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func snapshot(t *testing.T, s *Store) device.State {
	t.Helper()
	state, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func planned(t *testing.T, generation uint64) *device.Operation {
	t.Helper()
	plan := device.Plan{APIVersion: "knowndevice/v1alpha1", OperationID: strings.Repeat("a", 32), DeviceID: "device-one", Mode: "enroll", TargetGeneration: generation, TargetSlot: "A", ConfigDigest: strings.Repeat("b", 64), ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	var err error
	plan.Digest, err = plan.CalculateDigest()
	if err != nil {
		t.Fatal(err)
	}
	return &device.Operation{Plan: plan, Phase: device.Planned, Outcome: "running"}
}

func TestRevisionFenceAndDurability(t *testing.T) {
	path := journalPath(t)
	s := openTest(t, path)
	initial := snapshot(t, s)
	if initial.Fence != 1 || initial.Revision != 1 || initial.Counter != 0 {
		t.Fatalf("unexpected initial state: %+v", initial)
	}
	var mode string
	var synchronization int
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("PRAGMA synchronous").Scan(&synchronization); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" || synchronization != 2 || s.db.Stats().MaxOpenConnections != 1 {
		t.Fatalf("unexpected SQLite settings: mode=%s sync=%d", mode, synchronization)
	}
	next := initial
	next.ClockFloor = time.Now().UTC()
	next.Counter = 1
	next.Operation = planned(t, 1)
	saved, err := s.Save(context.Background(), next, initial.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(context.Background(), next, initial.Revision); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("stale revision accepted: %v", err)
	}
	if got := snapshot(t, s); !reflect.DeepEqual(got, saved) {
		t.Fatalf("rejected update changed snapshot: %+v", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTest(t, path)
	current := snapshot(t, reopened)
	if current.Fence != saved.Fence+1 || current.Revision != saved.Revision+1 || current.Operation.Plan.Digest != saved.Operation.Plan.Digest {
		t.Fatalf("reopen did not fence durably: %+v", current)
	}
	saved.Revision = current.Revision
	if _, err := reopened.Save(context.Background(), saved, current.Revision); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("old writer fence accepted: %v", err)
	}
}

func TestIdentityCountersAndPublicMaterial(t *testing.T) {
	s := openTest(t, journalPath(t))
	state := snapshot(t, s)
	state.Counter = 1
	state.ClockFloor = time.Now().UTC()
	state.Operation = planned(t, 1)
	state, err := s.Save(context.Background(), state, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name string
		edit func(*device.State)
	}{
		{"device", func(s *device.State) { s.DeviceID = "device-two" }},
		{"counter", func(s *device.State) { s.Counter = 0 }},
		{"clock", func(s *device.State) { s.ClockFloor = s.ClockFloor.Add(-time.Second) }},
		{"plan", func(s *device.State) { s.Operation.Plan.ConfigDigest = strings.Repeat("c", 64) }},
		{"private-csr", func(s *device.State) {
			s.Operation.Target = &device.Handle{Binding: s.Operation.Plan.Binding(), PublicKeyDigest: strings.Repeat("e", 64)}
			s.Operation.CSR = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("private")})
		}},
		{"private-reason", func(s *device.State) { s.Operation.Reason = "-----BEGIN PRIVATE KEY-----" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			candidate := snapshot(t, s)
			test.edit(&candidate)
			if _, err := s.Save(context.Background(), candidate, candidate.Revision); err == nil {
				t.Fatal("unsafe state accepted")
			}
			if got := snapshot(t, s); !reflect.DeepEqual(got, state) {
				t.Fatal("unsafe update changed state")
			}
		})
	}
	state.Operation.Target = &device.Handle{Binding: state.Operation.Plan.Binding(), PublicKeyDigest: strings.Repeat("e", 64)}
	state.Operation.Phase = device.Committed
	state.Active = state.Operation.Target
	state, err = s.Save(context.Background(), state, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*device.State){
		func(s *device.State) { s.Active = nil },
		func(s *device.State) { h := *s.Active; h.PublicKeyDigest = strings.Repeat("f", 64); s.Active = &h },
		func(s *device.State) { s.Operation.Phase = device.Verified },
		func(s *device.State) { s.Operation = nil },
	} {
		candidate := snapshot(t, s)
		edit(&candidate)
		if _, err := s.Save(context.Background(), candidate, candidate.Revision); !errors.Is(err, device.ErrConflict) {
			t.Fatalf("unsafe active update accepted: %v", err)
		}
	}
}

func TestNewerSchemaRefusedWithoutMutation(t *testing.T) {
	path := journalPath(t)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := connect(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE future(value TEXT); INSERT INTO future VALUES('preserve'); PRAGMA user_version=2"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, "device-one"); !errors.Is(err, device.ErrUnsupported) {
		t.Fatalf("newer journal accepted: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("newer database was modified")
	}
	items, _ := os.ReadDir(filepath.Dir(path))
	if len(items) != 1 {
		t.Fatal("newer schema refusal created files")
	}
}

func TestIdentityMismatchRefusedWithoutMutation(t *testing.T) {
	path := journalPath(t)
	s := openTest(t, path)
	want := snapshot(t, s)
	s.Close()
	if _, err := Open(context.Background(), path, "device-two"); err == nil {
		t.Fatal("journal accepted another device identity")
	}
	got, err := Read(context.Background(), path, "device-one")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("identity refusal changed snapshot: %+v, %v", got, err)
	}
}

func TestReadHasNoMutation(t *testing.T) {
	path := journalPath(t)
	s := openTest(t, path)
	if _, err := Read(context.Background(), path, "device-one"); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("read did not fence active writer: %v", err)
	}
	want := snapshot(t, s)
	s.Close()
	files := func() map[string]string {
		items, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		result := map[string]string{}
		for _, item := range items {
			data, err := os.ReadFile(filepath.Join(filepath.Dir(path), item.Name()))
			if err != nil {
				t.Fatal(err)
			}
			result[item.Name()] = device.Hash(data)
		}
		return result
	}
	before := files()
	got, err := Read(context.Background(), path, "device-one")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(before, files()) {
		t.Fatal("read modified files or fencing")
	}
	missing := filepath.Join(filepath.Dir(path), "missing.db")
	if _, err := Read(context.Background(), missing, "device-one"); !os.IsNotExist(err) {
		t.Fatalf("missing read unexpectedly succeeded: %v", err)
	}
	if !reflect.DeepEqual(before, files()) {
		t.Fatal("missing read created files")
	}
}

func TestSQLiteReadOnlyAndFullStopWrites(t *testing.T) {
	t.Run("read-only", func(t *testing.T) {
		s := openTest(t, journalPath(t))
		before := snapshot(t, s)
		if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
			t.Fatal(err)
		}
		next := before
		next.ClockFloor = time.Now().UTC()
		_, err := s.Save(context.Background(), next, before.Revision)
		var sqliteError *sqlite.Error
		if !errors.As(err, &sqliteError) || sqliteError.Code()&255 != 8 {
			t.Fatalf("expected actual SQLite READONLY, got %v", err)
		}
		if got := snapshot(t, s); !reflect.DeepEqual(got, before) {
			t.Fatal("read-only write changed state")
		}
		if _, err := s.db.Exec("PRAGMA query_only=OFF"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Save(context.Background(), next, before.Revision); err == nil {
			t.Fatal("failed writer continued without reopening")
		}
	})
	t.Run("full", func(t *testing.T) {
		s := openTest(t, journalPath(t))
		before := snapshot(t, s)
		var pages int
		if err := s.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); err != nil {
			t.Fatal(err)
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public, _ := x509.MarshalPKIXPublicKey(key.Public())
		next := before
		next.Counter = 1
		next.Operation = planned(t, 1)
		next.Operation.Target = &device.Handle{Binding: next.Operation.Plan.Binding(), PublicKeyDigest: device.Hash(public)}
		subject := device.Subject("device-one", 1)
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: subject}, DNSNames: []string{subject}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ExtraExtensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}, Value: bytes.Repeat([]byte{0}, 16<<10)}}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		next.Operation.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		_, err = s.Save(context.Background(), next, before.Revision)
		var sqliteError *sqlite.Error
		if !errors.As(err, &sqliteError) || sqliteError.Code()&255 != 13 {
			t.Fatalf("expected actual SQLite FULL, got %v", err)
		}
		if got := snapshot(t, s); !reflect.DeepEqual(got, before) {
			t.Fatal("full write changed state")
		}
	})
}

func TestSymlinksPermissionsAndLockReplacement(t *testing.T) {
	path := journalPath(t)
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, "device-one"); err == nil {
		t.Fatal("insecure database permissions accepted")
	}
	os.Remove(path)
	outside := filepath.Join(filepath.Dir(path), "outside")
	os.WriteFile(outside, nil, 0o600)
	os.Symlink(outside, path)
	if _, err := Open(context.Background(), path, "device-one"); err == nil {
		t.Fatal("database symlink accepted")
	}
	os.Remove(path)
	s := openTest(t, path)
	old := snapshot(t, s)
	if err := os.Rename(path+".lock", path+".old-lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(context.Background(), old, old.Revision); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("replaced stable lock accepted: %v", err)
	}
}

func TestJournalHelperProcess(t *testing.T) {
	path := os.Getenv("KD_JOURNAL_HELPER")
	if path == "" {
		t.Skip("subprocess helper")
	}
	s, err := Open(context.Background(), path, "device-one")
	if err != nil {
		t.Fatal(err)
	}
	state, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state.Counter = 1
	state.Operation = planned(t, 1)
	if _, err := s.Save(context.Background(), state, state.Revision); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("KD_JOURNAL_FUTURE") == "1" {
		if _, err := s.db.Exec("PRAGMA user_version=2"); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("ready")
	time.Sleep(time.Hour)
}

func TestNewerWALSchemaRefusedWithoutDatabaseMutation(t *testing.T) {
	path := journalPath(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestJournalHelperProcess$")
	cmd.Env = append(os.Environ(), "KD_JOURNAL_HELPER="+path, "KD_JOURNAL_FUTURE=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- strings.TrimSpace(line) }()
	select {
	case line := <-ready:
		if line != "ready" {
			t.Fatalf("helper failed: %s", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper did not reach schema checkpoint")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("helper was not killed")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	walBefore, err := os.ReadFile(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, "device-one"); !errors.Is(err, device.ErrUnsupported) {
		t.Fatalf("newer WAL journal accepted: %v", err)
	}
	after, _ := os.ReadFile(path)
	walAfter, _ := os.ReadFile(path + "-wal")
	if !bytes.Equal(before, after) || !bytes.Equal(walBefore, walAfter) {
		t.Fatal("version refusal mutated the database or WAL")
	}
}

func TestSIGKILLReleasesProcessLockAndPreservesWAL(t *testing.T) {
	path := journalPath(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestJournalHelperProcess$")
	cmd.Env = append(os.Environ(), "KD_JOURNAL_HELPER="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- strings.TrimSpace(line) }()
	select {
	case line := <-ready:
		if line != "ready" {
			t.Fatalf("helper failed: %s %s", line, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper did not reach durable checkpoint")
	}
	if _, err := Open(context.Background(), path, "device-one"); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("second process obtained writer lock: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("helper was not killed")
	}
	read, err := Read(context.Background(), path, "device-one")
	if err != nil {
		t.Fatal(err)
	}
	if read.Counter != 1 || read.Fence != 1 || read.Operation.Phase != device.Planned {
		t.Fatalf("killed writer lost committed WAL: %+v", read)
	}
	reopened := openTest(t, path)
	state := snapshot(t, reopened)
	if state.Counter != 1 || state.Fence != 2 || state.Operation.Plan.Digest != read.Operation.Plan.Digest {
		t.Fatalf("restart lost state or fencing: %+v", state)
	}
}
