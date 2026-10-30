// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/internal/device"
)

func keyPath(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "keys")
}

func keyStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func bind(slot string, generation uint64) device.Binding {
	id := "a"
	if slot == "B" {
		id = "b"
	}
	if generation > 2 {
		id = "c"
	}
	return device.Binding{DeviceID: "device-one", OperationID: strings.Repeat(id, 32), Generation: generation, Slot: slot}
}

func stage(t *testing.T, s *Store, b device.Binding) device.Handle {
	t.Helper()
	h, err := s.Stage(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func certificate(t *testing.T, s *Store, h device.Handle, serial int64) []byte {
	t.Helper()
	signer, err := s.Signer(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	subject := device.Subject(h.Binding.DeviceID, h.Binding.Generation)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: subject}, DNSNames: []string{subject}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func certify(t *testing.T, s *Store, h device.Handle) []byte {
	t.Helper()
	chain := certificate(t, s, h, int64(h.Binding.Generation))
	if err := s.StoreCertificate(context.Background(), h, chain); err != nil {
		t.Fatal(err)
	}
	return chain
}

func activate(t *testing.T, s *Store, h device.Handle) {
	t.Helper()
	if err := s.Activate(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func activeIs(t *testing.T, s *Store, h device.Handle) {
	t.Helper()
	active, err := s.Active(context.Background())
	if err != nil || active == nil || *active != h {
		t.Fatalf("unexpected active handle: %v, %v", active, err)
	}
}

func TestSignerBoundaryAndImmutableBinding(t *testing.T) {
	path := keyPath(t)
	s := keyStore(t, path)
	h := stage(t, s, bind("A", 1))
	if got := stage(t, s, bind("A", 1)); got != h {
		t.Fatal("duplicate stage changed the signing key")
	}
	signer, err := s.Signer(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if _, exposed := signer.(*ecdsa.PrivateKey); exposed {
		t.Fatal("private scalar escaped the signer boundary")
	}
	public := signer.Public().(*ecdsa.PublicKey)
	public.X.SetInt64(0)
	public = signer.Public().(*ecdsa.PublicKey)
	digest := sha256.Sum256([]byte("public challenge"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(public, digest[:], signature) {
		t.Fatalf("opaque signer failed: %v", err)
	}
	conflicting := bind("A", 3)
	if _, err := s.Stage(context.Background(), conflicting); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("occupied slot was overwritten: %v", err)
	}
	otherDevice := bind("B", 2)
	otherDevice.DeviceID = "device-two"
	if _, err := s.Stage(context.Background(), otherDevice); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("key store accepted another device: %v", err)
	}
	spoof := h
	spoof.PublicKeyDigest = strings.Repeat("c", 64)
	if _, err := s.Signer(context.Background(), spoof); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("spoofed handle accepted: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := keyStore(t, path)
	if got := stage(t, reopened, h.Binding); got != h {
		t.Fatal("restart changed staged signing key")
	}
}

func TestCertificateActivationAndEffectiveDestruction(t *testing.T) {
	s := keyStore(t, keyPath(t))
	a := stage(t, s, bind("A", 1))
	if err := s.Activate(context.Background(), a); err == nil {
		t.Fatal("uncertified slot became active")
	}
	chain := certify(t, s, a)
	if err := s.StoreCertificate(context.Background(), a, chain); err != nil {
		t.Fatal(err)
	}
	if err := s.StoreCertificate(context.Background(), a, certificate(t, s, a, 100)); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("immutable certificate changed: %v", err)
	}
	activate(t, s, a)
	if err := s.Destroy(context.Background(), a); !errors.Is(err, device.ErrDenied) {
		t.Fatalf("active key was destroyed: %v", err)
	}
	b := stage(t, s, bind("B", 2))
	if err := s.StoreCertificate(context.Background(), b, chain); err == nil {
		t.Fatal("another generation's certificate was stored")
	}
	if err := s.StoreCertificate(context.Background(), b, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("private")})); err == nil {
		t.Fatal("private material accepted as certificate")
	}
	certify(t, s, b)
	activate(t, s, b)
	if err := s.Activate(context.Background(), a); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("retired generation was reactivated: %v", err)
	}
	if err := s.Destroy(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if err := s.Destroy(context.Background(), a); err != nil {
		t.Fatalf("exact destruction binding did not reconcile: %v", err)
	}
	if _, err := s.Signer(context.Background(), a); err == nil {
		t.Fatal("destroyed key remained available")
	}
	if _, err := s.Stage(context.Background(), a.Binding); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("destroyed generation was recreated: %v", err)
	}
	c := stage(t, s, bind("A", 3))
	if err := s.Destroy(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Signer(context.Background(), c); err != nil {
		t.Fatal("old destroy removed a reused slot")
	}
	activeIs(t, s, b)
	missing := device.Handle{Binding: bind("B", 99), PublicKeyDigest: strings.Repeat("e", 64)}
	missing.Binding.Slot = "A"
	if err := s.Destroy(context.Background(), missing); err == nil {
		t.Fatal("arbitrary missing binding was accepted as destroyed")
	}
}

func TestActiveCertificateGapStopsDestruction(t *testing.T) {
	path := keyPath(t)
	s := keyStore(t, path)
	a := stage(t, s, bind("A", 1))
	chain := certify(t, s, a)
	activate(t, s, a)
	b := stage(t, s, bind("B", 2))
	if err := os.Remove(filepath.Join(path, "A", "certificate.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Active(context.Background()); err == nil {
		t.Fatal("active pointer with missing certificate was accepted")
	}
	if err := s.Destroy(context.Background(), b); err == nil {
		t.Fatal("destruction continued through an inconsistent active pointer")
	}
	if err := s.StoreCertificate(context.Background(), a, chain); err != nil {
		t.Fatal(err)
	}
	activeIs(t, s, a)
}

func TestMissingDeviceBindingDoesNotRebindExistingKeys(t *testing.T) {
	path := keyPath(t)
	s := keyStore(t, path)
	a := stage(t, s, bind("A", 1))
	if err := os.Remove(filepath.Join(path, ".device.json")); err != nil {
		t.Fatal(err)
	}
	other := bind("B", 2)
	other.DeviceID = "device-two"
	if _, err := s.Stage(context.Background(), other); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("existing keys were rebound after identity loss: %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, ".device.json")); !os.IsNotExist(err) {
		t.Fatalf("failed reconciliation created an identity: %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, "A", "key.pem")); err != nil {
		t.Fatal("identity reconciliation removed the last key")
	}
	if a.Binding.DeviceID != "device-one" {
		t.Fatal("existing binding changed")
	}
}

func TestFreshSlotCannotReuseGeneration(t *testing.T) {
	s := keyStore(t, keyPath(t))
	stage(t, s, bind("A", 1))
	if _, err := s.Stage(context.Background(), bind("B", 1)); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("fresh slot reused an observed generation: %v", err)
	}
}

func TestPublicMetadataRejectsUnknownAndTrailingData(t *testing.T) {
	path := keyPath(t)
	s := keyStore(t, path)
	a := stage(t, s, bind("A", 1))
	certify(t, s, a)
	activate(t, s, a)
	name := filepath.Join(path, "active.json")
	original, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"\n{}", "\ninvalid"} {
		if err := os.WriteFile(name, append(append([]byte{}, original...), []byte(suffix)...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Active(context.Background()); err == nil {
			t.Fatal("trailing pointer data was accepted")
		}
	}
	if err := os.WriteFile(name, original, 0o600); err != nil {
		t.Fatal(err)
	}
	activeIs(t, s, a)
}

func TestReadOnlyAndRecoverySigner(t *testing.T) {
	path := keyPath(t)
	s := keyStore(t, path)
	a := stage(t, s, bind("A", 1))
	chain := certify(t, s, a)
	activate(t, s, a)
	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	activeIs(t, reader, a)
	if got, err := reader.Certificate(context.Background(), a); err != nil || !bytes.Equal(got, chain) {
		t.Fatalf("read-only public chain failed: %v", err)
	}
	if _, err := reader.Signer(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func() error{
		func() error { _, err := reader.Stage(context.Background(), bind("B", 2)); return err },
		func() error { return reader.StoreCertificate(context.Background(), a, chain) },
		func() error { return reader.Activate(context.Background(), a) },
		func() error { return reader.Destroy(context.Background(), a) },
	} {
		if err := mutate(); !errors.Is(err, device.ErrDenied) {
			t.Fatalf("read-only mutation accepted: %v", err)
		}
	}
	credential, err := LoadCredential(filepath.Join(path, "A", "certificate.pem"), filepath.Join(path, "A", "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, exposed := credential.PrivateKey.(*ecdsa.PrivateKey); exposed {
		t.Fatal("recovery loader exposed private scalar")
	}
	if _, err := LoadCredential(filepath.Join(path, "A", "certificate.pem"), filepath.Join(path, "B", "key.pem")); err == nil {
		t.Fatal("recovery loader accepted paths across roots")
	}
	before, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReadOnly(filepath.Join(filepath.Dir(path), "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing read-only open unexpectedly succeeded: %v", err)
	}
	after, _ := os.ReadDir(filepath.Dir(path))
	if len(before) != len(after) {
		t.Fatal("read-only open created a directory")
	}
}

func TestSymlinkAndPermissionRefusal(t *testing.T) {
	path := keyPath(t)
	s := keyStore(t, path)
	a := stage(t, s, bind("A", 1))
	keyName := filepath.Join(path, "A", "key.pem")
	if err := os.Chmod(keyName, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Signer(context.Background(), a); err == nil {
		t.Fatal("world-readable key accepted")
	}
	os.Chmod(keyName, 0o600)
	if err := os.Rename(keyName, keyName+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("key.pem.old", keyName); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Signer(context.Background(), a); err == nil {
		t.Fatal("key symlink accepted")
	}
	if err := os.Symlink(path, path+"-link"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path + "-link"); err == nil {
		t.Fatal("root symlink accepted")
	}
	os.Remove(keyName)
	os.Rename(keyName+".old", keyName)
	if err := os.Rename(filepath.Join(path, ".lock"), filepath.Join(path, ".old-lock")); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(path, ".lock"), nil, 0o600)
	if _, err := s.Stage(context.Background(), bind("B", 2)); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("replaced stable lock accepted: %v", err)
	}
}

type helperInput struct {
	Root        string
	Action      string
	Checkpoint  string
	Handle      device.Handle
	Binding     device.Binding
	Certificate []byte
}

func TestKeyStoreHelperProcess(t *testing.T) {
	path := os.Getenv("KD_KEYSTORE_HELPER")
	if path == "" {
		t.Skip("subprocess helper")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var input helperInput
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	s, err := Open(input.Root)
	if err != nil {
		t.Fatal(err)
	}
	s.checkpoint = func(name string) {
		if name == input.Checkpoint {
			fmt.Println("checkpoint:" + name)
			time.Sleep(time.Hour)
		}
	}
	switch input.Action {
	case "stage":
		_, err = s.Stage(context.Background(), input.Binding)
	case "cert":
		err = s.StoreCertificate(context.Background(), input.Handle, input.Certificate)
	case "activate":
		err = s.Activate(context.Background(), input.Handle)
	case "destroy":
		err = s.Destroy(context.Background(), input.Handle)
	default:
		t.Fatal("unknown helper action")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("helper did not reach checkpoint")
}

func killAt(t *testing.T, input helperInput) {
	t.Helper()
	data, _ := json.Marshal(input)
	path := filepath.Join(filepath.Dir(input.Root), "helper-input.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestKeyStoreHelperProcess$")
	cmd.Env = append(os.Environ(), "KD_KEYSTORE_HELPER="+path)
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
		if line != "checkpoint:"+input.Checkpoint {
			t.Fatalf("helper failed: %s %s", line, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper did not reach filesystem checkpoint")
	}
	reader, err := OpenReadOnly(input.Root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Active(context.Background()); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("second process crossed slot mutation lock: %v", err)
	}
	reader.Close()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("helper was not killed")
	}
}

func TestSIGKILLSlotCheckpoints(t *testing.T) {
	cases := []struct {
		action      string
		checkpoints []string
	}{
		{"stage", []string{"stage-binding", "stage-key", "stage-manifest", "stage-directory", "stage-rename", "stage-parent"}},
		{"cert", []string{"cert-file", "cert-rename", "cert-parent"}},
		{"activate", []string{"active-file", "active-rename", "active-parent"}},
		{"destroy", []string{"destroy-intent", "destroy-rename", "destroy-parent", "destroy-key", "destroy-manifest", "destroy-complete"}},
	}
	for _, group := range cases {
		for _, checkpoint := range group.checkpoints {
			t.Run(checkpoint, func(t *testing.T) {
				path := keyPath(t)
				s := keyStore(t, path)
				a := stage(t, s, bind("A", 1))
				certify(t, s, a)
				activate(t, s, a)
				input := helperInput{Root: path, Action: group.action, Checkpoint: checkpoint, Binding: bind("B", 2)}
				var b device.Handle
				if group.action != "stage" {
					b = stage(t, s, bind("B", 2))
					input.Handle = b
					input.Certificate = certificate(t, s, b, 2)
					if group.action != "cert" {
						if err := s.StoreCertificate(context.Background(), b, input.Certificate); err != nil {
							t.Fatal(err)
						}
					}
					if group.action == "destroy" {
						activate(t, s, b)
						input.Handle = a
					}
				}
				s.Close()
				killAt(t, input)
				restarted := keyStore(t, path)
				switch group.action {
				case "stage":
					activeIs(t, restarted, a)
					recovered := stage(t, restarted, input.Binding)
					if recovered.Binding != input.Binding {
						t.Fatal("stage restart changed binding")
					}
				case "cert":
					activeIs(t, restarted, a)
					if err := restarted.StoreCertificate(context.Background(), b, input.Certificate); err != nil {
						t.Fatal(err)
					}
				case "activate":
					if checkpoint == "active-file" {
						activeIs(t, restarted, a)
					} else {
						activeIs(t, restarted, b)
					}
					activate(t, restarted, b)
					activeIs(t, restarted, b)
					if _, err := restarted.Signer(context.Background(), a); err != nil {
						t.Fatal("activation crash lost previous signer")
					}
				case "destroy":
					activeIs(t, restarted, b)
					if err := restarted.Destroy(context.Background(), a); err != nil {
						t.Fatal(err)
					}
					if err := restarted.Destroy(context.Background(), a); err != nil {
						t.Fatal("destruction ack did not survive restart")
					}
					if _, err := restarted.Signer(context.Background(), b); err != nil {
						t.Fatal("destruction crash lost active signer")
					}
				}
			})
		}
	}
}

func TestDirectoryWriteDenialKeepsActiveGeneration(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permission")
	}
	path := keyPath(t)
	s := keyStore(t, path)
	a := stage(t, s, bind("A", 1))
	certify(t, s, a)
	activate(t, s, a)
	s.checkpoint = func(checkpoint string) {
		if checkpoint == "stage-precreate" {
			if err := os.Chmod(path, 0o500); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { os.Chmod(path, 0o700) })
	if _, err := s.Stage(context.Background(), bind("B", 2)); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected actual filesystem write denial, got %v", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	s.checkpoint = nil
	activeIs(t, s, a)
}
