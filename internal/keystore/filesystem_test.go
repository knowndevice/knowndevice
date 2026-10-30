// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"knowndevice.local/knowndevice/internal/device"
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
	if mode == "setup" {
		s := keyStore(t, root)
		a := stage(t, s, bind("A", 1))
		certify(t, s, a)
		activate(t, s, a)
		return
	}
	if mode == "erofs" {
		reader, err := OpenReadOnly(root)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		active, err := reader.Active(ctx)
		if err != nil || active == nil || active.Binding.Generation != 1 {
			t.Fatalf("read-only mount lost its active signer: %v", err)
		}
		if _, err := Open(root); !errors.Is(err, syscall.EROFS) {
			t.Fatalf("expected actual read-only mount EROFS, got %v", err)
		}
		activeIs(t, reader, *active)
		if _, err := reader.Signer(ctx, *active); err != nil {
			t.Fatal("read-only mount lost access to the last signer")
		}
		t.Log("observed Linux open errno EROFS; current signer remains readable")
		return
	}
	for _, effect := range []string{"stage", "certificate"} {
		t.Run(effect, func(t *testing.T) {
			s := keyStore(t, filepath.Join(root, effect))
			a := stage(t, s, bind("A", 1))
			original := certify(t, s, a)
			activate(t, s, a)
			var b device.Handle
			var chain []byte
			if effect == "certificate" {
				b = stage(t, s, bind("B", 2))
				chain = certificate(t, s, b, 2)
			}
			exhaustFilesystem(t, filepath.Join(root, "filler-"+effect))
			var err error
			if effect == "stage" {
				_, err = s.Stage(ctx, bind("B", 2))
			} else {
				err = s.StoreCertificate(ctx, b, chain)
			}
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("expected actual slot %s ENOSPC, got %v", effect, err)
			}
			activeIs(t, s, a)
			if _, err := s.Signer(ctx, a); err != nil {
				t.Fatal("ENOSPC removed the last active signer")
			}
			if got, err := s.Certificate(ctx, a); err != nil || !bytes.Equal(got, original) {
				t.Fatalf("ENOSPC changed the active certificate: %v", err)
			}
			if effect == "certificate" {
				if err := s.Activate(ctx, b); err == nil {
					t.Fatal("activation continued after certificate storage failed")
				}
				activeIs(t, s, a)
			}
			t.Logf("observed Linux slot %s errno ENOSPC; active generation remains one", effect)
		})
	}
}
