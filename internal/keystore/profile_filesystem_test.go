// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
)

func TestV2FilesystemFaultMount(t *testing.T) {
	mode, root := filesystemEnvironment(t)
	ctx := context.Background()
	if mode == "setup" {
		f := newProfileFixture(t, credentialprofile.StableID)
		s := f.open(t, filepath.Join(root, "slots"))
		h, _, chain := f.prepare(t, s, "A", 1)
		if err := s.StoreCertificate(ctx, h, chain); err != nil {
			t.Fatal(err)
		}
		if err := s.ActivateV2(ctx, h, time.Now().Add(-100*time.Millisecond), time.Now().Add(100*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "snapshot.json"), f.snapshot.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if mode == "erofs" {
		data, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := device.DecodeSnapshot(data)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "slots")
		reader, err := OpenReadOnlyV2(path, snapshot.DeploymentID, snapshot.DeviceID, snapshot.Profile.ID, snapshot.Profile.Version, snapshot.Profile.PolicyDigest)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		active, err := reader.Active(ctx)
		if err != nil || active == nil || active.Binding.Generation != 1 {
			t.Fatalf("read-only mount lost its version-two active signer: %v", err)
		}
		if _, err := OpenV2(path, snapshot.DeploymentID, snapshot.DeviceID, snapshot.Profile.ID, snapshot.Profile.Version, snapshot.Profile.PolicyDigest); !errors.Is(err, syscall.EROFS) {
			t.Fatalf("expected actual Linux V2 EROFS, got %v", err)
		}
		if _, err := reader.Signer(ctx, *active); err != nil {
			t.Fatal("EROFS removed access to the version-two current signer")
		}
		activeIs(t, reader, *active)
		t.Log("observed actual Linux EROFS; V2 pointer, signer, CSR and public snapshot remain readable")
		return
	}
	for _, effect := range []string{"stage", "snapshot", "csr", "certificate", "activation", "destroy"} {
		t.Run(effect, func(t *testing.T) {
			f := newProfileFixture(t, credentialprofile.StableID)
			s := f.open(t, filepath.Join(root, effect))
			a, _, current := f.prepare(t, s, "A", 1)
			if err := s.StoreCertificate(ctx, a, current); err != nil {
				t.Fatal(err)
			}
			if err := s.ActivateV2(ctx, a, time.Now().Add(-100*time.Millisecond), time.Now().Add(100*time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var b device.Handle
			var csr, chain []byte
			if effect != "stage" {
				b = stage(t, s, f.plan(t, "B", 2).Binding())
				if effect != "snapshot" {
					if err := s.StoreSnapshot(ctx, b, f.snapshot.Bytes()); err != nil {
						t.Fatal(err)
					}
				}
				csr = f.csr(t, s, b)
				if effect != "snapshot" && effect != "csr" {
					if err := s.StoreCSR(ctx, b, csr); err != nil {
						t.Fatal(err)
					}
				}
				signer, err := s.Signer(ctx, b)
				if err != nil {
					t.Fatal(err)
				}
				chain = f.leaf(t, signer, b, 2, nil)
				if effect == "activation" || effect == "destroy" {
					if err := s.StoreCertificate(ctx, b, chain); err != nil {
						t.Fatal(err)
					}
				}
			}
			exhaustFilesystem(t, filepath.Join(root, "filler-v2-"+effect))
			var err error
			switch effect {
			case "stage":
				_, err = s.Stage(ctx, f.plan(t, "B", 2).Binding())
			case "snapshot":
				err = s.StoreSnapshot(ctx, b, f.snapshot.Bytes())
			case "csr":
				err = s.StoreCSR(ctx, b, csr)
			case "certificate":
				err = s.StoreCertificate(ctx, b, chain)
			case "activation":
				err = s.ActivateV2(ctx, b, time.Now().Add(-100*time.Millisecond), time.Now().Add(100*time.Millisecond))
			case "destroy":
				err = s.Destroy(ctx, b)
			}
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("expected actual Linux V2 %s ENOSPC, got %v", effect, err)
			}
			activeIs(t, s, a)
			if _, err := s.Signer(ctx, a); err != nil {
				t.Fatal("ENOSPC removed the current signer")
			}
			if got, err := s.Certificate(ctx, a); err != nil || !bytes.Equal(got, current) {
				t.Fatalf("ENOSPC changed current immutable certificate: %v", err)
			}
			if err := os.Remove(filepath.Join(root, "filler-v2-"+effect)); err != nil {
				t.Fatal(err)
			}
			if err := s.StoreSnapshot(ctx, a, f.snapshot.Bytes()); err == nil {
				t.Fatal("failed V2 writer resumed effects without reopening")
			}
			t.Logf("observed actual Linux V2 %s ENOSPC; generation one remains active and protected writes stay stopped", effect)
		})
	}
}
