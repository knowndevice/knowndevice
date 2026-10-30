// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/internal/credentialprofile"
	"knowndevice.local/knowndevice/internal/device"
)

type profileFixture struct {
	snapshot *device.PublicSnapshot
	issuer   *ecdsa.PrivateKey
	ca       *x509.Certificate
}

func newProfileFixture(t *testing.T, id string) profileFixture {
	t.Helper()
	policy, err := credentialprofile.Find(id, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := &device.PublicSnapshot{APIVersion: device.V2, EncodingVersion: 2, DeploymentID: "storage-lab", DeviceID: "device-one", Profile: policy, RecoveryIdentity: device.RecoverySubject("device-one"), RecoveryLeafPin: device.Hash([]byte("recovery-leaf")), RecoverySPKIPin: device.Hash([]byte("recovery-spki")), Limits: device.DefaultLimits(), RequestTimeoutSeconds: 5, PlanTTLSeconds: 600, ClockTrust: "trusted-system-clock"}
	s.Composition = device.Composition{ID: "local-http-lab", Version: 1, AuthorityTemplateDigest: device.Hash([]byte("fixture-template")), ApplicationID: "worker", SessionPolicy: "new-connection-no-state-transfer", ObservationRoute: "authenticated-application-callback", WithdrawalScope: "whole-service-lab"}
	capabilities := map[string]string{"entitlement": "current-entitlement", "authority": "bounded-unknown-issuance", "platform": "exact-peer-binding", "transport": "explicit-access-observation", "application": "durable-activation-and-fresh-observation", "clock": "bounded-interval", "withdrawal": "durable-deny-and-session-inventory"}
	for role, capability := range capabilities {
		s.Composition.Adapters = append(s.Composition.Adapters, device.AdapterSpec{Role: role, ID: "local-http-lab-" + role, Version: "1", ArtifactDigest: device.Hash([]byte(role)), Capabilities: []string{capability}})
	}
	sort.Slice(s.Composition.Adapters, func(i, j int) bool { return s.Composition.Adapters[i].Role < s.Composition.Adapters[j].Role })
	f := profileFixture{snapshot: s}
	for i, role := range []string{"application", "control", "issuance", "observer", "operational", "recovery", "transport"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "fixture-" + role}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		trust := device.RoleSnapshot{Role: role, Anchors: [][]byte{der}}
		if role == "issuance" {
			trust.CallerSPKIPins = []string{device.Hash([]byte("control-provisioner"))}
		}
		if role == "operational" {
			trust.AllowedIssuers = []string{device.Hash(der)}
			f.issuer, f.ca = key, cert
		} else if role == "observer" {
			trust.PeerName = "observer.invalid"
			trust.LeafPins = []string{device.Hash([]byte(role + "-leaf"))}
		} else if role != "recovery" {
			trust.Endpoint = "https://" + role + ".invalid:9443"
			trust.PeerName = role + ".invalid"
			trust.LeafPins = []string{device.Hash([]byte(role + "-leaf"))}
		}
		s.Trust = append(s.Trust, trust)
	}
	s.Trust = append(s.Trust, device.RoleSnapshot{Role: "authority-transport", Endpoint: "https://step-ca:9000", PeerName: "step-ca", Anchors: [][]byte{f.ca.Raw}, LeafPins: []string{device.Hash([]byte("authority-transport-leaf"))}})
	sort.Slice(s.Trust, func(i, j int) bool { return s.Trust[i].Role < s.Trust[j].Role })
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f profileFixture) plan(t *testing.T, slot string, generation uint64) device.Plan {
	t.Helper()
	p := device.Plan{APIVersion: device.V2, DigestEncodingVersion: 2, OperationID: strings.Repeat(fmt.Sprintf("%x", generation), 32), DeviceID: f.snapshot.DeviceID, DeploymentID: f.snapshot.DeploymentID, Mode: "enroll", TargetGeneration: generation, TargetSlot: slot, ConfigDigest: f.snapshot.Digest(), SnapshotDigest: f.snapshot.Digest(), ProfileID: f.snapshot.Profile.ID, ProfileVersion: f.snapshot.Profile.Version, ProfileDigest: f.snapshot.Profile.PolicyDigest, CompositionDigest: f.snapshot.Composition.Digest(), ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	if generation > 1 {
		p.Mode, p.ExpectedGeneration = "rotate", generation-1
	}
	for _, field := range []struct {
		role string
		to   *string
	}{{"control", &p.ControlTrustDigest}, {"application", &p.ApplicationTrustDigest}, {"issuance", &p.IssuanceTrustDigest}, {"recovery", &p.RecoveryTrustDigest}, {"transport", &p.TransportTrustDigest}} {
		r, err := f.snapshot.Role(field.role)
		if err != nil {
			t.Fatal(err)
		}
		*field.to = r.Digest()
	}
	var err error
	p.Digest, err = p.CalculateDigest()
	if err != nil || p.Validate(time.Now()) != nil {
		t.Fatalf("invalid fixture plan: %v", err)
	}
	return p
}

func (f profileFixture) open(t *testing.T, path string) *Store {
	t.Helper()
	s, err := OpenV2(path, f.snapshot.DeploymentID, f.snapshot.DeviceID, f.snapshot.Profile.ID, f.snapshot.Profile.Version, f.snapshot.Profile.PolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func (f profileFixture) csr(t *testing.T, s *Store, h device.Handle) []byte {
	t.Helper()
	signer, err := s.Signer(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := f.snapshot.Profile.CreateCSR(signer, h.Binding.DeviceID, h.Binding.Generation)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func (f profileFixture) leaf(t *testing.T, signer crypto.Signer, h device.Handle, serial int64, edit func(*x509.Certificate)) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: f.snapshot.Profile.Subject(h.Binding.DeviceID, h.Binding.Generation)}, NotBefore: time.Now().Add(-time.Second), NotAfter: time.Now().Add(10 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	if f.snapshot.Profile.ID == credentialprofile.ReferenceID {
		template.DNSNames = []string{template.Subject.CommonName}
	}
	if edit != nil {
		edit(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.ca, signer.Public(), f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})...)
}

func (f profileFixture) prepare(t *testing.T, s *Store, slot string, generation uint64) (device.Handle, []byte, []byte) {
	t.Helper()
	h := stage(t, s, f.plan(t, slot, generation).Binding())
	if err := s.StoreSnapshot(context.Background(), h, f.snapshot.Bytes()); err != nil {
		t.Fatal(err)
	}
	csr := f.csr(t, s, h)
	if err := s.StoreCSR(context.Background(), h, csr); err != nil {
		t.Fatal(err)
	}
	signer, err := s.Signer(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	chain := f.leaf(t, signer, h, int64(generation), nil)
	return h, csr, chain
}

func fileInventory(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			result[strings.TrimPrefix(path, root)] = device.Hash(data)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestV2VersionAndScopeRefusalWithoutMutation(t *testing.T) {
	f := newProfileFixture(t, credentialprofile.StableID)
	legacyPath := keyPath(t)
	legacy := keyStore(t, legacyPath)
	stage(t, legacy, bind("A", 1))
	legacy.Close()
	before := fileInventory(t, legacyPath)
	if _, err := OpenV2(legacyPath, f.snapshot.DeploymentID, f.snapshot.DeviceID, f.snapshot.Profile.ID, 1, f.snapshot.Profile.PolicyDigest); !errors.Is(err, device.ErrUnsupported) {
		t.Fatalf("legacy store silently opted in: %v", err)
	}
	if !reflect.DeepEqual(before, fileInventory(t, legacyPath)) {
		t.Fatal("refused opt-in changed legacy files")
	}
	path := keyPath(t)
	s := f.open(t, path)
	s.Close()
	before = fileInventory(t, path)
	for _, open := range []func() (*Store, error){
		func() (*Store, error) { return Open(path) },
		func() (*Store, error) { return OpenReadOnly(path) },
		func() (*Store, error) {
			return OpenV2(path, "another-lab", f.snapshot.DeviceID, f.snapshot.Profile.ID, 1, f.snapshot.Profile.PolicyDigest)
		},
		func() (*Store, error) {
			return OpenV2(path, f.snapshot.DeploymentID, "another-device", f.snapshot.Profile.ID, 1, f.snapshot.Profile.PolicyDigest)
		},
		func() (*Store, error) {
			p, _ := credentialprofile.Find(credentialprofile.ReferenceID, 1)
			return OpenV2(path, f.snapshot.DeploymentID, f.snapshot.DeviceID, p.ID, p.Version, p.PolicyDigest)
		},
	} {
		if candidate, err := open(); err == nil {
			candidate.Close()
			t.Fatal("wrong storage version or scope was accepted")
		}
		if !reflect.DeepEqual(before, fileInventory(t, path)) {
			t.Fatal("refusal mutated version-two store")
		}
	}
	missing := filepath.Join(filepath.Dir(path), "missing")
	if _, err := OpenV2(missing, f.snapshot.DeploymentID, f.snapshot.DeviceID, f.snapshot.Profile.ID, 2, f.snapshot.Profile.PolicyDigest); err == nil {
		t.Fatal("unknown profile version accepted")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("unsupported profile created a store")
	}
}

func TestLegacySlotRefusesPresentVersionTwoFields(t *testing.T) {
	path := keyPath(t)
	s := keyStore(t, path)
	h := stage(t, s, bind("A", 1))
	name := filepath.Join(path, "A", "manifest.json")
	original, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []struct {
		name  string
		value any
	}{{"profileId", nil}, {"profileVersion", 0}, {"deploymentId", ""}, {"snapshotDigest", ""}} {
		t.Run(field.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(original, &value); err != nil {
				t.Fatal(err)
			}
			value["handle"].(map[string]any)["binding"].(map[string]any)[field.name] = field.value
			data, _ := json.Marshal(value)
			if err := os.WriteFile(name, data, 0o600); err != nil {
				t.Fatal(err)
			}
			before := fileInventory(t, path)
			if _, err := s.Signer(context.Background(), h); err == nil {
				t.Fatal("version-one metadata silently consumed a version-two field")
			}
			if !reflect.DeepEqual(before, fileInventory(t, path)) {
				t.Fatal("version-field refusal changed existing keys")
			}
		})
	}
	if err := os.WriteFile(name, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Signer(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestV2OriginalCSRAndSnapshotSurviveRestart(t *testing.T) {
	for _, id := range []string{credentialprofile.ReferenceID, credentialprofile.StableID} {
		t.Run(id, func(t *testing.T) {
			f := newProfileFixture(t, id)
			path := keyPath(t)
			s := f.open(t, path)
			h, csr, _ := f.prepare(t, s, "A", 1)
			if err := s.StoreCSR(context.Background(), h, csr); err != nil {
				t.Fatal(err)
			}
			otherSignature := f.csr(t, s, h)
			if bytes.Equal(otherSignature, csr) {
				t.Fatal("fixture did not produce a distinct ECDSA signature")
			}
			before := fileInventory(t, path)
			if err := s.StoreCSR(context.Background(), h, otherSignature); !errors.Is(err, device.ErrConflict) {
				t.Fatalf("original signed CSR was replaced: %v", err)
			}
			if !reflect.DeepEqual(before, fileInventory(t, path)) {
				t.Fatal("conflicting CSR changed slot artifacts")
			}
			s.Close()
			s = f.open(t, path)
			if got, err := s.CSR(context.Background(), h); err != nil || !bytes.Equal(got, csr) {
				t.Fatalf("restart lost the original CSR: %v", err)
			}
			for _, corrupt := range []struct {
				file string
				data []byte
			}{{"csr.pem", otherSignature}, {"public-snapshot.json", append(f.snapshot.Bytes(), '\n')}} {
				name := filepath.Join(path, "A", corrupt.file)
				original, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, corrupt.data, 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Signer(context.Background(), h); err == nil {
					t.Fatal("reload accepted changed original public artifact")
				}
				if err := os.WriteFile(name, original, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			reader, err := OpenReadOnlyV2(path, f.snapshot.DeploymentID, f.snapshot.DeviceID, id, 1, f.snapshot.Profile.PolicyDigest)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if got, err := reader.CSR(context.Background(), h); err != nil || !bytes.Equal(got, csr) {
				t.Fatalf("read-only reload changed CSR: %v", err)
			}
			if err := reader.StoreCSR(context.Background(), h, csr); !errors.Is(err, device.ErrDenied) {
				t.Fatalf("read-only CSR mutation accepted: %v", err)
			}
		})
	}
}

func TestV2CertificateRequiresExactCSRKeyAndProfile(t *testing.T) {
	for _, id := range []string{credentialprofile.ReferenceID, credentialprofile.StableID} {
		t.Run(id, func(t *testing.T) {
			f := newProfileFixture(t, id)
			path := keyPath(t)
			s := f.open(t, path)
			h := stage(t, s, f.plan(t, "A", 1).Binding())
			signer, _ := s.Signer(context.Background(), h)
			chain := f.leaf(t, signer, h, 1, nil)
			if err := s.StoreCertificate(context.Background(), h, chain); err == nil {
				t.Fatal("certificate accepted without original CSR/snapshot")
			}
			if err := s.StoreSnapshot(context.Background(), h, f.snapshot.Bytes()); err != nil {
				t.Fatal(err)
			}
			csr := f.csr(t, s, h)
			if err := s.StoreCSR(context.Background(), h, csr); err != nil {
				t.Fatal(err)
			}
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			wrongKeyCSR, _ := f.snapshot.Profile.CreateCSR(other, h.Binding.DeviceID, h.Binding.Generation)
			if err := s.StoreCSR(context.Background(), h, wrongKeyCSR); err == nil {
				t.Fatal("CSR from another signer was accepted")
			}
			wrong := []struct {
				name string
				data []byte
			}{{"same-cn-other-key", f.leaf(t, other, h, 2, nil)}, {"extra-subject", f.leaf(t, signer, h, 3, func(c *x509.Certificate) { c.Subject.Organization = []string{"unapproved"} })}, {"extra-san", f.leaf(t, signer, h, 4, func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "unapproved.invalid") })}, {"any-eku", f.leaf(t, signer, h, 5, func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageAny) })}}
			if id == credentialprofile.StableID {
				wrong = append(wrong, struct {
					name string
					data []byte
				}{"server-eku", f.leaf(t, signer, h, 6, func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) })})
			}
			before := fileInventory(t, path)
			for _, test := range wrong {
				t.Run(test.name, func(t *testing.T) {
					if err := s.StoreCertificate(context.Background(), h, test.data); err == nil {
						t.Fatal("invalid profile/key chain was stored")
					}
					if !reflect.DeepEqual(before, fileInventory(t, path)) {
						t.Fatal("invalid certificate changed slot")
					}
				})
			}
			if err := s.StoreCertificate(context.Background(), h, chain); err != nil {
				t.Fatal(err)
			}
			if err := s.Activate(context.Background(), h); !errors.Is(err, device.ErrDenied) {
				t.Fatalf("activation skipped fresh interval: %v", err)
			}
			if err := s.ActivateV2(context.Background(), h, time.Now().Add(-100*time.Millisecond), time.Now().Add(100*time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			activeIs(t, s, h)
			if err := s.Destroy(context.Background(), h); !errors.Is(err, device.ErrDenied) {
				t.Fatalf("last active signer was destroyed: %v", err)
			}
			secondLeaf := f.leaf(t, signer, h, 99, nil)
			if err := os.WriteFile(filepath.Join(path, "A", "certificate.pem"), secondLeaf, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Signer(context.Background(), h); err == nil {
				t.Fatal("reload accepted a different leaf for the same key/CN")
			}
			if _, err := s.Active(context.Background()); err == nil {
				t.Fatal("corrupted active leaf was accepted")
			}
			if err := os.WriteFile(filepath.Join(path, "A", "certificate.pem"), chain, 0o600); err != nil {
				t.Fatal(err)
			}
			activeIs(t, s, h)
		})
	}
}

func TestV2ActivationIntervalAndHistoricalArtifact(t *testing.T) {
	f := newProfileFixture(t, credentialprofile.StableID)
	s := f.open(t, keyPath(t))
	h, _, chain := f.prepare(t, s, "A", 1)
	if err := s.StoreCertificate(context.Background(), h, chain); err != nil {
		t.Fatal(err)
	}
	certs, _ := credentialprofile.ParseChain(chain)
	leaf := certs[0]
	for _, interval := range []struct {
		name             string
		earliest, latest time.Time
	}{{"not-before", leaf.NotBefore.Add(-time.Millisecond), leaf.NotBefore.Add(time.Millisecond)}, {"not-after", leaf.NotAfter.Add(-time.Millisecond), leaf.NotAfter.Add(time.Millisecond)}, {"remaining-margin", leaf.NotAfter.Add(-119 * time.Second), leaf.NotAfter.Add(-118 * time.Second)}, {"unknown-time", time.Time{}, time.Time{}}, {"too-wide", time.Now(), time.Now().Add(5 * time.Second)}} {
		t.Run(interval.name, func(t *testing.T) {
			if err := s.ActivateV2(context.Background(), h, interval.earliest, interval.latest); err == nil {
				t.Fatal("invalid assessed interval activated the signer")
			}
			if active, err := s.Active(context.Background()); err != nil || active != nil {
				t.Fatalf("refused activation changed pointer: %v", err)
			}
		})
	}
	if err := s.ActivateV2(context.Background(), h, time.Now(), time.Now().Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	b, _, _ := f.prepare(t, s, "B", 2)
	signer, _ := s.Signer(context.Background(), b)
	expired := f.leaf(t, signer, b, 2, func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = time.Now().Add(-10*time.Minute), time.Now().Add(-time.Second)
	})
	if err := s.StoreCertificate(context.Background(), b, expired); err != nil {
		t.Fatalf("historical artifact could not be bound: %v", err)
	}
	if _, err := s.Certificate(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateV2(context.Background(), b, time.Now(), time.Now().Add(time.Millisecond)); err == nil {
		t.Fatal("historical binding authorized an expired target")
	}
	activeIs(t, s, h)
	if err := s.Destroy(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stage(context.Background(), b.Binding); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("retired version-two binding was reused: %v", err)
	}
	activeIs(t, s, h)
}

func TestV2ActivationAcceptsPropagatedClockUncertainty(t *testing.T) {
	f := newProfileFixture(t, credentialprofile.StableID)
	s := f.open(t, keyPath(t))
	h, _, chain := f.prepare(t, s, "A", 1)
	if err := s.StoreCertificate(context.Background(), h, chain); err != nil {
		t.Fatal(err)
	}
	clock := device.SystemClock{Uncertainty: time.Second, MaximumAge: 10 * time.Second, DriftPPM: 50}
	assessment, err := clock.Assess(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	// Reloading actual artifacts advances the local monotonic clock. Its drift
	// expansion must fit the declared half-width bound at activation.
	if _, err := s.Certificate(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	early, late, err := assessment.Interval(time.Now(), time.Time{})
	if err != nil || late.Sub(early) <= 2*time.Second {
		t.Fatalf("elapsed drift was not observed: %v", err)
	}
	if err := s.ActivateV2(context.Background(), h, early, late); err != nil {
		t.Fatalf("valid propagated interval was refused: %v", err)
	}
	activeIs(t, s, h)
}

func TestV2DuplicateMetadataAndMissingCertificateRefusal(t *testing.T) {
	f := newProfileFixture(t, credentialprofile.StableID)
	path := keyPath(t)
	s := f.open(t, path)
	h, _, chain := f.prepare(t, s, "A", 1)
	if err := s.StoreCertificate(context.Background(), h, chain); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(path, "A", "certificate.pem")); err != nil {
		t.Fatal(err)
	}
	signer, err := s.Signer(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	other := f.leaf(t, signer, h, 99, nil)
	before := fileInventory(t, path)
	if err := s.StoreCertificate(context.Background(), h, other); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("missing original leaf was replaced by a different result: %v", err)
	}
	if !reflect.DeepEqual(before, fileInventory(t, path)) {
		t.Fatal("refused replacement wrote a different pending certificate")
	}
	if err := s.StoreCertificate(context.Background(), h, chain); err != nil {
		t.Fatalf("exact original public chain could not reconcile: %v", err)
	}
	s.Close()
	name := filepath.Join(path, ".device.json")
	original, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append([]byte(`{"schemaVersion":2,`), original[1:]...)
	if err := os.WriteFile(name, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	before = fileInventory(t, path)
	if _, err := OpenV2(path, f.snapshot.DeploymentID, f.snapshot.DeviceID, f.snapshot.Profile.ID, f.snapshot.Profile.Version, f.snapshot.Profile.PolicyDigest); err == nil {
		t.Fatal("duplicate metadata field was accepted")
	}
	if !reflect.DeepEqual(before, fileInventory(t, path)) {
		t.Fatal("duplicate metadata refusal mutated the store")
	}
}

func TestV2MissingIdentityDoesNotReinitialize(t *testing.T) {
	f := newProfileFixture(t, credentialprofile.StableID)
	path := keyPath(t)
	s := f.open(t, path)
	f.prepare(t, s, "A", 1)
	s.Close()
	if err := os.Remove(filepath.Join(path, ".device.json")); err != nil {
		t.Fatal(err)
	}
	before := fileInventory(t, path)
	if _, err := OpenV2(path, f.snapshot.DeploymentID, f.snapshot.DeviceID, f.snapshot.Profile.ID, 1, f.snapshot.Profile.PolicyDigest); !errors.Is(err, device.ErrConflict) {
		t.Fatalf("orphan version-two state was rebound: %v", err)
	}
	if _, err := Open(path); !errors.Is(err, device.ErrUnsupported) {
		t.Fatalf("orphan version-two slots silently downgraded: %v", err)
	}
	if !reflect.DeepEqual(before, fileInventory(t, path)) {
		t.Fatal("identity refusal changed existing slot data")
	}
}

type profileHelperInput struct {
	Snapshot []byte
	Handle   device.Handle
	CSR      []byte
	Chain    []byte
}

func TestV2KeyStoreHelperProcess(t *testing.T) {
	path, inputPath := os.Getenv("KD_V2_KEYSTORE_HELPER"), os.Getenv("KD_V2_KEYSTORE_INPUT")
	if path == "" {
		return
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var input profileHelperInput
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	snapshot, err := device.DecodeSnapshot(input.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenV2(path, snapshot.DeploymentID, snapshot.DeviceID, snapshot.Profile.ID, snapshot.Profile.Version, snapshot.Profile.PolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.checkpoint = func(point string) {
		if point == os.Getenv("KD_V2_KEYSTORE_STOP") {
			fmt.Println(point)
			select {}
		}
	}
	switch os.Getenv("KD_V2_KEYSTORE_ACTION") {
	case "snapshot":
		err = s.StoreSnapshot(context.Background(), input.Handle, input.Snapshot)
	case "csr":
		err = s.StoreCSR(context.Background(), input.Handle, input.CSR)
	case "certificate":
		err = s.StoreCertificate(context.Background(), input.Handle, input.Chain)
	default:
		t.Fatal("unknown helper action")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestV2SIGKILLPublicArtifactCheckpoints(t *testing.T) {
	for _, gap := range []struct{ action, point string }{{"snapshot", "snapshot-file"}, {"snapshot", "snapshot-rename"}, {"snapshot", "snapshot-parent"}, {"csr", "csr-file"}, {"csr", "csr-binding"}, {"csr", "csr-rename"}, {"csr", "csr-parent"}, {"certificate", "cert-binding"}} {
		t.Run(gap.point, func(t *testing.T) {
			f := newProfileFixture(t, credentialprofile.StableID)
			path := keyPath(t)
			s := f.open(t, path)
			h := stage(t, s, f.plan(t, "A", 1).Binding())
			csr := f.csr(t, s, h)
			signer, _ := s.Signer(context.Background(), h)
			chain := f.leaf(t, signer, h, 1, nil)
			if gap.action != "snapshot" {
				if err := s.StoreSnapshot(context.Background(), h, f.snapshot.Bytes()); err != nil {
					t.Fatal(err)
				}
			}
			if gap.action == "certificate" {
				if err := s.StoreCSR(context.Background(), h, csr); err != nil {
					t.Fatal(err)
				}
			}
			s.Close()
			input, _ := json.Marshal(profileHelperInput{Snapshot: f.snapshot.Bytes(), Handle: h, CSR: csr, Chain: chain})
			inputPath := filepath.Join(filepath.Dir(path), "helper.json")
			if err := os.WriteFile(inputPath, input, 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestV2KeyStoreHelperProcess$")
			command.Env = append(os.Environ(), "KD_V2_KEYSTORE_HELPER="+path, "KD_V2_KEYSTORE_INPUT="+inputPath, "KD_V2_KEYSTORE_STOP="+gap.point, "KD_V2_KEYSTORE_ACTION="+gap.action)
			stdout, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			command.Stderr = &stderr
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			reached := make(chan string, 1)
			go func() { scanner := bufio.NewScanner(stdout); scanner.Scan(); reached <- scanner.Text() }()
			select {
			case point := <-reached:
				if point != gap.point {
					command.Process.Kill()
					command.Wait()
					t.Fatalf("checkpoint not reached: %q %s", point, stderr.String())
				}
			case <-time.After(10 * time.Second):
				command.Process.Kill()
				command.Wait()
				t.Fatal("helper checkpoint timed out")
			}
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := command.Wait(); err == nil {
				t.Fatal("helper was not killed")
			}
			s = f.open(t, path)
			if got := stage(t, s, h.Binding); got != h {
				t.Fatal("restart replaced the staged key/handle")
			}
			if gap.action == "csr" {
				if got, err := s.CSR(context.Background(), h); err != nil || !bytes.Equal(got, csr) {
					t.Fatalf("restart generated/lost original CSR: %v", err)
				}
			}
			if err := s.StoreSnapshot(context.Background(), h, f.snapshot.Bytes()); err != nil {
				t.Fatal(err)
			}
			if err := s.StoreCSR(context.Background(), h, csr); err != nil {
				t.Fatal(err)
			}
			if err := s.StoreCertificate(context.Background(), h, chain); err != nil {
				t.Fatal(err)
			}
			if got, err := s.CSR(context.Background(), h); err != nil || !bytes.Equal(got, csr) {
				t.Fatalf("reconciliation changed original CSR: %v", err)
			}
		})
	}
}
