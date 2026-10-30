// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"bytes"
	"context"
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
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/internal/credentialprofile"
	"knowndevice.local/knowndevice/internal/device"
	"modernc.org/sqlite"
)

type journalProfileFixture struct {
	snapshot *device.PublicSnapshot
	signer   *ecdsa.PrivateKey
	issuer   *ecdsa.PrivateKey
	ca       *x509.Certificate
}

func newJournalProfileFixture(t *testing.T, id string) journalProfileFixture {
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
	f := journalProfileFixture{snapshot: s}
	f.signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
			trust.Endpoint, trust.PeerName = "https://"+role+".invalid:9443", role+".invalid"
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

func (f journalProfileFixture) open(t *testing.T, path string) *Store {
	t.Helper()
	s, err := OpenV2(context.Background(), path, f.snapshot.DeploymentID, f.snapshot.DeviceID, f.snapshot.Profile.ID, f.snapshot.Profile.Version, f.snapshot.Profile.PolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func (f journalProfileFixture) operation(t *testing.T, generation uint64) *device.Operation {
	t.Helper()
	p := device.Plan{APIVersion: device.V2, DigestEncodingVersion: 2, OperationID: strings.Repeat(fmt.Sprintf("%x", generation), 32), DeviceID: f.snapshot.DeviceID, DeploymentID: f.snapshot.DeploymentID, Mode: "enroll", TargetGeneration: generation, TargetSlot: "A", ConfigDigest: f.snapshot.Digest(), SnapshotDigest: f.snapshot.Digest(), ProfileID: f.snapshot.Profile.ID, ProfileVersion: f.snapshot.Profile.Version, ProfileDigest: f.snapshot.Profile.PolicyDigest, CompositionDigest: f.snapshot.Composition.Digest(), ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
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
	return &device.Operation{Plan: p, Phase: device.Planned, Outcome: "running", Snapshot: f.snapshot.Bytes()}
}

func (f journalProfileFixture) material(t *testing.T, operation *device.Operation) {
	t.Helper()
	public, err := x509.MarshalPKIXPublicKey(f.signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	operation.Target = &device.Handle{Binding: operation.Plan.Binding(), PublicKeyDigest: device.Hash(public)}
	operation.CSR, err = f.snapshot.Profile.CreateCSR(f.signer, operation.Plan.DeviceID, operation.Plan.TargetGeneration)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(int64(operation.Plan.TargetGeneration)), Subject: pkix.Name{CommonName: f.snapshot.Profile.Subject(operation.Plan.DeviceID, operation.Plan.TargetGeneration)}, NotBefore: time.Now().Add(-time.Second), NotAfter: time.Now().Add(10 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	if f.snapshot.Profile.ID == credentialprofile.ReferenceID {
		template.DNSNames = []string{template.Subject.CommonName}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.ca, f.signer.Public(), f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	operation.Certificate = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})...)
}

func journalInventory(t *testing.T, path string) map[string]string {
	t.Helper()
	items, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, item := range items {
		if item.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(filepath.Dir(path), item.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[item.Name()] = device.Hash(data)
	}
	return result
}

func TestV2JournalVersionAndScopeRefusalBeforeMutation(t *testing.T) {
	f := newJournalProfileFixture(t, credentialprofile.StableID)
	path := journalPath(t)
	legacy := openTest(t, path)
	legacy.Close()
	before := journalInventory(t, path)
	if _, err := OpenV2(context.Background(), path, f.snapshot.DeploymentID, f.snapshot.DeviceID, f.snapshot.Profile.ID, 1, f.snapshot.Profile.PolicyDigest); !errors.Is(err, device.ErrUnsupported) {
		t.Fatalf("schema-one journal opted in: %v", err)
	}
	if !reflect.DeepEqual(before, journalInventory(t, path)) {
		t.Fatal("refused opt-in changed legacy journal")
	}
	path = journalPath(t)
	s := f.open(t, path)
	want := snapshot(t, s)
	s.Close()
	before = journalInventory(t, path)
	for _, open := range []func() (*Store, error){
		func() (*Store, error) { return Open(context.Background(), path, f.snapshot.DeviceID) },
		func() (*Store, error) {
			return OpenV2(context.Background(), path, "another-lab", f.snapshot.DeviceID, f.snapshot.Profile.ID, 1, f.snapshot.Profile.PolicyDigest)
		},
		func() (*Store, error) {
			return OpenV2(context.Background(), path, f.snapshot.DeploymentID, "another-device", f.snapshot.Profile.ID, 1, f.snapshot.Profile.PolicyDigest)
		},
		func() (*Store, error) {
			profile, _ := credentialprofile.Find(credentialprofile.ReferenceID, 1)
			return OpenV2(context.Background(), path, f.snapshot.DeploymentID, f.snapshot.DeviceID, profile.ID, profile.Version, profile.PolicyDigest)
		},
	} {
		if candidate, err := open(); err == nil {
			candidate.Close()
			t.Fatal("wrong version/namespace/device/profile accepted")
		}
		if !reflect.DeepEqual(before, journalInventory(t, path)) {
			t.Fatal("refusal mutated schema-two journal or lock")
		}
	}
	got, err := ReadV2(context.Background(), path, f.snapshot.DeploymentID, f.snapshot.DeviceID, f.snapshot.Profile.ID, 1, f.snapshot.Profile.PolicyDigest)
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(before, journalInventory(t, path)) {
		t.Fatalf("read-only V2 inspection mutated state: %v", err)
	}
	if _, err := Read(context.Background(), path, f.snapshot.DeviceID); !errors.Is(err, device.ErrUnsupported) {
		t.Fatalf("legacy reader accepted V2: %v", err)
	}
}

func TestV2JournalUnknownIntentFencingAndRestart(t *testing.T) {
	for _, id := range []string{credentialprofile.ReferenceID, credentialprofile.StableID} {
		t.Run(id, func(t *testing.T) {
			f := newJournalProfileFixture(t, id)
			path := journalPath(t)
			s := f.open(t, path)
			state := snapshot(t, s)
			state.Counter, state.Operation = 1, f.operation(t, 1)
			state, err := s.Save(context.Background(), state, state.Revision)
			if err != nil {
				t.Fatal(err)
			}
			f.material(t, state.Operation)
			state.Operation.Certificate = nil
			state.Operation.Phase, state.Operation.Outcome = device.IssueIntent, "unknown"
			state, err = s.Save(context.Background(), state, state.Revision)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenV2(context.Background(), path, f.snapshot.DeploymentID, f.snapshot.DeviceID, id, 1, f.snapshot.Profile.PolicyDigest); !errors.Is(err, device.ErrConflict) {
				t.Fatalf("two V2 writers acquired the journal: %v", err)
			}
			s.Close()
			s = f.open(t, path)
			current := snapshot(t, s)
			if current.Counter != 1 || current.Fence != state.Fence+1 || current.Revision != state.Revision+1 || current.Operation.Phase != device.IssueIntent || current.Operation.Outcome != "unknown" || !bytes.Equal(current.Operation.CSR, state.Operation.CSR) || !bytes.Equal(current.Operation.Snapshot, state.Operation.Snapshot) {
				t.Fatal("restart lost original binding, intent, uncertainty or floor")
			}
			state.Revision = current.Revision
			if _, err := s.Save(context.Background(), state, current.Revision); !errors.Is(err, device.ErrConflict) {
				t.Fatalf("stale writer fence accepted: %v", err)
			}
			for _, test := range []struct {
				name string
				edit func(*device.State)
			}{{"namespace", func(s *device.State) { s.DeploymentID = "other-lab" }}, {"counter", func(s *device.State) { s.Counter = 0 }}, {"snapshot", func(s *device.State) { s.Operation.Snapshot = append(s.Operation.Snapshot, '\n') }}, {"profile", func(s *device.State) { s.ProfileVersion = 2 }}, {"second-operation", func(s *device.State) { s.Counter, s.Operation = 2, f.operation(t, 2) }}, {"second-csr", func(s *device.State) {
				csr, err := f.snapshot.Profile.CreateCSR(f.signer, s.DeviceID, 1)
				if err != nil {
					t.Fatal(err)
				}
				s.Operation.CSR = csr
			}}} {
				t.Run(test.name, func(t *testing.T) {
					next := snapshot(t, s)
					test.edit(&next)
					if _, err := s.Save(context.Background(), next, next.Revision); err == nil {
						t.Fatal("mutation of an unknown reservation was accepted")
					}
					if !reflect.DeepEqual(current, snapshot(t, s)) {
						t.Fatal("refusal changed durable unknown operation")
					}
				})
			}
		})
	}
}

func TestV2JournalStrictCSRChainAndSnapshot(t *testing.T) {
	f := newJournalProfileFixture(t, credentialprofile.StableID)
	s := f.open(t, journalPath(t))
	state := snapshot(t, s)
	state.Counter, state.Operation = 1, f.operation(t, 1)
	state, err := s.Save(context.Background(), state, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*device.Operation)
	}{{"wrong-profile-csr", func(o *device.Operation) {
		p, _ := credentialprofile.Find(credentialprofile.ReferenceID, 1)
		o.CSR, _ = p.CreateCSR(f.signer, o.Plan.DeviceID, o.Plan.TargetGeneration)
	}}, {"wrong-key-csr", func(o *device.Operation) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		o.CSR, _ = f.snapshot.Profile.CreateCSR(key, o.Plan.DeviceID, o.Plan.TargetGeneration)
	}}, {"missing-csr", func(o *device.Operation) { o.CSR = nil }}, {"missing-chain", func(o *device.Operation) { o.Certificate = nil; o.Phase = device.Issued }}, {"private-csr", func(o *device.Operation) { o.CSR = []byte("-----BEGIN PRIVATE KEY-----") }}, {"changed-trust", func(o *device.Operation) {
		var snap device.PublicSnapshot
		if err := json.Unmarshal(o.Snapshot, &snap); err != nil {
			t.Fatal(err)
		}
		snap.Trust[0].LeafPins = []string{device.Hash([]byte("changed-peer"))}
		o.Snapshot = snap.Bytes()
	}}} {
		t.Run(test.name, func(t *testing.T) {
			next := snapshot(t, s)
			f.material(t, next.Operation)
			next.Operation.Phase = device.KeyReady
			test.edit(next.Operation)
			if _, err := s.Save(context.Background(), next, next.Revision); err == nil {
				t.Fatal("invalid profile/key/trust material was accepted")
			}
			if !reflect.DeepEqual(state, snapshot(t, s)) {
				t.Fatal("invalid material changed original state")
			}
		})
	}
	valid := snapshot(t, s)
	f.material(t, valid.Operation)
	valid.Operation.Phase = device.Issued
	if _, err := s.Save(context.Background(), valid, valid.Revision); err != nil {
		t.Fatal(err)
	}
}

func TestV2JournalWriteFailureStopsEffects(t *testing.T) {
	for _, mode := range []string{"read-only", "full"} {
		t.Run(mode, func(t *testing.T) {
			f := newJournalProfileFixture(t, credentialprofile.StableID)
			s := f.open(t, journalPath(t))
			before := snapshot(t, s)
			next := before
			next.Counter, next.Operation = 1, f.operation(t, 1)
			code := 8
			if mode == "read-only" {
				if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
					t.Fatal(err)
				}
			} else {
				var pages int
				if err := s.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); err != nil {
					t.Fatal(err)
				}
				code = 13
			}
			_, err := s.Save(context.Background(), next, next.Revision)
			var sqliteErr *sqlite.Error
			if !errors.As(err, &sqliteErr) || sqliteErr.Code()&255 != code {
				t.Fatalf("expected actual SQLite %d, got %v", code, err)
			}
			if !reflect.DeepEqual(before, snapshot(t, s)) {
				t.Fatal("failed write changed counters/intent")
			}
			if _, err := s.db.Exec("PRAGMA query_only=OFF; PRAGMA max_page_count=1073741823"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Save(context.Background(), next, next.Revision); err == nil {
				t.Fatal("failed writer resumed effects without reopening")
			}
		})
	}
}

func TestV2JournalDuplicateJSONRefused(t *testing.T) {
	f := newJournalProfileFixture(t, credentialprofile.StableID)
	s := f.open(t, journalPath(t))
	state := snapshot(t, s)
	data, _ := json.Marshal(state)
	data = append([]byte(`{"schemaVersion":2,`), data[1:]...)
	if _, err := s.db.Exec("UPDATE snapshot SET payload=? WHERE id=1", string(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(context.Background()); err == nil {
		t.Fatal("duplicate storage JSON silently replaced a field")
	}
}
