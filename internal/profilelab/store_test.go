// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knowndevice.local/knowndevice/internal/credentialprofile"
	"knowndevice.local/knowndevice/internal/device"
)

func testLab(t *testing.T) (string, servicesConfig, *device.PublicSnapshot) {
	t.Helper()
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	base, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(base, "fresh-profile")
	if e = seed(path, credentialprofile.StableID, executable, executable); e != nil {
		t.Fatal(e)
	}
	cfg, snapshot, e := loadServices(path)
	if e != nil {
		t.Fatal(e)
	}
	return path, cfg, snapshot
}
func testPlan(t *testing.T, s *device.PublicSnapshot, expected, target uint64) device.Plan {
	t.Helper()
	id, e := device.RandomID()
	if e != nil {
		t.Fatal(e)
	}
	mode := "rotate"
	if expected == 0 {
		mode = "enroll"
	}
	p := device.Plan{APIVersion: device.V2, DigestEncodingVersion: 2, DeploymentID: s.DeploymentID, DeviceID: s.DeviceID, OperationID: id, Mode: mode, ExpectedGeneration: expected, TargetGeneration: target, TargetSlot: "A", ExpiresAt: time.Now().UTC().Add(599 * time.Second), ConfigDigest: s.Digest(), SnapshotDigest: s.Digest(), ProfileID: s.Profile.ID, ProfileVersion: s.Profile.Version, ProfileDigest: s.Profile.PolicyDigest, CompositionDigest: s.Composition.Digest()}
	for _, r := range s.Trust {
		switch r.Role {
		case "control":
			p.ControlTrustDigest = r.Digest()
		case "application":
			p.ApplicationTrustDigest = r.Digest()
		case "issuance":
			p.IssuanceTrustDigest = r.Digest()
		case "recovery":
			p.RecoveryTrustDigest = r.Digest()
		case "transport":
			p.TransportTrustDigest = r.Digest()
		}
	}
	p.Digest, e = p.CalculateDigest()
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Validate(time.Now()); e != nil {
		t.Fatal(e)
	}
	return p
}
func testReservation(t *testing.T, s *device.PublicSnapshot, p device.Plan) reservation {
	t.Helper()
	key, e := newKey()
	if e != nil {
		t.Fatal(e)
	}
	csr, e := s.Profile.CreateCSR(key, p.DeviceID, p.TargetGeneration)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := s.Profile.ValidateCSR(csr, p.DeviceID, p.TargetGeneration)
	if e != nil {
		t.Fatal(e)
	}
	return reservation{Plan: p, CSR: csr, SPKI: parsed.RawSubjectPublicKeyInfo, Candidate: bound(p, parsed)}
}
func testRegistry(cfg servicesConfig, s *device.PublicSnapshot) registry {
	return registry{DeploymentID: s.DeploymentID, DeviceID: s.DeviceID, Status: "authorized", Revision: 1, SnapshotDigest: s.Digest(), RecoveryFingerprint: cfg.RecoveryFingerprint, RecoveryPublicKeyDigest: cfg.RecoveryPublicKeyDigest}
}

func TestDurableUnknownReservationFencesOperationGenerationAndSPKI(t *testing.T) {
	dir, cfg, snapshot := testLab(t)
	ctx := context.Background()
	initial := testRegistry(cfg, snapshot)
	s, e := openStore(filepath.Join(dir, "control"), initial)
	if e != nil {
		t.Fatal(e)
	}
	r := testReservation(t, snapshot, testPlan(t, snapshot, 0, 1))
	saved, e := s.reserve(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	if !saved.IssueSent || len(saved.Certificate) != 0 {
		t.Fatal("issuance intent not durably unknown")
	}
	if _, e = openStore(filepath.Join(dir, "control"), initial); !errors.Is(e, device.ErrConflict) {
		t.Fatal("second registry writer acquired lock")
	}
	rival := testReservation(t, snapshot, testPlan(t, snapshot, 0, 2))
	if _, e = s.reserve(ctx, rival); !errors.Is(e, device.ErrConflict) {
		t.Fatal("concurrent unfinished operation admitted")
	}
	changed := r
	changed.CSR = append([]byte(nil), r.CSR...)
	changed.CSR[len(changed.CSR)-10] ^= 1
	if _, e = s.reserve(ctx, changed); !errors.Is(e, device.ErrConflict) {
		t.Fatal("original CSR binding replaced")
	}
	s.close()
	s, e = openStore(filepath.Join(dir, "control"), initial)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	reloaded, e := s.reserve(ctx, r)
	if e != nil || string(reloaded.CSR) != string(r.CSR) || string(reloaded.SPKI) != string(r.SPKI) || !reloaded.IssueSent {
		t.Fatal("restart replaced or lost immutable reservation")
	}
	reloaded.Finished = true
	if e = s.save(ctx, reloaded); e != nil {
		t.Fatal(e)
	}
	reused := testReservation(t, snapshot, testPlan(t, snapshot, 0, 2))
	reused.SPKI = r.SPKI
	reused.Candidate.PublicKeyDigest = r.Candidate.PublicKeyDigest
	if _, e = s.reserve(ctx, reused); !errors.Is(e, device.ErrConflict) {
		t.Fatal("consumed operational SPKI reused")
	}
	old := testReservation(t, snapshot, testPlan(t, snapshot, 0, 1))
	if _, e = s.reserve(ctx, old); !errors.Is(e, device.ErrConflict) {
		t.Fatal("consumed generation reused")
	}
	if _, e = s.reserve(ctx, rival); e != nil {
		t.Fatal(e)
	}
	reg, e := s.registry(ctx)
	if e != nil || reg.Counter != 2 {
		t.Fatal("monotonic floor did not advance")
	}
}

func TestRegistryRefusesVersionAndMissingWALSidecarWithoutMutation(t *testing.T) {
	dir, cfg, snapshot := testLab(t)
	path := filepath.Join(dir, "control")
	initial := testRegistry(cfg, snapshot)
	s, e := openStore(path, initial)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("PRAGMA user_version=1"); e != nil {
		t.Fatal(e)
	}
	s.close()
	before, e := os.ReadFile(filepath.Join(path, "registry.db"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = openStore(path, initial); e == nil {
		t.Fatal("version-1 registry implicitly migrated")
	}
	after, e := os.ReadFile(filepath.Join(path, "registry.db"))
	if e != nil || string(before) != string(after) {
		t.Fatal("refused registry was mutated")
	}
	if e = os.WriteFile(filepath.Join(path, "registry.db-wal"), []byte("retained uncertain sidecar"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = openStore(path, initial); e == nil {
		t.Fatal("WAL without SHM was admitted")
	}
	retained, e := os.ReadFile(filepath.Join(path, "registry.db-wal"))
	if e != nil || string(retained) != "retained uncertain sidecar" {
		t.Fatal("refusal altered uncertain WAL")
	}
}

func TestRegistryRejectsReplacedLockInode(t *testing.T) {
	dir, cfg, snapshot := testLab(t)
	s, e := openStore(filepath.Join(dir, "control"), testRegistry(cfg, snapshot))
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	path := filepath.Join(dir, "control", "writer.lock")
	if e = os.Rename(path, path+".original"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte{}, 0600); e != nil {
		t.Fatal(e)
	}
	r := testReservation(t, snapshot, testPlan(t, snapshot, 0, 1))
	if _, e = s.reserve(context.Background(), r); !errors.Is(e, device.ErrConflict) {
		t.Fatal("replaced writer fence admitted mutation")
	}
}

func TestAuthorityTemplatesPinnedToFiles(t *testing.T) {
	for _, entry := range []struct{ name, template string }{{"stable-client.tpl", stableTemplate}, {"reference-client.tpl", referenceTemplate}} {
		b, e := os.ReadFile(filepath.Join("..", "..", "lab", "profiles", entry.name))
		if e != nil || string(b) != entry.template {
			t.Fatal("pinned authority template and generated service differ")
		}
	}
}

func TestServicePinsCannotOverrideSnapshotBeforeRegistryCreation(t *testing.T) {
	dir, cfg, _ := testLab(t)
	for _, kind := range []string{"recovery-leaf", "recovery-key", "observer-leaf", "observer-key", "authority-leaf", "authority-key"} {
		altered := cfg
		wrong := device.Hash([]byte("wrong public pin"))
		switch kind {
		case "recovery-leaf":
			altered.RecoveryFingerprint = wrong
		case "recovery-key":
			altered.RecoveryPublicKeyDigest = wrong
		case "observer-leaf":
			altered.ObserverFingerprint = wrong
		case "observer-key":
			altered.ObserverPublicKeyDigest = wrong
		case "authority-leaf":
			altered.AuthorityCallerFingerprint = wrong
		case "authority-key":
			altered.AuthorityCallerPublicKeyDigest = wrong
		}
		if e := writeJSON(filepath.Join(dir, "services.json"), altered); e != nil {
			t.Fatal(e)
		}
		if _, e := openControl(dir); e == nil {
			t.Fatalf("%s override admitted", kind)
		}
		if _, e := os.Lstat(filepath.Join(dir, "control", "registry.db")); !os.IsNotExist(e) {
			t.Fatalf("%s override created registry before refusal", kind)
		}
	}
}

func TestUnsupportedClockPrecisionStopsBeforeRegistryOrIssuance(t *testing.T) {
	dir, cfg, snapshot := testLab(t)
	countsPath := filepath.Join(dir, "control", "ca-counts.json")
	countsBefore, e := os.ReadFile(countsPath)
	if e != nil {
		t.Fatal(e)
	}
	for _, millis := range []int{0, 999, 1000} {
		altered := *snapshot
		altered.Limits.MaximumUncertaintyMillis = millis
		encoded, e := json.Marshal(altered)
		if e != nil {
			t.Fatal(e)
		}
		bad := cfg
		bad.Snapshot = encoded
		bad.ConfigDigest = altered.Digest()
		if e = writeJSON(filepath.Join(dir, "services.json"), bad); e != nil {
			t.Fatal(e)
		}
		if _, e = openControl(dir); e == nil {
			t.Fatalf("unavailable clock precision %d ms accepted", millis)
		}
		if _, e = os.Lstat(filepath.Join(dir, "control", "registry.db")); !os.IsNotExist(e) {
			t.Fatalf("precision %d ms created registry before refusal", millis)
		}
		countsAfter, e := os.ReadFile(countsPath)
		if e != nil || string(countsBefore) != string(countsAfter) {
			t.Fatalf("precision %d ms reached issuance before refusal", millis)
		}
	}
}

func TestServerCredentialPurposeUsesOwnRoleTrust(t *testing.T) {
	dir, _, snapshot := testLab(t)
	config, e := serviceTLS(dir, "control", snapshot, []string{"operational", "recovery"})
	if e != nil {
		t.Fatal(e)
	}
	if !config.SessionTicketsDisabled {
		t.Fatal("server permits unfenced TLS tickets")
	}
	for _, name := range []string{"cert.pem", "key.pem"} {
		b, e := os.ReadFile(filepath.Join(dir, "application", name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, "control", name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = serviceTLS(dir, "control", snapshot, []string{"operational", "recovery"}); e == nil {
		t.Fatal("valid wrong-role server credential bypassed pinned Control trust")
	}
}

func TestServiceObserverAndRecoveryRefuseUnapprovedImmediateIssuer(t *testing.T) {
	dir, _, snapshot := testLab(t)
	for _, role := range []string{"observer", "recovery"} {
		credential, e := credentialAt(dir, role)
		if e != nil {
			t.Fatal(e)
		}
		certs := make([]*x509.Certificate, 0, len(credential.Certificate))
		for _, der := range credential.Certificate {
			c, e := x509.ParseCertificate(der)
			if e != nil {
				t.Fatal(e)
			}
			certs = append(certs, c)
		}
		req := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: certs}}
		for i := range snapshot.Trust {
			if snapshot.Trust[i].Role == role {
				snapshot.Trust[i].AllowedIssuers = []string{device.Hash(snapshot.Trust[i].Anchors[0])}
			}
		}
		if e = verifyPeerRole(req, snapshot, role); e != nil {
			t.Fatalf("declared %s issuer refused: %v", role, e)
		}
		for i := range snapshot.Trust {
			if snapshot.Trust[i].Role == role {
				snapshot.Trust[i].AllowedIssuers = []string{device.Hash([]byte("another issuer"))}
			}
		}
		if e = verifyPeerRole(req, snapshot, role); e == nil {
			t.Fatalf("%s ignored its immediate issuer", role)
		}
		if e = validateCallerInterval(snapshot, &credential); e == nil {
			t.Fatalf("%s outbound ignored its immediate issuer", role)
		}
	}
	for i := range snapshot.Trust {
		if snapshot.Trust[i].Role == "application" {
			snapshot.Trust[i].AllowedIssuers = []string{device.Hash([]byte("another application issuer"))}
		}
	}
	if _, e := serviceTLS(dir, "application", snapshot, []string{"observer", "operational"}); e == nil {
		t.Fatal("application listener ignored its immediate issuer")
	}
}
