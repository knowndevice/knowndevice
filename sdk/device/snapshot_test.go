// SPDX-License-Identifier: Apache-2.0

package device

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
)

func snapshotRoot(t *testing.T, name string) ([]byte, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SignatureAlgorithm: x509.ECDSAWithSHA256}
	der, e := x509.CreateCertificate(rand.Reader, c, c, k.Public(), k)
	if e != nil {
		t.Fatal(e)
	}
	c, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return der, k, c
}
func snapshotFixture(t *testing.T) *PublicSnapshot {
	t.Helper()
	p, _ := credentialprofile.Find(credentialprofile.StableID, 1)
	s := &PublicSnapshot{APIVersion: V2, EncodingVersion: 2, DeploymentID: "test-deployment", DeviceID: "gateway", Profile: p, Composition: Composition{ID: "local-http-lab", Version: 1, AuthorityTemplateDigest: Hash([]byte("template")), ApplicationID: "worker", SessionPolicy: "new-connection-no-state-transfer", ObservationRoute: "authenticated-application-callback", WithdrawalScope: "whole-service-lab"}, RecoveryIdentity: RecoverySubject("gateway"), RecoveryLeafPin: Hash([]byte("recovery leaf")), RecoverySPKIPin: Hash([]byte("recovery key")), Limits: DefaultLimits(), RequestTimeoutSeconds: 5, PlanTTLSeconds: 600, ClockTrust: "trusted-system-clock"}
	for role, cap := range requiredCapabilities {
		s.Composition.Adapters = append(s.Composition.Adapters, AdapterSpec{Role: role, ID: "local-http-lab-" + role, Version: "1", ArtifactDigest: Hash([]byte("artifact")), Capabilities: []string{cap}})
	}
	sort.Slice(s.Composition.Adapters, func(i, j int) bool { return s.Composition.Adapters[i].Role < s.Composition.Adapters[j].Role })
	for _, role := range []string{"application", "authority-transport", "control", "issuance", "observer", "operational", "recovery", "transport"} {
		der, _, _ := snapshotRoot(t, role)
		r := RoleSnapshot{Role: role, Anchors: [][]byte{der}, LeafPins: []string{}, SPKIPins: []string{}, AllowedIssuers: []string{}}
		if role == "operational" {
			r.AllowedIssuers = []string{Hash(der)}
		} else if role != "recovery" {
			r.Endpoint = "https://" + role + ".invalid:9443"
			r.PeerName = role + ".invalid"
			r.LeafPins = []string{Hash([]byte(role + " leaf"))}
			r.SPKIPins = []string{Hash([]byte(role + " key"))}
		}
		if role == "observer" {
			r.Endpoint = ""
		}
		if role == "issuance" {
			r.CallerLeafPins = []string{Hash([]byte("authority caller"))}
			r.CallerSPKIPins = []string{Hash([]byte("authority key"))}
		}
		s.Trust = append(s.Trust, r)
	}
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestP4RoleDomainsAndCapabilityRefusal(t *testing.T) {
	valid := snapshotFixture(t)
	for _, change := range []func(*PublicSnapshot){func(s *PublicSnapshot) { s.Trust = s.Trust[:len(s.Trust)-1] }, func(s *PublicSnapshot) { s.Trust[2].Anchors = s.Trust[0].Anchors }, func(s *PublicSnapshot) { s.Trust[0].PeerName = "control.invalid" }, func(s *PublicSnapshot) { s.Trust[3].CallerLeafPins = nil; s.Trust[3].CallerSPKIPins = nil }, func(s *PublicSnapshot) {
		s.Composition.Adapters[0].Capabilities = []string{"advertised-but-insufficient"}
	}, func(s *PublicSnapshot) { s.Composition.Adapters[0].Version = "future" }, func(s *PublicSnapshot) { s.Profile.Version = 2 }, func(s *PublicSnapshot) { s.Trust[0].Anchors = append(s.Trust[0].Anchors, s.Trust[0].Anchors[0]) }} {
		copy, e := DecodeSnapshot(valid.Bytes())
		if e != nil {
			t.Fatal(e)
		}
		change(copy)
		if copy.Validate() == nil {
			t.Fatal("missing, wrong-role or unsupported policy accepted")
		}
	}
}

func TestCompositionLifetimeVersionsAndImmutablePolicy(t *testing.T) {
	s := snapshotFixture(t)
	oldDigest := s.Composition.Digest()
	if s.Composition.AuthorityLifetime() != 1200*time.Second || strings.Contains(string(s.Bytes()), "authorityLifetimeSeconds") {
		t.Fatal("composition 1 encoding or lifetime changed")
	}
	s.Composition.Version = 2
	s.Composition.AuthorityLifetimeSeconds = 300
	if err := s.Validate(); err != nil || s.Composition.AuthorityLifetime() != 300*time.Second || s.Composition.Digest() == oldDigest {
		t.Fatal("explicit composition 2 lifetime is not bound")
	}
	for _, value := range []int{0, 299, 1201} {
		s.Composition.AuthorityLifetimeSeconds = value
		if s.Validate() == nil {
			t.Fatalf("unsupported lifetime %d accepted", value)
		}
	}
	s.Composition.AuthorityLifetimeSeconds = 300
	s.Limits.MinLifetimeSeconds = 600
	if s.Validate() == nil {
		t.Fatal("request outside stricter accepted lifetime admitted")
	}
	s.Limits = DefaultLimits()
	s.Composition.Version = 1
	if s.Validate() == nil {
		t.Fatal("composition 1 accepted a changed fixed request")
	}
	s.Composition.AuthorityLifetimeSeconds = 0
	if s.Composition.Digest() != oldDigest {
		t.Fatal("composition 1 digest changed")
	}
}
func TestP5ImmutableSnapshotAndTrustPathReplacement(t *testing.T) {
	original := snapshotFixture(t)
	copy, e := DecodeSnapshot(original.Bytes())
	if e != nil {
		t.Fatal(e)
	}
	r, e := copy.Role("control")
	if e != nil {
		t.Fatal(e)
	}
	r.Anchors[0][0] ^= 1
	if copy.Digest() != original.Digest() {
		t.Fatal("role getter exposed mutable anchor storage")
	}
	dir := t.TempDir()
	c := Config{APIVersion: V2, DeploymentID: original.DeploymentID, DeviceID: original.DeviceID, StateDir: "new-state", ApplicationID: original.Composition.ApplicationID, ClockTrust: original.ClockTrust, RequestTimeoutSeconds: original.RequestTimeoutSeconds, PlanTTLSeconds: original.PlanTTLSeconds, CredentialProfile: &original.Profile, Composition: &original.Composition, Trust: &TrustConfig{}, Limits: &original.Limits, RecoveryKey: "opaque-handle-path"}
	for _, r := range original.Trust {
		path := filepath.Join(dir, r.Role+".crt")
		if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.Anchors[0]}), 0600); e != nil {
			t.Fatal(e)
		}
		c.Trust.Roles = append(c.Trust.Roles, RoleConfig{Role: r.Role, RootCertificates: []string{path}, Endpoint: r.Endpoint, PeerName: r.PeerName, LeafPins: r.LeafPins, SPKIPins: r.SPKIPins, AllowedIssuers: r.AllowedIssuers, CallerLeafPins: r.CallerLeafPins, CallerSPKIPins: r.CallerSPKIPins})
		switch r.Role {
		case "control":
			c.ControlURL = r.Endpoint
		case "application":
			c.ApplicationURL = r.Endpoint
		case "transport":
			c.TransportEndpoint = r.Endpoint
		}
	}
	// Recovery public pin is independently resolved; no private bytes enter the digest.
	_, key, ca := snapshotRoot(t, "recovery issuer")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: RecoverySubject(c.DeviceID)}, DNSNames: []string{RecoverySubject(c.DeviceID)}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range c.Trust.Roles {
		if r.Role == "recovery" {
			if e = os.WriteFile(r.RootCertificates[0], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
	c.RecoveryCertificate = filepath.Join(dir, "recovery-cert.pem")
	if e = os.WriteFile(c.RecoveryCertificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	first, e := c.ResolveSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	for i := range c.Trust.Roles {
		if c.Trust.Roles[i].Role != "recovery" {
			continue
		}
		prior := c.Trust.Roles[i].AllowedIssuers
		c.Trust.Roles[i].AllowedIssuers = []string{Hash([]byte("excluded recovery issuer"))}
		if _, e = c.ResolveSnapshot(); e == nil {
			t.Fatal("recovery snapshot ignored approved issuer despite valid root and identity")
		}
		c.Trust.Roles[i].AllowedIssuers = []string{Hash(ca.Raw)}
		if _, e = c.ResolveSnapshot(); e != nil {
			t.Fatal("actual approved recovery issuer refused")
		}
		c.Trust.Roles[i].AllowedIssuers = prior
	}
	roots, e := first.Roots("control")
	if e != nil {
		t.Fatal(e)
	}
	role, _ := first.Role("control")
	prior, _ := x509.ParseCertificate(role.Anchors[0])
	if len(roots.Subjects()) != 1 {
		t.Fatal("wrong immutable roots")
	}
	replacement, _, _ := snapshotRoot(t, "replacement")
	path := ""
	for _, r := range c.Trust.Roles {
		if r.Role == "control" {
			path = r.RootCertificates[0]
		}
	}
	if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: replacement}), 0600); e != nil {
		t.Fatal(e)
	}
	second, e := c.ResolveSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	if first.Digest() == second.Digest() {
		t.Fatal("same-path trust replacement did not change digest")
	}
	if _, e = prior.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now()}); e != nil {
		t.Fatal("operation snapshot changed after file replacement")
	}
	b := first.Bytes()
	var corrupt map[string]any
	if json.Unmarshal(b, &corrupt) != nil {
		t.Fatal("decode")
	}
	corrupt["privateKey"] = "must not be consumed"
	b, _ = json.Marshal(corrupt)
	if _, e = DecodeSnapshot(b); e == nil {
		t.Fatal("unknown snapshot field accepted")
	}
	if _, e = DecodeSnapshot(append(first.Bytes(), []byte(" junk")...)); e == nil {
		t.Fatal("snapshot junk accepted")
	}
}
func TestP19ProfilePolicyDigestVectors(t *testing.T) {
	for id, want := range map[string]string{credentialprofile.ReferenceID: "f0eb9b354f7a0fe2b075fba5c3481ef613ad49687629f713ea455c770942547f", credentialprofile.StableID: "c9d1d264e0875a05f02d29557d671ae1d22c68454c84e8bf98c715543f617bcc"} {
		p, e := credentialprofile.Find(id, 1)
		if e != nil || p.PolicyDigest != want || len(p.PolicyDigest) != 64 || strings.ToLower(p.PolicyDigest) != p.PolicyDigest {
			t.Fatal("invalid profile vector")
		}
		again, e := credentialprofile.Resolve(id, 1, p.PolicyDigest)
		if e != nil || again != p {
			t.Fatal("profile vector not stable")
		}
	}
}
