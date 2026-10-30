// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"knowndevice.local/knowndevice/internal/credentialprofile"
	"knowndevice.local/knowndevice/internal/device"
)

const stableTemplate = "{\n  \"subject\": {\"commonName\": {{ toJson .Subject.CommonName }}},\n  \"sans\": [],\n  \"keyUsage\": [\"digitalSignature\"],\n  \"extKeyUsage\": [\"clientAuth\"],\n  \"basicConstraints\": {\"isCA\": false}\n}\n"
const referenceTemplate = "{\n  \"subject\": {\"commonName\": {{ toJson .Subject.CommonName }}},\n  \"sans\": {{ toJson .SANs }},\n  \"keyUsage\": [\"digitalSignature\"],\n  \"extKeyUsage\": [\"clientAuth\"],\n  \"basicConstraints\": {\"isCA\": false}\n}\n"

func Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kd-profilelab seed|control|application|check --dir PATH")
	}
	flags := flag.NewFlagSet("kd-profilelab", flag.ContinueOnError)
	dir := flags.String("dir", "/lab", "Private new generated-data root")
	profile := flags.String("profile", credentialprofile.StableID, "Strict credential profile")
	cli := flags.String("cli", "/usr/local/bin/knowndevice", "CLI executable for conformance checks")
	serviceArtifact := flags.String("service-artifact", "", "Exact service executable used by this composition")
	controllerArtifact := flags.String("controller-artifact", "", "Exact controller executable used by this composition")
	processArtifact := flags.String("process-artifact", "", "Pinned process adapter executable for a fresh process composition")
	lifetime := flags.Int("authority-lifetime-seconds", 1200, "Total operational validity for a fresh composition (300-1200 seconds)")
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	switch args[0] {
	case "seed":
		return seedWithProcessArtifact(*dir, *profile, *serviceArtifact, *controllerArtifact, *lifetime, *processArtifact)
	case "control":
		return runControl(*dir)
	case "application":
		return runApplication(*dir)
	case "check":
		return runChecks(*dir, *cli)
	default:
		return fmt.Errorf("unknown profile service")
	}
}

type caMaterial struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
func cert(subject string, dns []string, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool, eku []x509.ExtKeyUsage) ([]byte, *x509.Certificate, error) {
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, nil, e
	}
	now := time.Now().UTC()
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: subject}, NotBefore: now.Add(-60 * time.Second), NotAfter: now.Add(48 * time.Hour), DNSNames: dns, SignatureAlgorithm: x509.ECDSAWithSHA256, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: ca, ExtKeyUsage: eku}
	if ca {
		t.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		t.MaxPathLen = 1
	}
	if parent == nil {
		parent = t
		parentKey = key
	}
	der, e := x509.CreateCertificate(rand.Reader, t, parent, key.Public(), parentKey)
	if e != nil {
		return nil, nil, e
	}
	parsed, e := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), parsed, e
}
func keyFile(path string, key *ecdsa.PrivateKey) error {
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	return writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
func coordinate(n *big.Int) string { b := make([]byte, 32); n.FillBytes(b); return b64(b) }

func seed(dir, profileID, serviceArtifact, controllerArtifact string) error {
	return seedWithLifetime(dir, profileID, serviceArtifact, controllerArtifact, 1200)
}

func seedWithLifetime(dir, profileID, serviceArtifact, controllerArtifact string, lifetime int) error {
	return seedWithProcessArtifact(dir, profileID, serviceArtifact, controllerArtifact, lifetime, "")
}

func seedWithProcessArtifact(dir, profileID, serviceArtifact, controllerArtifact string, lifetime int, processArtifact string) error {
	if lifetime < 300 || lifetime > 1200 {
		return fmt.Errorf("unsupported authority lifetime: expected 300-1200 seconds")
	}
	if _, e := os.Lstat(dir); !os.IsNotExist(e) {
		return fmt.Errorf("profile seed requires a new directory and new logical identity")
	}
	profile, e := credentialprofile.Find(profileID, 1)
	if e != nil {
		return e
	}
	absolute, e := filepath.Abs(dir)
	if e != nil {
		return e
	}
	dir = absolute
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	for _, name := range []string{"ca", "control", "application", "transport", "issuance", "observer", "authority-caller", "recovery", "device", "fixtures"} {
		if e = os.Mkdir(filepath.Join(dir, name), 0700); e != nil {
			return e
		}
	}
	if e = os.Mkdir(filepath.Join(dir, "device", "slots"), 0700); e != nil {
		return e
	}
	if e = os.Mkdir(filepath.Join(dir, "artifacts"), 0700); e != nil {
		return e
	}
	random, e := device.RandomID()
	if e != nil {
		return e
	}
	deviceID := "profile-" + random[:12]
	deploymentID := "lab-" + random[12:24]
	roots := map[string]caMaterial{}
	leaves := map[string]*x509.Certificate{}
	for _, role := range []string{"operational", "control", "application", "transport", "issuance", "observer", "recovery"} {
		key, e := newKey()
		if e != nil {
			return e
		}
		data, c, e := cert("Known Device profile demo "+role+" root", nil, key, nil, nil, true, nil)
		if e != nil {
			return e
		}
		roots[role] = caMaterial{c, key, data}
		if e = writeAtomic(filepath.Join(dir, role+"-root.crt"), data); e != nil {
			return e
		}
		if role == "operational" {
			if e = keyFile(filepath.Join(dir, "ca", "root.key"), key); e != nil {
				return e
			}
			continue
		}
		serverName := "profile-" + role
		if role == "recovery" {
			serverName = device.RecoverySubject(deviceID)
		}
		key, e = newKey()
		if e != nil {
			return e
		}
		usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if role == "observer" || role == "recovery" {
			usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		data, c, e = cert(serverName, []string{serverName}, key, roots[role].cert, roots[role].key, false, usage)
		if e != nil {
			return e
		}
		leaves[role] = c
		if e = writeAtomic(filepath.Join(dir, role, "cert.pem"), data); e != nil {
			return e
		}
		if e = keyFile(filepath.Join(dir, role, "key.pem"), key); e != nil {
			return e
		}
	}
	authorityKey, e := newKey()
	if e != nil {
		return e
	}
	authorityPEM, authorityLeaf, e := cert("profile-authority-caller", []string{"profile-authority-caller"}, authorityKey, roots["control"].cert, roots["control"].key, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if e != nil {
		return e
	}
	if e = writeAtomic(filepath.Join(dir, "authority-caller", "cert.pem"), authorityPEM); e != nil {
		return e
	}
	if e = keyFile(filepath.Join(dir, "authority-caller", "key.pem"), authorityKey); e != nil {
		return e
	}
	intermediateKey, e := newKey()
	if e != nil {
		return e
	}
	intermediatePEM, intermediate, e := cert("Known Device profile demo operational intermediate", nil, intermediateKey, roots["operational"].cert, roots["operational"].key, true, nil)
	if e != nil {
		return e
	}
	if e = writeAtomic(filepath.Join(dir, "ca", "intermediate.crt"), intermediatePEM); e != nil {
		return e
	}
	if e = keyFile(filepath.Join(dir, "ca", "intermediate.key"), intermediateKey); e != nil {
		return e
	}
	template := stableTemplate
	if profileID == credentialprofile.ReferenceID {
		template = referenceTemplate
	}
	if e = writeAtomic(filepath.Join(dir, "ca", "profile.tpl"), []byte(template)); e != nil {
		return e
	}
	provisioner, e := newKey()
	if e != nil {
		return e
	}
	if e = keyFile(filepath.Join(dir, "control", "provisioner.key"), provisioner); e != nil {
		return e
	}
	kid := device.Hash(elliptic.Marshal(elliptic.P256(), provisioner.X, provisioner.Y))
	if e = writeJSON(filepath.Join(dir, "control", "provisioner.json"), map[string]string{"kid": kid}); e != nil {
		return e
	}
	caConfig := map[string]any{"root": "/lab/operational-root.crt", "crt": "/lab/ca/intermediate.crt", "key": "/lab/ca/intermediate.key", "address": ":9000", "dnsNames": []string{"step-ca"}, "logger": map[string]any{"format": "common"}, "db": map[string]any{"type": "badgerv2", "dataSource": "/lab/ca/db"}, "authority": map[string]any{"backdate": "30s", "provisioners": []any{map[string]any{"type": "JWK", "name": "known-device-profile-lab", "key": map[string]any{"kty": "EC", "crv": "P-256", "kid": kid, "x": coordinate(provisioner.X), "y": coordinate(provisioner.Y)}, "claims": map[string]any{"minTLSCertDuration": "300s", "maxTLSCertDuration": "1200s", "defaultTLSCertDuration": "1200s", "disableRenewal": true, "disableSmallstepExtensions": true}, "options": map[string]any{"x509": map[string]any{"templateFile": "/lab/ca/profile.tpl"}}}}}}
	if e = writeJSON(filepath.Join(dir, "ca", "ca.json"), caConfig); e != nil {
		return e
	}
	limits := device.DefaultLimits()
	composition := device.Composition{ID: "local-http-lab", Version: 1, AuthorityTemplateDigest: device.Hash([]byte(template)), ApplicationID: "http-worker", SessionPolicy: "new-connection-no-state-transfer", ObservationRoute: "authenticated-application-callback", WithdrawalScope: "whole-service-lab"}
	if lifetime != 1200 {
		composition.Version = 2
		composition.AuthorityLifetimeSeconds = lifetime
	}
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	if serviceArtifact == "" {
		serviceArtifact = executable
	}
	if controllerArtifact == "" {
		return fmt.Errorf("profile seed requires --controller-artifact for the selected executable")
	}
	artifact, e := os.ReadFile(serviceArtifact)
	if e != nil {
		return e
	}
	artifactDigest := device.Hash(artifact)
	controllerBytes, e := os.ReadFile(controllerArtifact)
	if e != nil {
		return e
	}
	controllerDigest := device.Hash(controllerBytes)
	artifacts := []struct {
		path string
		data []byte
	}{{serviceArtifact, artifact}, {controllerArtifact, controllerBytes}}
	if processArtifact != "" {
		f, e := os.Open(processArtifact)
		if e != nil {
			return fmt.Errorf("process artifact unavailable")
		}
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128<<20 {
			f.Close()
			return fmt.Errorf("process artifact size or type refused")
		}
		data, e := io.ReadAll(io.LimitReader(f, (128<<20)+1))
		f.Close()
		if e != nil || len(data) == 0 || len(data) > 128<<20 {
			return fmt.Errorf("process artifact read refused")
		}
		composition.ID = "local-http-process-lab"
		composition.Version = 1
		composition.AuthorityLifetimeSeconds = lifetime
		composition.ProcessArtifactDigest = device.Hash(data)
		artifacts = append(artifacts, struct {
			path string
			data []byte
		}{processArtifact, data})
	}
	seenArtifacts := map[string]string{}
	for _, entry := range artifacts {
		target := filepath.Join(dir, "artifacts", filepath.Base(entry.path))
		if seen, present := seenArtifacts[target]; present {
			if seen != device.Hash(entry.data) {
				return fmt.Errorf("different artifacts require distinct file names")
			}
			continue
		}
		seenArtifacts[target] = device.Hash(entry.data)
		if e = writeAtomic(target, entry.data); e != nil {
			return e
		}
		if e = os.Chmod(target, 0755); e != nil {
			return e
		}
		f, e := os.Open(target)
		if e != nil {
			return e
		}
		syncErr := f.Sync()
		closeErr := f.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	artifactDir, e := os.Open(filepath.Join(dir, "artifacts"))
	if e != nil {
		return e
	}
	syncErr := artifactDir.Sync()
	closeErr := artifactDir.Close()
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, entry := range []struct{ role, cap string }{{"application", "durable-activation-and-fresh-observation"}, {"authority", "bounded-unknown-issuance"}, {"clock", "bounded-interval"}, {"entitlement", "current-entitlement"}, {"platform", "exact-peer-binding"}, {"transport", "explicit-access-observation"}, {"withdrawal", "durable-deny-and-session-inventory"}} {
		pin := artifactDigest
		if entry.role == "clock" || entry.role == "transport" {
			pin = controllerDigest
		}
		composition.Adapters = append(composition.Adapters, device.AdapterSpec{Role: entry.role, ID: "local-http-lab-" + entry.role, Version: "1", ArtifactDigest: pin, Capabilities: []string{entry.cap}})
	}
	trust := &device.TrustConfig{}
	for _, role := range []string{"application", "authority-transport", "control", "issuance", "observer", "operational", "recovery", "transport"} {
		r := device.RoleConfig{Role: role, RootCertificates: []string{filepath.Join(dir, role+"-root.crt")}, LeafPins: []string{}, SPKIPins: []string{}, AllowedIssuers: []string{}}
		if role == "authority-transport" {
			r.RootCertificates = []string{filepath.Join(dir, "operational-root.crt")}
			r.Endpoint = "https://step-ca:9000"
			r.PeerName = "step-ca"
			r.AllowedIssuers = []string{device.Hash(intermediate.Raw)}
		} else if role == "operational" {
			r.AllowedIssuers = []string{device.Hash(intermediate.Raw)}
		} else if role != "recovery" {
			r.Endpoint = "https://profile-" + role + ":9443"
			if role == "transport" {
				r.Endpoint = "https://profile-control:9445"
				r.PeerName = "profile-control"
			} else if role == "issuance" {
				r.Endpoint = "https://profile-control:9444"
				r.PeerName = "profile-control"
			} else {
				r.PeerName = "profile-" + role
			}
			r.LeafPins = []string{device.Hash(leaves[role].Raw)}
			r.SPKIPins = []string{device.Hash(leaves[role].RawSubjectPublicKeyInfo)}
			if role == "observer" {
				r.Endpoint = ""
			}
			if role == "issuance" {
				r.CallerLeafPins = []string{device.Hash(authorityLeaf.Raw)}
				r.CallerSPKIPins = []string{device.Hash(authorityLeaf.RawSubjectPublicKeyInfo)}
			}
		}
		trust.Roles = append(trust.Roles, r)
	}
	// The two role endpoints share a host, while their exact certificate SANs and roots remain disjoint.
	for _, role := range []string{"transport", "issuance"} {
		key, e := newKey()
		if e != nil {
			return e
		}
		data, c, e := cert("profile-control", []string{"profile-control"}, key, roots[role].cert, roots[role].key, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		if e != nil {
			return e
		}
		leaves[role] = c
		if e = writeAtomic(filepath.Join(dir, role, "cert.pem"), data); e != nil {
			return e
		}
		if e = keyFile(filepath.Join(dir, role, "key.pem"), key); e != nil {
			return e
		}
		for i := range trust.Roles {
			if trust.Roles[i].Role == role {
				trust.Roles[i].LeafPins = []string{device.Hash(c.Raw)}
				trust.Roles[i].SPKIPins = []string{device.Hash(c.RawSubjectPublicKeyInfo)}
			}
		}
	}
	cfg := device.Config{APIVersion: device.V2, DeploymentID: deploymentID, DeviceID: deviceID, StateDir: "/lab/device", ControlURL: "https://profile-control:9443", ApplicationURL: "https://profile-application:9443", ApplicationID: "http-worker", TransportEndpoint: "https://profile-control:9445", RecoveryCertificate: filepath.Join(dir, "recovery", "cert.pem"), RecoveryKey: "/lab/recovery/key.pem", ClockTrust: "trusted-system-clock", RequestTimeoutSeconds: 5, PlanTTLSeconds: 600, CredentialProfile: &profile, Composition: &composition, Trust: trust, Limits: &limits}
	snapshot, e := cfg.ResolveSnapshot()
	if e != nil {
		return e
	}
	digest := snapshot.Digest()
	for i := range cfg.Trust.Roles {
		for j, path := range cfg.Trust.Roles[i].RootCertificates {
			cfg.Trust.Roles[i].RootCertificates[j] = "/lab/" + filepath.Base(path)
		}
	}
	cfg.RecoveryCertificate = "/lab/recovery/cert.pem"
	if e = writeJSON(filepath.Join(dir, "device.json"), cfg); e != nil {
		return e
	}
	services := servicesConfig{SchemaVersion: 2, DeviceConfig: "/lab/device.json", Snapshot: snapshot.Bytes(), ConfigDigest: digest, CAURL: "https://step-ca:9000", ControlAddress: ":9443", ApplicationAddress: ":9443", TransportAddress: ":9445", IssuanceAddress: ":9444", RecoveryFingerprint: device.Hash(leaves["recovery"].Raw), RecoveryPublicKeyDigest: device.Hash(leaves["recovery"].RawSubjectPublicKeyInfo), ObserverFingerprint: device.Hash(leaves["observer"].Raw), ObserverPublicKeyDigest: device.Hash(leaves["observer"].RawSubjectPublicKeyInfo), AuthorityCallerFingerprint: device.Hash(authorityLeaf.Raw), AuthorityCallerPublicKeyDigest: device.Hash(authorityLeaf.RawSubjectPublicKeyInfo), TemplateDigest: composition.AuthorityTemplateDigest}
	if e = writeJSON(filepath.Join(dir, "services.json"), services); e != nil {
		return e
	}
	if e = writeJSON(filepath.Join(dir, "fixtures", "entitlement.json"), entitlement{DeploymentID: deploymentID, DeviceID: deviceID, Status: "authorized", Revision: 1, ExpiresAt: time.Now().UTC().Add(24 * time.Hour)}); e != nil {
		return e
	}
	if e = writeJSON(filepath.Join(dir, "fixtures", "policy.json"), policy{}); e != nil {
		return e
	}
	if e = writeJSON(filepath.Join(dir, "control", "ca-counts.json"), caCounts{}); e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"deviceId": deviceID, "deploymentId": deploymentID, "profile": profile.ID, "snapshotDigest": digest, "templateDigest": composition.AuthorityTemplateDigest, "scope": "local-generated-profile-lab"})
}
