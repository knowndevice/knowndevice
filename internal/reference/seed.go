// SPDX-License-Identifier: Apache-2.0

// Package reference runs the generated-data lab. It is not a production registry.
package reference

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/knowndevice/knowndevice/internal/device"
)

type entitlement struct {
	DeviceID            string `json:"deviceId"`
	Status              string `json:"status"`
	RecoveryFingerprint string `json:"recoveryFingerprint"`
	ControlFingerprint  string `json:"controlFingerprint"`
}
type policy struct {
	DenyProbe        bool   `json:"denyProbe"`
	DenyGeneration   uint64 `json:"denyGeneration"`
	LoseCAResponse   bool   `json:"loseCAResponse"`
	StaleReply       bool   `json:"staleReply"`
	DenyActivation   bool   `json:"denyActivation"`
	ShortCertificate bool   `json:"shortCertificate"`
}

func Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kd-reference seed|control|application|responder|check --dir PATH")
	}
	flags := flag.NewFlagSet("kd-reference", flag.ContinueOnError)
	dir := flags.String("dir", "/lab", "Private generated-data root")
	cli := flags.String("cli", "/usr/local/bin/knowndevice", "CLI executable used by check")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	switch args[0] {
	case "seed":
		return seed(*dir)
	case "control":
		return runControl(*dir)
	case "application":
		return runApplication(*dir)
	case "responder":
		return runResponder(*dir)
	case "check":
		return runChecks(*dir, *cli)
	default:
		return fmt.Errorf("unknown reference service")
	}
}

func atomic(path string, b []byte) error {
	f, err := os.OpenFile(path+".pending", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(path+".pending", path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomic(path, append(b, '\n'))
}
func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return device.DecodeStrict(f, v)
}

func cert(subject string, dns []string, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool) ([]byte, *x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: subject}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(48 * time.Hour), DNSNames: dns, BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
	if ca {
		t.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		t.MaxPathLen = 1
	} else {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	if parent == nil {
		parent = t
		parentKey = key
	}
	b, err := x509.CreateCertificate(rand.Reader, t, parent, key.Public(), parentKey)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(b)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}), parsed, err
}

func keyFile(path string, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return atomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}
func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
func b64(b []byte) string                { return base64.RawURLEncoding.EncodeToString(b) }
func coordinate(n *big.Int) string       { b := make([]byte, 32); n.FillBytes(b); return b64(b) }

func seed(dir string) error {
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		return fmt.Errorf("seed requires a new directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for _, p := range []string{"ca", "control", "application", "responder", "recovery", "device", "broker", "fixtures"} {
		if err := os.Mkdir(filepath.Join(dir, p), 0700); err != nil {
			return err
		}
	}
	rootKey, err := newKey()
	if err != nil {
		return err
	}
	rootPEM, root, err := cert("Known Device demo root", nil, rootKey, nil, nil, true)
	if err != nil {
		return err
	}
	if err := atomic(filepath.Join(dir, "root.crt"), rootPEM); err != nil {
		return err
	}
	if err := keyFile(filepath.Join(dir, "ca", "root.key"), rootKey); err != nil {
		return err
	}
	intermediateKey, err := newKey()
	if err != nil {
		return err
	}
	intermediatePEM, _, err := cert("Known Device demo intermediate", nil, intermediateKey, root, rootKey, true)
	if err != nil {
		return err
	}
	if err := atomic(filepath.Join(dir, "ca", "intermediate.crt"), intermediatePEM); err != nil {
		return err
	}
	if err := keyFile(filepath.Join(dir, "ca", "intermediate.key"), intermediateKey); err != nil {
		return err
	}
	for _, p := range []struct {
		dir, subject string
		dns          []string
	}{{"control", "broker-control", []string{"broker-control", "localhost"}}, {"application", "application", []string{"application", "localhost"}}, {"responder", "responder", []string{"responder"}}, {"recovery", device.RecoverySubject("gateway-1"), []string{device.RecoverySubject("gateway-1")}}} {
		key, err := newKey()
		if err != nil {
			return err
		}
		chain, leaf, err := cert(p.subject, p.dns, key, root, rootKey, false)
		if err != nil {
			return err
		}
		if err := atomic(filepath.Join(dir, p.dir, "cert.pem"), chain); err != nil {
			return err
		}
		if err := keyFile(filepath.Join(dir, p.dir, "key.pem"), key); err != nil {
			return err
		}
		if p.dir == "recovery" {
			if err := writeJSON(filepath.Join(dir, "fixtures", "entitlement.json"), entitlement{DeviceID: "gateway-1", Status: "authorized", RecoveryFingerprint: device.Hash(leaf.Raw)}); err != nil {
				return err
			}
		}
	}
	provisioner, err := newKey()
	if err != nil {
		return err
	}
	if err := keyFile(filepath.Join(dir, "control", "provisioner.key"), provisioner); err != nil {
		return err
	}
	kid := device.Hash(elliptic.Marshal(elliptic.P256(), provisioner.X, provisioner.Y))
	var ent entitlement
	if err := readJSON(filepath.Join(dir, "fixtures", "entitlement.json"), &ent); err != nil {
		return err
	}
	controlPEM, err := os.ReadFile(filepath.Join(dir, "control", "cert.pem"))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(controlPEM)
	if block == nil {
		return fmt.Errorf("control certificate invalid")
	}
	ent.ControlFingerprint = device.Hash(block.Bytes)
	if err := writeJSON(filepath.Join(dir, "fixtures", "entitlement.json"), ent); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "control", "provisioner.json"), map[string]string{"kid": kid}); err != nil {
		return err
	}
	caConfig := map[string]any{"root": "/lab/root.crt", "crt": "/lab/ca/intermediate.crt", "key": "/lab/ca/intermediate.key", "address": ":9000", "dnsNames": []string{"step-ca", "localhost"}, "logger": map[string]any{"format": "common"}, "db": map[string]any{"type": "badgerv2", "dataSource": "/lab/ca/db"}, "authority": map[string]any{"provisioners": []any{map[string]any{"type": "JWK", "name": "known-device-lab", "key": map[string]any{"kty": "EC", "crv": "P-256", "kid": kid, "x": coordinate(provisioner.X), "y": coordinate(provisioner.Y)}, "claims": map[string]any{"minTLSCertDuration": "1s", "maxTLSCertDuration": "24h", "defaultTLSCertDuration": "1h"}}}}}
	if err := writeJSON(filepath.Join(dir, "ca", "ca.json"), caConfig); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "fixtures", "policy.json"), policy{}); err != nil {
		return err
	}
	cfg := device.Config{APIVersion: "knowndevice/v1alpha1", DeviceID: "gateway-1", StateDir: "/lab/device", ControlURL: "https://broker-control:9443", ApplicationURL: "https://application:9443", ApplicationID: "mqtt-worker", MQTTEndpoint: "tls://broker-control:8883", RootCertificate: "/lab/root.crt", RecoveryCertificate: "/lab/recovery/cert.pem", RecoveryKey: "/lab/recovery/key.pem", ClockTrust: "trusted-system-clock", RequestTimeoutSeconds: 5, PlanTTLSeconds: 600}
	if err := writeJSON(filepath.Join(dir, "device.json"), cfg); err != nil {
		return err
	}
	broker := "listener 8883 0.0.0.0\nallow_anonymous false\nrequire_certificate true\nuse_identity_as_username true\ncafile /lab/root.crt\ncertfile /lab/control/cert.pem\nkeyfile /lab/control/key.pem\nacl_file /lab/broker/acl\npersistence false\nlog_dest stdout\nlog_type error\nuser root\n"
	if err := atomic(filepath.Join(dir, "broker", "mosquitto.conf"), []byte(broker)); err != nil {
		return err
	}
	return atomic(filepath.Join(dir, "broker", "acl"), []byte("user responder\ntopic read kd/+/+/request\ntopic write kd/+/+/response\n"))
}
