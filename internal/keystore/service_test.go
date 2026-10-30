// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServiceCredentialRequiresExplicitPurpose(t *testing.T) {
	path := keyPath(t)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, signerPath := filepath.Join(path, "service.crt"), filepath.Join(path, "service.key")
	if err := os.WriteFile(signerPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	certificate := func(t *testing.T, usages []x509.ExtKeyUsage, edit func(*x509.Certificate)) {
		t.Helper()
		// Service identities use their role's SAN/pin validator. They can have
		// several SANs and a subject outside the device credential convention.
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "service.invalid", Organization: []string{"fixture"}}, DNSNames: []string{"service.invalid", "service-alias.invalid"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, SignatureAlgorithm: x509.ECDSAWithSHA256}
		if edit != nil {
			edit(template)
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	certificate(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
	server, err := LoadServiceCredential(certPath, signerPath, x509.ExtKeyUsageServerAuth)
	if err != nil {
		t.Fatalf("explicit serverAuth service failed: %v", err)
	}
	if _, exposed := server.PrivateKey.(*ecdsa.PrivateKey); exposed {
		t.Fatal("service loader exposed a private scalar")
	}
	if _, err := LoadCredential(certPath, signerPath); err == nil {
		t.Fatal("server service was accepted as a recovery-profile credential")
	}
	if _, err := LoadServiceCredential(certPath, signerPath, x509.ExtKeyUsageClientAuth); err == nil {
		t.Fatal("server-only leaf satisfied clientAuth purpose")
	}
	if _, err := LoadServiceCredential(certPath, signerPath, x509.ExtKeyUsageAny); err == nil {
		t.Fatal("unspecified service purpose was accepted")
	}
	certificate(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, nil)
	for _, purpose := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := LoadServiceCredential(certPath, signerPath, purpose); err != nil {
			t.Fatalf("legacy specific EKU was refused: %v", err)
		}
	}
	certificate(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	if _, err := LoadServiceCredential(certPath, signerPath, x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*x509.Certificate)
	}{{"ca", func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }}, {"no-digital-signature", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }}, {"any-eku", func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageAny) }}, {"wrong-signature", func(c *x509.Certificate) { c.SignatureAlgorithm = x509.ECDSAWithSHA384 }}, {"unhandled-critical", func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
	}}} {
		t.Run(test.name, func(t *testing.T) {
			certificate(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, test.edit)
			if _, err := LoadServiceCredential(certPath, signerPath, x509.ExtKeyUsageServerAuth); err == nil {
				t.Fatal("invalid service leaf was accepted")
			}
		})
	}
	certificate(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, _ := x509.MarshalPKCS8PrivateKey(other)
	if err := os.WriteFile(signerPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServiceCredential(certPath, signerPath, x509.ExtKeyUsageServerAuth); err == nil {
		t.Fatal("service certificate was paired with another signer")
	}
}
