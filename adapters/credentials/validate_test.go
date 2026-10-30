// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/adapters/internal/testtls"
	"knowndevice.local/knowndevice/sdk/device"
)

func TestCertificateValidation(t *testing.T) {
	profile := testtls.New(t)
	key := testtls.Key(t)
	subject := device.Subject("device-a", 2)
	csr := testtls.CSR(t, subject, key)
	for _, test := range []struct {
		name      string
		change    func(*x509.Certificate)
		wrongKey  bool
		untrusted bool
		wantError bool
	}{
		{name: "valid"},
		{name: "wrong key", wrongKey: true, wantError: true},
		{name: "wrong CN", change: func(c *x509.Certificate) { c.Subject.CommonName = device.Subject("device-a", 1) }, wantError: true},
		{name: "extra subject", change: func(c *x509.Certificate) { c.Subject.Organization = []string{"unexpected"} }, wantError: true},
		{name: "extra DNS", change: func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "extra.invalid") }, wantError: true},
		{name: "no client auth", change: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }, wantError: true},
		{name: "any usage", change: func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageAny) }, wantError: true},
		{name: "expired", change: func(c *x509.Certificate) {
			c.NotBefore = profile.Now.Add(-2 * time.Hour)
			c.NotAfter = profile.Now.Add(-time.Hour)
		}, wantError: true},
		{name: "not yet valid", change: func(c *x509.Certificate) { c.NotBefore = profile.Now.Add(time.Minute) }, wantError: true},
		{name: "CA leaf", change: func(c *x509.Certificate) { c.IsCA = true }, wantError: true},
		{name: "untrusted", untrusted: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			public := key.Public()
			if test.wrongKey {
				public = testtls.Key(t).Public()
			}
			_, chain := profile.Sign(t, subject, public, test.change)
			roots := profile.Roots
			if test.untrusted {
				roots = testtls.New(t).Roots
			}
			err := ValidateCertificate(chain, csr, subject, roots, profile.Now)
			if (err != nil) != test.wantError {
				t.Fatalf("validation error = %v, want error %t", err, test.wantError)
			}
		})
	}
}

func TestCSRSignatureIdentityAndEncoding(t *testing.T) {
	key := testtls.Key(t)
	subject := device.Subject("device-a", 2)
	valid := testtls.CSR(t, subject, key)
	block, _ := pem.Decode(valid)
	block.Bytes[len(block.Bytes)-1] ^= 0x01
	badSignature := pem.EncodeToMemory(block)
	for _, data := range [][]byte{badSignature, append(valid, []byte("trailing secret")...), []byte(strings.Repeat("x", MaxCSRSize+1)), testtls.CSR(t, device.Subject("device-b", 2), key)} {
		if _, err := ValidateCSR(data, subject); err == nil {
			t.Fatal("invalid CSR accepted")
		}
	}
	if _, err := ParseCertificateChain([]byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----")); err == nil {
		t.Fatal("private material accepted as a chain")
	}
	if exactSubject(pkix.Name{CommonName: subject}, subject) {
		t.Fatal("unparsed subject must not bypass exact attribute check")
	}
}

func TestCertificateWhitespaceCannotCreateAnEmptyChain(t *testing.T) {
	profile := testtls.New(t)
	key := testtls.Key(t)
	subject := device.Subject("device-a", 2)
	csr := testtls.CSR(t, subject, key)
	for _, chain := range [][]byte{nil, []byte(" "), []byte("\n\t\r\n ")} {
		if _, err := ParseCertificateChain(chain); err == nil {
			t.Fatal("empty certificate chain accepted")
		}
		if _, err := CertificateFingerprint(chain); err == nil {
			t.Fatal("empty chain has a fingerprint")
		}
		if err := ValidateCertificate(chain, csr, subject, profile.Roots, profile.Now); err == nil {
			t.Fatal("empty chain authorized a CSR")
		}
	}
	_, valid := profile.Sign(t, subject, key.Public(), nil)
	withWhitespace := append(append([]byte("\n "), valid...), '\n', '\t')
	if err := ValidateCertificate(withWhitespace, csr, subject, profile.Roots, profile.Now); err != nil {
		t.Fatal("valid PEM whitespace rejected")
	}
}

func TestSignerAndRecoveryBoundary(t *testing.T) {
	profile := testtls.New(t)
	credential := profile.Credential(t, device.Binding{DeviceID: "device-a", OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Generation: 2, Slot: "B"})
	if err := ValidateCredential(credential); err != nil {
		t.Fatal(err)
	}
	wrong := credential
	wrong.TLS.PrivateKey = testtls.Key(t)
	if err := ValidateCredential(wrong); err == nil {
		t.Fatal("wrong signer accepted")
	}
	wrong = credential
	wrong.TLS.PrivateKey = (*ecdsa.PrivateKey)(nil)
	if err := ValidateCredential(wrong); err == nil {
		t.Fatal("nil signer accepted")
	}
	wrong = credential
	wrong.Handle.PublicKeyDigest = device.Hash([]byte("wrong"))
	if err := ValidateCredential(wrong); err == nil {
		t.Fatal("wrong handle accepted")
	}
	recovery := profile.Recovery(t, "device-a")
	if err := ValidateRecovery(recovery, profile.Roots, profile.Now); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecovery(recovery, profile.Roots, profile.Now.Add(time.Hour)); err == nil {
		t.Fatal("expired recovery accepted")
	}
	if err := ValidateRecovery(recovery, testtls.New(t).Roots, profile.Now); err == nil {
		t.Fatal("untrusted recovery accepted")
	}
	recovery.Handle = credential.Handle
	if err := ValidateCredential(recovery); err == nil {
		t.Fatal("recovery invented an operational generation")
	}
}
