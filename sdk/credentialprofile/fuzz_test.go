// SPDX-License-Identifier: Apache-2.0

package credentialprofile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func FuzzValidateCSR(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	for _, id := range []string{ReferenceID, StableID} {
		policy, _ := Find(id, 1)
		csr, err := policy.CreateCSR(key, "fuzz-device", 2)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(csr)
	}
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\ninvalid\n-----END CERTIFICATE REQUEST-----"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, id := range []string{ReferenceID, StableID} {
			policy, _ := Find(id, 1)
			r, err := policy.ValidateCSR(data, "fuzz-device", 2)
			if err == nil && (r == nil || r.CheckSignature() != nil || len(data) == 0 || len(data) > MaxCSRSize) {
				t.Fatal("accepted CSR violates the public parser boundary")
			}
		}
	})
}

func FuzzParseChain(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	at := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fuzz CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SignatureAlgorithm: x509.ECDSAWithSHA256, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		chain, err := ParseChain(data)
		if err != nil {
			return
		}
		if len(data) == 0 || len(data) > MaxChainSize || len(chain) == 0 || len(chain) > 8 {
			t.Fatal("accepted chain violates its public resource bounds")
		}
		for _, certificate := range chain {
			if certificate == nil || len(certificate.Raw) == 0 {
				t.Fatal("accepted chain contains an absent certificate")
			}
		}
	})
}
