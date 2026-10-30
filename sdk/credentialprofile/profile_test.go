// SPDX-License-Identifier: Apache-2.0

package credentialprofile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func testCA(t *testing.T, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	k := testKey(t)
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign, SignatureAlgorithm: x509.ECDSAWithSHA256}
	der, e := x509.CreateCertificate(rand.Reader, c, c, k.Public(), k)
	if e != nil {
		t.Fatal(e)
	}
	c, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c)
	return c, k, roots
}
func testLeaf(t *testing.T, p Policy, k *ecdsa.PrivateKey, ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time, change func(*x509.Certificate)) []byte {
	t.Helper()
	c := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: p.Subject("gateway", 2)}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(1170 * time.Second), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SignatureAlgorithm: x509.ECDSAWithSHA256}
	if p.ID == ReferenceID {
		c.DNSNames = []string{c.Subject.CommonName}
	}
	if change != nil {
		change(c)
	}
	der, e := x509.CreateCertificate(rand.Reader, c, ca, k.Public(), caKey)
	if e != nil {
		t.Fatal(e)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
}
func TestP1StrictProfilesAndRawAttributes(t *testing.T) {
	for _, id := range []string{ReferenceID, StableID} {
		t.Run(id, func(t *testing.T) {
			p, _ := Find(id, 1)
			k := testKey(t)
			csr, e := p.CreateCSR(k, "gateway", 2)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = p.ValidateCSR(csr, "gateway", 2); e != nil {
				t.Fatal(e)
			}
			for _, name := range []string{"extra-cn", "extra-attribute", "wrong-san", "extra-extension", "wrong-signature", "bad-signature"} {
				t.Run(name, func(t *testing.T) {
					r := &x509.CertificateRequest{Subject: pkix.Name{CommonName: p.Subject("gateway", 2)}, SignatureAlgorithm: x509.ECDSAWithSHA256}
					if id == ReferenceID {
						r.DNSNames = []string{r.Subject.CommonName}
					}
					switch name {
					case "extra-cn":
						r.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: cnOID, Value: "other"}}
						r.Subject.Organization = []string{"unexpected"}
					case "extra-attribute":
						r.Attributes = []pkix.AttributeTypeAndValueSET{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, Value: [][]pkix.AttributeTypeAndValue{{{Type: cnOID, Value: "password"}}}}}
					case "wrong-san":
						r.DNSNames = []string{"wrong.invalid"}
					case "extra-extension":
						r.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
					case "wrong-signature":
						r.SignatureAlgorithm = x509.ECDSAWithSHA512
					}
					der, e := x509.CreateCertificateRequest(rand.Reader, r, k)
					if e != nil {
						t.Fatal(e)
					}
					if name == "bad-signature" {
						der[len(der)-1] ^= 1
					}
					bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
					if _, e = p.ValidateCSR(bad, "gateway", 2); e == nil {
						t.Fatal("invalid CSR accepted")
					}
				})
			}
			other, _ := Find(ReferenceID, 1)
			if id == ReferenceID {
				other, _ = Find(StableID, 1)
			}
			if _, e = other.ValidateCSR(csr, "gateway", 2); e == nil {
				t.Fatal("cross-profile CSR accepted")
			}
			if _, e = Resolve(id, 2, p.PolicyDigest); e == nil {
				t.Fatal("unknown version accepted")
			}
			if _, e = Resolve(id, 1, Hash([]byte("changed"))); e == nil {
				t.Fatal("changed policy digest accepted")
			}
		})
	}
}
func TestP2P8ExactKeyAndPublicChain(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, caKey, roots := testCA(t, now)
	for _, id := range []string{ReferenceID, StableID} {
		t.Run(id, func(t *testing.T) {
			p, _ := Find(id, 1)
			k := testKey(t)
			csr, e := p.CreateCSR(k, "gateway", 2)
			if e != nil {
				t.Fatal(e)
			}
			request, _ := p.ValidateCSR(csr, "gateway", 2)
			chain := testLeaf(t, p, k, ca, caKey, now, nil)
			v := Validation{Roots: roots, Earliest: now.Add(-time.Second), Latest: now.Add(time.Second), AllowedIssuers: []string{Hash(ca.Raw)}, MinLifetime: 300 * time.Second, MaxLifetime: 1260 * time.Second, MaxBackdate: 60 * time.Second, MinimumRemaining: 120 * time.Second}
			if e = p.ValidateChain(chain, csr, Hash(request.RawSubjectPublicKeyInfo), "gateway", 2, v); e != nil {
				t.Fatal(e)
			}
			if e = p.ValidateChain(testLeaf(t, p, testKey(t), ca, caKey, now, nil), csr, Hash(request.RawSubjectPublicKeyInfo), "gateway", 2, v); e == nil {
				t.Fatal("another CSR/key accepted")
			}
			duplicate := append(append([]byte{}, chain...), chain...)
			if e = p.ValidateChain(duplicate, csr, Hash(request.RawSubjectPublicKeyInfo), "gateway", 2, v); e == nil {
				t.Fatal("multiple candidate chains accepted")
			}
			for _, change := range []func(*x509.Certificate){func(c *x509.Certificate) { c.Subject.Organization = []string{"extra"} }, func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageAny) }, func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
			}, func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "extra.invalid") }} {
				if e = p.ValidateChain(testLeaf(t, p, k, ca, caKey, now, change), csr, Hash(request.RawSubjectPublicKeyInfo), "gateway", 2, v); e == nil {
					t.Fatal("undeclared certificate identity/usage accepted")
				}
			}
			if id == StableID {
				extraEKU := testLeaf(t, p, k, ca, caKey, now, func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) })
				if e = p.ValidateChain(extraEKU, csr, Hash(request.RawSubjectPublicKeyInfo), "gateway", 2, v); e == nil {
					t.Fatal("stable extra EKU accepted")
				}
			}
			empty := []byte(" \n")
			if _, e = ParseChain(empty); e == nil {
				t.Fatal("empty chain accepted")
			}
			if _, e = p.ValidateCSR(make([]byte, MaxCSRSize+1), "gateway", 2); e == nil {
				t.Fatal("oversize CSR accepted")
			}
		})
	}
}
func TestP17ClosedIntervalAndActivationMargin(t *testing.T) {
	p, _ := Find(StableID, 1)
	now := time.Now().UTC().Truncate(time.Second)
	ca, caKey, roots := testCA(t, now)
	k := testKey(t)
	csr, _ := p.CreateCSR(k, "gateway", 2)
	r, _ := p.ValidateCSR(csr, "gateway", 2)
	chain := testLeaf(t, p, k, ca, caKey, now, nil)
	for _, v := range []Validation{{Roots: roots, Earliest: now.Add(-31 * time.Second), Latest: now}, {Roots: roots, Earliest: now.Add(1169 * time.Second), Latest: now.Add(1170 * time.Second)}, {Roots: roots, Earliest: now.Add(1049 * time.Second), Latest: now.Add(1051 * time.Second), MinimumRemaining: 120 * time.Second}} {
		if e := p.ValidateChain(chain, csr, Hash(r.RawSubjectPublicKeyInfo), "gateway", 2, v); e == nil {
			t.Fatal("crossing interval/margin accepted")
		}
	}
}

func TestP1ReferenceCSRRejectsIgnoredSANGeneralName(t *testing.T) {
	p, _ := Find(ReferenceID, 1)
	k := testKey(t)
	subject := p.Subject("gateway", 2)
	value, e := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte(subject)}, {Class: 2, Tag: 8, Bytes: []byte{42, 3, 4}}})
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}, ExtraExtensions: []pkix.Extension{{Id: sanOID, Value: value}}, SignatureAlgorithm: x509.ECDSAWithSHA256}, k)
	if e != nil {
		t.Fatal(e)
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, e = p.ValidateCSR(csr, "gateway", 2); e == nil {
		t.Fatal("ignored additional GeneralName accepted")
	}
}
