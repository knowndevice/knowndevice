// SPDX-License-Identifier: Apache-2.0

package credentialprofile

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func intervalCertificate(t *testing.T, template, parent *x509.Certificate, key, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestPublicChainRejectsNilCertificate(t *testing.T) {
	policy, _ := Find(StableID, 1)
	now := time.Now().UTC().Truncate(time.Second)
	ca, caKey, roots := testCA(t, now)
	certs, err := ParseChain(testLeaf(t, policy, testKey(t), ca, caKey, now, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range [][]*x509.Certificate{{nil}, {certs[0], nil}} {
		if err := policy.ValidatePublicChain(chain, "gateway", 2, Validation{Roots: roots, Earliest: now, Latest: now}); err == nil {
			t.Fatal("nil certificate accepted")
		}
	}
}

func TestClosedIntervalCannotBridgeDisjointTrustPaths(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootKey, issuerKey := testKey(t), testKey(t)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "shared root key"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Second)}
	first := intervalCertificate(t, rootTemplate, rootTemplate, rootKey, rootKey)
	rootTemplate.SerialNumber = big.NewInt(2)
	rootTemplate.NotBefore, rootTemplate.NotAfter = now.Add(2*time.Second), now.Add(time.Hour)
	second := intervalCertificate(t, rootTemplate, rootTemplate, rootKey, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(first)
	roots.AddCert(second)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "one allowed issuer"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	issuer := intervalCertificate(t, issuerTemplate, first, issuerKey, rootKey)
	for _, id := range []string{ReferenceID, StableID} {
		t.Run(id, func(t *testing.T) {
			policy, _ := Find(id, 1)
			key := testKey(t)
			leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: policy.Subject("gateway", 2)}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(20 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
			if id == ReferenceID {
				leafTemplate.DNSNames = []string{leafTemplate.Subject.CommonName}
			}
			leaf := intervalCertificate(t, leafTemplate, issuer, key, issuerKey)
			chain := []*x509.Certificate{leaf, issuer}
			for _, at := range []time.Time{now, now.Add(3 * time.Second)} {
				if err := policy.ValidatePublicChain(chain, "gateway", 2, Validation{Roots: roots, Earliest: at, Latest: at, AllowedIssuers: []string{Hash(issuer.Raw)}}); err != nil {
					t.Fatalf("fixture endpoint must have a valid allowed path: %v", err)
				}
			}
			middle := now.Add(1500 * time.Millisecond)
			if err := policy.ValidatePublicChain(chain, "gateway", 2, Validation{Roots: roots, Earliest: middle, Latest: middle}); err == nil {
				t.Fatal("fixture must have a trust gap between its valid endpoints")
			}
			v := Validation{Roots: roots, Earliest: now, Latest: now.Add(3 * time.Second), AllowedIssuers: []string{Hash(issuer.Raw)}}
			if err := policy.ValidatePublicChain(chain, "gateway", 2, v); err == nil {
				t.Fatal("different endpoint paths concealed a trust gap inside the assessed interval")
			}
			rootTemplate.SerialNumber = big.NewInt(5)
			rootTemplate.NotBefore = now.Add(-time.Hour)
			continuous := intervalCertificate(t, rootTemplate, rootTemplate, rootKey, rootKey)
			v.Roots = roots.Clone()
			v.Roots.AddCert(continuous)
			if err := policy.ValidatePublicChain(chain, "gateway", 2, v); err != nil {
				t.Fatalf("one complete allowed path must cover the interval: %v", err)
			}
			if err := policy.ValidatePublicChain([]*x509.Certificate{leaf, nil}, "gateway", 2, v); err == nil {
				t.Fatal("nil intermediate accepted")
			}
		})
	}
}
