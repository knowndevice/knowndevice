// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/sdk/credentialprofile"
	"knowndevice.local/knowndevice/sdk/device"
)

func TestExternalModuleValidatesBothSelectedProfiles(t *testing.T) {
	report, err := proveSDK()
	if err != nil || len(report.Profiles) != 2 || report.ModuleResolution != "workspace-local-replace" || report.Process != nil {
		t.Fatal("external import and validation proof failed")
	}
	for _, proof := range report.Profiles {
		if _, err := credentialprofile.Resolve(proof.ID, proof.Version, proof.PolicyDigest); err != nil || len(proof.CSRDigest) != 64 || len(proof.PublicKeyDigest) != 64 {
			t.Fatal("profile proof lacks the exact public binding")
		}
	}
}

func TestExternalModuleRefusesWrongProfileAndSigner(t *testing.T) {
	signer, err := newSigner()
	if err != nil {
		t.Fatal(err)
	}
	stable, _ := credentialprofile.Find(credentialprofile.StableID, 1)
	csr, err := stable.CreateCSR(signer, "sdk-consumer", 2)
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := credentialprofile.Find(credentialprofile.ReferenceID, 1)
	if _, err := validateCSR(reference, signer, csr); err == nil {
		t.Fatal("wrong profile accepted the stable request")
	}
	different, err := newSigner()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateCSR(stable, different, csr); err == nil {
		t.Fatal("different signer SPKI accepted the original request")
	}
}

func TestExternalModuleRefusesIssuedChainWithWrongSPKI(t *testing.T) {
	original, err := newSigner()
	if err != nil {
		t.Fatal(err)
	}
	different, err := newSigner()
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := credentialprofile.Find(credentialprofile.StableID, 1)
	csr, err := policy.CreateCSR(original, "sdk-consumer", 2)
	if err != nil {
		t.Fatal(err)
	}
	request, err := policy.ValidateCSR(csr, "sdk-consumer", 2)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	chain, roots := issuedFixture(t, policy, different, at)
	v := credentialprofile.Validation{Roots: roots, Earliest: at.Add(-time.Second), Latest: at.Add(time.Second), MinLifetime: 300 * time.Second, MaxLifetime: 1260 * time.Second, MaxBackdate: 60 * time.Second, MinimumRemaining: 120 * time.Second}
	if err := policy.ValidateChain(chain, csr, credentialprofile.Hash(request.RawSubjectPublicKeyInfo), "sdk-consumer", 2, v); err == nil {
		t.Fatal("issued chain with a different SPKI accepted the original CSR")
	}
	differentCSR, err := policy.CreateCSR(different, "sdk-consumer", 2)
	if err != nil {
		t.Fatal(err)
	}
	differentRequest, _ := policy.ValidateCSR(differentCSR, "sdk-consumer", 2)
	if err := policy.ValidateChain(chain, differentCSR, credentialprofile.Hash(differentRequest.RawSubjectPublicKeyInfo), "sdk-consumer", 2, v); err != nil {
		t.Fatal("control fixture with the exact CSR/SPKI was refused")
	}
}

func issuedFixture(t *testing.T, policy credentialprofile.Policy, signer *memorySigner, at time.Time) ([]byte, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "external consumer test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SignatureAlgorithm: x509.ECDSAWithSHA256, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: policy.Subject("sdk-consumer", 2)}, NotBefore: at.Add(-30 * time.Second), NotAfter: at.Add(570 * time.Second), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SignatureAlgorithm: x509.ECDSAWithSHA256}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, signer.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return chain, roots
}

func TestExternalModuleRefusesCredentialJSON(t *testing.T) {
	signer, err := newSigner()
	if err != nil {
		t.Fatal(err)
	}
	credential := device.Credential{TLS: tls.Certificate{PrivateKey: signer.key}}
	if data, err := json.Marshal(credential); len(data) != 0 || !errors.Is(err, device.ErrUnsupported) {
		t.Fatal("private signer became JSON")
	}
	marker := "EXTERNAL_CONSUMER_PRIVATE_MARKER"
	if err := json.Unmarshal([]byte(`{"TLS":{"PrivateKey":"`+marker+`"}}`), &credential); !errors.Is(err, device.ErrUnsupported) || strings.Contains(err.Error(), marker) || credential.TLS.PrivateKey != signer.key {
		t.Fatal("private input was accepted, exposed or replaced the signer")
	}
}
