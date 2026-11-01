// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
	"github.com/knowndevice/knowndevice/sdk/device"
)

type issuer struct {
	key  *ecdsa.PrivateKey
	root *x509.Certificate
}

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126)) }

func newIssuer(role string) (*issuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, device.ErrUnknown
	}
	id, err := serial()
	if err != nil {
		return nil, device.ErrUnknown
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: id, Subject: pkix.Name{CommonName: "conformance " + role + " root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SignatureAlgorithm: x509.ECDSAWithSHA256}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, device.ErrUnknown
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, device.ErrUnknown
	}
	return &issuer{key: key, root: root}, nil
}

func (i *issuer) sign(template *x509.Certificate, public any) ([][]byte, *x509.Certificate, error) {
	id, err := serial()
	if err != nil {
		return nil, nil, device.ErrUnknown
	}
	template.SerialNumber = id
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	der, err := x509.CreateCertificate(rand.Reader, template, i.root, public, i.key)
	if err != nil {
		return nil, nil, device.ErrUnknown
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, device.ErrUnknown
	}
	return [][]byte{der, i.root.Raw}, leaf, nil
}

func (i *issuer) server() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, device.ErrUnknown
	}
	now := time.Now().UTC()
	template := &x509.Certificate{Subject: pkix.Name{CommonName: "conformance loopback service"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true}
	chain, leaf, err := i.sign(template, key.Public())
	return tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, err
}

func (i *issuer) recovery(deviceID string) (device.Credential, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return device.Credential{}, device.ErrUnknown
	}
	now := time.Now().UTC()
	subject := device.RecoverySubject(deviceID)
	template := &x509.Certificate{Subject: pkix.Name{CommonName: subject}, DNSNames: []string{subject}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	chain, leaf, err := i.sign(template, key.Public())
	return device.Credential{Recovery: true, DeviceID: deviceID, TLS: tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}}, err
}

func targetVector(p device.Plan, policy credentialprofile.Policy) (device.Credential, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return device.Credential{}, device.ErrUnknown
	}
	csr, err := policy.CreateCSR(key, p.DeviceID, p.TargetGeneration)
	if err != nil {
		return device.Credential{}, device.ErrDenied
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return device.Credential{}, device.ErrDenied
	}
	return device.Credential{Handle: device.Handle{Binding: p.Binding(), PublicKeyDigest: device.Hash(spki)}, CSR: csr, TLS: tls.Certificate{PrivateKey: key}}, nil
}

func (i *issuer) issue(policy credentialprofile.Policy, p device.Plan, csr []byte) ([][]byte, *x509.Certificate, error) {
	request, err := policy.ValidateCSR(csr, p.DeviceID, p.TargetGeneration)
	if err != nil {
		return nil, nil, device.ErrDenied
	}
	now := time.Now().UTC()
	template := &x509.Certificate{RawSubject: request.RawSubject, Subject: request.Subject, DNSNames: request.DNSNames, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(1170 * time.Second), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	return i.sign(template, request.PublicKey)
}

func publicChain(chain [][]byte) []byte {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

func credentialBinding(k device.Credential) device.CredentialBinding {
	b := k.Handle.Binding
	block, _ := pem.Decode(k.CSR)
	csrDigest := ""
	if block != nil {
		csrDigest = device.Hash(block.Bytes)
	}
	fingerprint := ""
	if len(k.TLS.Certificate) > 0 {
		fingerprint = device.Hash(k.TLS.Certificate[0])
	}
	return device.CredentialBinding{DeploymentID: b.DeploymentID, DeviceID: b.DeviceID, OperationID: b.OperationID, PlanDigest: b.PlanDigest, ConfigDigest: b.ConfigDigest, SnapshotDigest: b.SnapshotDigest, ProfileID: b.ProfileID, ProfileVersion: b.ProfileVersion, ProfileDigest: b.ProfileDigest, Generation: b.Generation, PublicKeyDigest: k.Handle.PublicKeyDigest, CertificateFingerprint: fingerprint, CSRDigest: csrDigest}
}
