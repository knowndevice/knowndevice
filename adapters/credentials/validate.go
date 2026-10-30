// SPDX-License-Identifier: Apache-2.0

// Package credentials checks the public material at adapter boundaries.
package credentials

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"reflect"
	"time"

	"knowndevice.local/knowndevice/sdk/credentialprofile"
	"knowndevice.local/knowndevice/sdk/device"
)

const (
	MaxCSRSize   = 16 << 10
	MaxChainSize = 64 << 10
)

var commonNameOID = asn1.ObjectIdentifier{2, 5, 4, 3}
var subjectAltNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}

func exactSubject(name pkix.Name, subject string) bool {
	if subject == "" || name.CommonName != subject || len(name.Names) != 1 {
		return false
	}
	return name.Names[0].Type.Equal(commonNameOID) && name.Names[0].Value == subject
}

func ParseCertificateChain(chain []byte) ([]*x509.Certificate, error) {
	return credentialprofile.ParseChain(chain)
}
func ValidateCSR(data []byte, subject string) (*x509.CertificateRequest, error) {
	return credentialprofile.ValidateReferenceCSR(data, subject)
}

func ValidateCertificate(chain, csr []byte, subject string, roots *x509.CertPool, now time.Time) error {
	if roots == nil || len(roots.Subjects()) == 0 || now.IsZero() {
		return fmt.Errorf("certificate trust roots and trusted time are required")
	}
	request, err := ValidateCSR(csr, subject)
	if err != nil {
		return err
	}
	certificates, err := ParseCertificateChain(chain)
	if err != nil {
		return err
	}
	leaf := certificates[0]
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, request.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("certificate does not match the CSR and generation")
	}
	if err := ValidateIdentity(leaf, subject); err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: subject, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("certificate trust, identity, usage or validity check failed")
	}
	return nil
}

func ValidateIdentity(leaf *x509.Certificate, subject string) error {
	return credentialprofile.ValidateReferenceIdentity(leaf, subject)
}

// ValidateTLSCertificate checks the actual signer, not a supplied Leaf cache.
// Certificate purpose, issuer trust and time remain caller-specific checks.
func ValidateTLSCertificate(certificate tls.Certificate) (*x509.Certificate, error) {
	if len(certificate.Certificate) == 0 || len(certificate.Certificate) > 8 {
		return nil, fmt.Errorf("missing or oversized credential chain")
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok || signer == nil {
		return nil, fmt.Errorf("credential requires a signer handle")
	}
	value := reflect.ValueOf(signer)
	if value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, fmt.Errorf("credential requires a nonnil signer handle")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("invalid credential signer public key")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, public) {
		return nil, fmt.Errorf("credential certificate does not match the signer")
	}
	size := 0
	for _, der := range certificate.Certificate {
		size += len(der)
		if size > MaxChainSize {
			return nil, fmt.Errorf("oversized credential chain")
		}
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, fmt.Errorf("invalid public certificate in credential chain")
		}
	}
	return leaf, nil
}

// ValidateCredential accepts signer handles and checks both public-key bindings.
// It does not classify recovery entitlement or operational certificate health.
func ValidateCredential(credential device.Credential) error {
	if credential.Recovery {
		if !device.ValidDeviceID(credential.DeviceID) || credential.Handle != (device.Handle{}) {
			return fmt.Errorf("recovery credential must have only a device scope")
		}
	} else {
		if err := credential.Handle.Validate(); err != nil {
			return err
		}
		if credential.DeviceID != "" && credential.DeviceID != credential.Handle.Binding.DeviceID {
			return fmt.Errorf("operational credential device scope mismatch")
		}
	}
	leaf, err := ValidateTLSCertificate(credential.TLS)
	if err != nil {
		return err
	}
	if !credential.Recovery && device.Hash(leaf.RawSubjectPublicKeyInfo) != credential.Handle.PublicKeyDigest {
		return fmt.Errorf("credential signer does not match the handle")
	}
	if credential.Recovery {
		return ValidateIdentity(leaf, device.RecoverySubject(credential.DeviceID))
	}
	if credential.Handle.Binding.ProfileID != "" {
		b := credential.Handle.Binding
		p, e := credentialprofile.Resolve(b.ProfileID, b.ProfileVersion, b.ProfileDigest)
		if e != nil {
			return e
		}
		return p.ValidateLeaf(leaf, b.DeviceID, b.Generation)
	}
	return ValidateIdentity(leaf, device.Subject(credential.Handle.Binding.DeviceID, credential.Handle.Binding.Generation))
}

func ValidateRecovery(credential device.Credential, roots *x509.CertPool, now time.Time) error {
	if !credential.Recovery || roots == nil || len(roots.Subjects()) == 0 || now.IsZero() {
		return fmt.Errorf("scoped recovery credential, trust roots and trusted time are required")
	}
	if err := ValidateCredential(credential); err != nil {
		return err
	}
	leaf, _ := x509.ParseCertificate(credential.TLS.Certificate[0])
	intermediates := x509.NewCertPool()
	for _, der := range credential.TLS.Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("invalid recovery certificate chain")
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: device.RecoverySubject(credential.DeviceID), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("recovery certificate trust, identity or validity check failed: %w", device.ErrDenied)
	}
	return nil
}

func CertificateFingerprint(chain []byte) (string, error) {
	certificates, err := ParseCertificateChain(chain)
	if err != nil {
		return "", err
	}
	return device.Hash(certificates[0].Raw), nil
}

func PublicChain(credential device.Credential) ([]byte, error) {
	if err := ValidateCredential(credential); err != nil {
		return nil, err
	}
	var chain []byte
	for _, der := range credential.TLS.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if len(chain) > MaxChainSize {
		return nil, fmt.Errorf("oversized credential chain")
	}
	return chain, nil
}
