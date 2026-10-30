// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"time"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
)

// softwareSigner keeps the private key behind crypto.Signer. Returning the
// underlying *ecdsa.PrivateKey would let a caller extract its scalar.
type softwareSigner struct {
	key *ecdsa.PrivateKey
}

func (s *softwareSigner) Public() crypto.PublicKey {
	return &ecdsa.PublicKey{Curve: s.key.Curve, X: new(big.Int).Set(s.key.X), Y: new(big.Int).Set(s.key.Y)}
}

func (s *softwareSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(random, digest, opts)
}

func parseSigner(data []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(data)
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN PRIVATE KEY-----")) || block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("software signer requires one PKCS#8 private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid software signing key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("software signer requires ECDSA P-256")
	}
	return &softwareSigner{key: key}, nil
}

func fingerprint(signer crypto.Signer) (string, error) {
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", err
	}
	return device.Hash(public), nil
}

func parseChain(data []byte) ([]*x509.Certificate, error) {
	return credentialprofile.ParseChain(data)
}

func validateCertificate(data []byte, h device.Handle, signer crypto.Signer, current bool) error {
	chain, err := parseChain(data)
	if err != nil {
		return err
	}
	leaf := chain[0]
	public, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) || device.Hash(public) != h.PublicKeyDigest {
		return fmt.Errorf("certificate public key does not match slot")
	}
	digest, err := fingerprint(signer)
	if err != nil || digest != h.PublicKeyDigest {
		return fmt.Errorf("signer public key does not match slot")
	}
	expected, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, expected) {
		return fmt.Errorf("certificate SPKI differs from actual signer")
	}
	if err := credentialprofile.ValidateReferenceIdentity(leaf, device.Subject(h.Binding.DeviceID, h.Binding.Generation)); err != nil {
		return err
	}
	if current && (time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter)) {
		return fmt.Errorf("certificate is outside its validity period")
	}
	return nil
}

// LoadCredential loads a separately provisioned recovery credential. Both
// files must live in one private owned directory; the signer stays opaque.
func LoadCredential(certPath, keyPath string) (tls.Certificate, error) {
	credential, err := loadCredential(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := credentialprofile.ValidateReferenceIdentity(credential.Leaf, credential.Leaf.Subject.CommonName); err != nil {
		return tls.Certificate{}, err
	}
	return credential, nil
}

// LoadServiceCredential loads a scoped service signer with an explicit TLS purpose.
// The selected role validator supplies its SAN identity, roots and exact pins.
func LoadServiceCredential(certPath, keyPath string, purpose x509.ExtKeyUsage) (tls.Certificate, error) {
	if purpose != x509.ExtKeyUsageServerAuth && purpose != x509.ExtKeyUsageClientAuth {
		return tls.Certificate{}, fmt.Errorf("service credential requires an explicit TLS purpose")
	}
	credential, err := loadCredential(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf := credential.Leaf
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 || len(leaf.UnhandledCriticalExtensions) != 0 || len(leaf.UnknownExtKeyUsage) != 0 {
		return tls.Certificate{}, fmt.Errorf("service certificate algorithm or usage is invalid")
	}
	allowed := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny {
			return tls.Certificate{}, fmt.Errorf("service certificate has unrestricted usage")
		}
		if usage == purpose {
			allowed = true
		}
	}
	if !allowed {
		return tls.Certificate{}, fmt.Errorf("service certificate lacks its required TLS usage")
	}
	return credential, nil
}

func loadCredential(certPath, keyPath string) (tls.Certificate, error) {
	certAbs, err := filepath.Abs(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyAbs, err := filepath.Abs(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if filepath.Dir(certAbs) != filepath.Dir(keyAbs) || certAbs == keyAbs {
		return tls.Certificate{}, fmt.Errorf("credential files must share one confined directory")
	}
	root, err := openDirectory(filepath.Dir(certAbs), false)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer root.Close()
	keyData, err := readFile(root, filepath.Base(keyAbs))
	if err != nil {
		return tls.Certificate{}, err
	}
	signer, err := parseSigner(keyData)
	if err != nil {
		return tls.Certificate{}, err
	}
	certData, err := readFile(root, filepath.Base(certAbs))
	if err != nil {
		return tls.Certificate{}, err
	}
	chain, err := parseChain(certData)
	if err != nil {
		return tls.Certificate{}, err
	}
	public, err := x509.MarshalPKIXPublicKey(chain[0].PublicKey)
	digest, e := fingerprint(signer)
	expected, publicErr := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || e != nil || publicErr != nil || !bytes.Equal(public, chain[0].RawSubjectPublicKeyInfo) || !bytes.Equal(public, expected) || device.Hash(public) != digest {
		return tls.Certificate{}, fmt.Errorf("certificate SPKI does not match confined signer")
	}
	credential := tls.Certificate{PrivateKey: signer, Leaf: chain[0]}
	for _, cert := range chain {
		credential.Certificate = append(credential.Certificate, cert.Raw)
	}
	return credential, nil
}

var _ crypto.Signer = (*softwareSigner)(nil)
