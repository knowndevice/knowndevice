// SPDX-License-Identifier: Apache-2.0

// Package credentialprofile implements the reviewed, strict public identity policies.
package credentialprofile

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

const (
	MaxCSRSize   = 16 << 10
	MaxChainSize = 64 << 10
)
const ReferenceID = "reference-generation-cn"
const StableID = "stable-device-cn"

var cnOID = asn1.ObjectIdentifier{2, 5, 4, 3}
var sanOID = asn1.ObjectIdentifier{2, 5, 29, 17}
var extensionRequestOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
var validID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)

// Policy has no mutable callbacks or caller-supplied acceptance rules.
type Policy struct {
	ID           string `json:"id"`
	Version      int    `json:"version"`
	PolicyDigest string `json:"policyDigest"`
}
type publicPolicy struct {
	ID            string   `json:"id"`
	Version       int      `json:"version"`
	Subject       string   `json:"subject"`
	SAN           string   `json:"san"`
	CSRAttributes string   `json:"csrAttributes"`
	Key           string   `json:"key"`
	Signature     string   `json:"signature"`
	LeafUsage     string   `json:"leafUsage"`
	AdditionalEKU bool     `json:"additionalEKU"`
	Extensions    []string `json:"extensions"`
	CSRBytes      int      `json:"csrBytes"`
	ChainBytes    int      `json:"chainBytes"`
	ChainCount    int      `json:"chainCount"`
}

func Hash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func Find(id string, version int) (Policy, error) {
	if version != 1 || (id != ReferenceID && id != StableID) {
		return Policy{}, fmt.Errorf("unsupported credential profile")
	}
	p := publicPolicy{ID: id, Version: 1, Subject: "single-generation-cn", SAN: "single-matching-dns", CSRAttributes: "single-san-extension-request", Key: "ECDSA-P256", Signature: "ECDSA-SHA256", LeafUsage: "non-ca,digitalSignature,clientAuth,no-anyEKU", AdditionalEKU: true, Extensions: []string{"2.5.29.14", "2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.35", "2.5.29.37", "1.3.6.1.4.1.37476.9000.64.1"}, CSRBytes: MaxCSRSize, ChainBytes: MaxChainSize, ChainCount: 8}
	if id == StableID {
		p.Subject = "single-stable-device-cn"
		p.SAN = "absent"
		p.CSRAttributes = "empty"
		p.AdditionalEKU = false
		p.Extensions = []string{"2.5.29.14", "2.5.29.15", "2.5.29.19", "2.5.29.35", "2.5.29.37", "1.3.6.1.4.1.37476.9000.64.1"}
	}
	b, _ := json.Marshal(p)
	return Policy{ID: id, Version: version, PolicyDigest: Hash(b)}, nil
}
func Resolve(id string, version int, digest string) (Policy, error) {
	p, e := Find(id, version)
	if e != nil || p.PolicyDigest != digest {
		return Policy{}, fmt.Errorf("profile policy digest mismatch")
	}
	return p, nil
}
func (p Policy) valid() error { _, e := Resolve(p.ID, p.Version, p.PolicyDigest); return e }
func (p Policy) Subject(deviceID string, generation uint64) string {
	if p.ID == StableID {
		return deviceID
	}
	return fmt.Sprintf("g%d.%s.known-device.invalid", generation, deviceID)
}
func key(public crypto.PublicKey) error {
	k, ok := public.(*ecdsa.PublicKey)
	if !ok || k == nil || k.X == nil || k.Y == nil || k.Curve != elliptic.P256() || !k.Curve.IsOnCurve(k.X, k.Y) {
		return fmt.Errorf("credential requires ECDSA P-256")
	}
	return nil
}
func exactSubject(raw []byte, subject string) bool {
	var rdns pkix.RDNSequence
	rest, err := asn1.Unmarshal(raw, &rdns)
	return err == nil && len(rest) == 0 && len(rdns) == 1 && len(rdns[0]) == 1 && rdns[0][0].Type.Equal(cnOID) && rdns[0][0].Value == subject
}
func (p Policy) CreateCSR(signer crypto.Signer, deviceID string, generation uint64) ([]byte, error) {
	if p.valid() != nil || !validID.MatchString(deviceID) || generation == 0 || signer == nil {
		return nil, fmt.Errorf("invalid credential CSR binding")
	}
	if e := key(signer.Public()); e != nil {
		return nil, e
	}
	r := &x509.CertificateRequest{Subject: pkix.Name{CommonName: p.Subject(deviceID, generation)}, SignatureAlgorithm: x509.ECDSAWithSHA256}
	if p.ID == ReferenceID {
		r.DNSNames = []string{r.Subject.CommonName}
	}
	der, e := x509.CreateCertificateRequest(rand.Reader, r, signer)
	if e != nil {
		return nil, fmt.Errorf("CSR signing failed")
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	_, e = p.ValidateCSR(b, deviceID, generation)
	return b, e
}

type rawRequest struct {
	Info struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []asn1.RawValue `asn1:"tag:0"`
	}
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

func (p Policy) ValidateCSR(data []byte, deviceID string, generation uint64) (*x509.CertificateRequest, error) {
	if p.valid() != nil || !validID.MatchString(deviceID) || generation == 0 || len(data) == 0 || len(data) > MaxCSRSize {
		return nil, fmt.Errorf("invalid CSR policy or size")
	}
	b := bytes.TrimSpace(data)
	if !bytes.HasPrefix(b, []byte("-----BEGIN CERTIFICATE REQUEST-----")) {
		return nil, fmt.Errorf("invalid CSR encoding")
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("invalid CSR encoding")
	}
	r, e := x509.ParseCertificateRequest(block.Bytes)
	if e != nil || r.CheckSignature() != nil || r.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return nil, fmt.Errorf("invalid CSR signature or algorithm")
	}
	if e = key(r.PublicKey); e != nil {
		return nil, e
	}
	if !exactSubject(r.RawSubject, p.Subject(deviceID, generation)) {
		return nil, fmt.Errorf("CSR subject mismatch")
	}
	var raw rawRequest
	rest, e = asn1.Unmarshal(block.Bytes, &raw)
	if e != nil || len(rest) != 0 || raw.Info.Version != 0 {
		return nil, fmt.Errorf("invalid CSR attributes")
	}
	if p.ID == StableID {
		if len(raw.Info.Attributes) != 0 || len(r.Extensions) != 0 || len(r.DNSNames)+len(r.EmailAddresses)+len(r.IPAddresses)+len(r.URIs) != 0 {
			return nil, fmt.Errorf("stable CSR requires absent SAN and empty attributes")
		}
	} else {
		if len(raw.Info.Attributes) != 1 || len(r.Extensions) != 1 || !r.Extensions[0].Id.Equal(sanOID) || r.Extensions[0].Critical || len(r.DNSNames) != 1 || r.DNSNames[0] != p.Subject(deviceID, generation) || len(r.EmailAddresses)+len(r.IPAddresses)+len(r.URIs) != 0 {
			return nil, fmt.Errorf("reference CSR requires only one matching DNS SAN")
		}
		expectedSAN, _ := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte(p.Subject(deviceID, generation))}})
		if !bytes.Equal(expectedSAN, r.Extensions[0].Value) {
			return nil, fmt.Errorf("undeclared CSR SAN general name")
		}
		var a attribute
		rest, e = asn1.Unmarshal(raw.Info.Attributes[0].FullBytes, &a)
		if e != nil || len(rest) != 0 || !a.Type.Equal(extensionRequestOID) || len(a.Values) != 1 {
			return nil, fmt.Errorf("unsupported CSR attribute")
		}
		var ext []pkix.Extension
		rest, e = asn1.Unmarshal(a.Values[0].FullBytes, &ext)
		if e != nil || len(rest) != 0 || len(ext) != 1 || !ext[0].Id.Equal(sanOID) || ext[0].Critical || !bytes.Equal(ext[0].Value, r.Extensions[0].Value) {
			return nil, fmt.Errorf("duplicate or unsupported CSR extension")
		}
	}
	return r, nil
}
func ParseChain(data []byte) ([]*x509.Certificate, error) {
	if len(data) == 0 || len(data) > MaxChainSize {
		return nil, fmt.Errorf("invalid certificate chain size")
	}
	var result []*x509.Certificate
	for rest := bytes.TrimSpace(data); len(rest) > 0; {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("invalid certificate chain encoding")
		}
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(result) == 8 {
			return nil, fmt.Errorf("invalid certificate chain encoding")
		}
		c, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, fmt.Errorf("invalid certificate")
		}
		result = append(result, c)
		rest = bytes.TrimSpace(tail)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}
	return result, nil
}
func (p Policy) ValidateLeaf(c *x509.Certificate, deviceID string, generation uint64) error {
	if !validID.MatchString(deviceID) || generation == 0 {
		return fmt.Errorf("invalid certificate device/generation")
	}
	return p.validateIdentity(c, p.Subject(deviceID, generation))
}
func (p Policy) validateIdentity(c *x509.Certificate, subject string) error {
	if p.valid() != nil || c == nil || !exactSubject(c.RawSubject, subject) || c.IsCA || len(c.UnhandledCriticalExtensions) > 0 || c.KeyUsage&x509.KeyUsageDigitalSignature == 0 || c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return fmt.Errorf("certificate identity, algorithm or usage mismatch")
	}

	if e := key(c.PublicKey); e != nil {
		return e
	}
	client := false
	for _, eku := range c.ExtKeyUsage {
		if eku == x509.ExtKeyUsageAny {
			return fmt.Errorf("unrestricted certificate EKU")
		}
		if eku == x509.ExtKeyUsageClientAuth {
			client = true
		} else if p.ID == StableID {
			return fmt.Errorf("stable certificate requires only clientAuth")
		}
	}
	if !client || (p.ID == StableID && (len(c.ExtKeyUsage) != 1 || len(c.UnknownExtKeyUsage) != 0)) {
		return fmt.Errorf("certificate requires clientAuth")
	}
	seen := map[string]bool{}
	hasSAN := false
	for _, ext := range c.Extensions {
		oid := ext.Id.String()
		if seen[oid] {
			return fmt.Errorf("duplicate certificate extension")
		}
		seen[oid] = true
		switch oid {
		case "2.5.29.14", "2.5.29.15", "2.5.29.19", "2.5.29.35", "2.5.29.37", "1.3.6.1.4.1.37476.9000.64.1":
		case "2.5.29.17":
			hasSAN = true
		default:
			return fmt.Errorf("undeclared certificate extension")
		}
	}
	if p.ID == StableID {
		if hasSAN || len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) != 0 {
			return fmt.Errorf("stable certificate requires absent SAN")
		}
	} else {
		if !hasSAN || len(c.DNSNames) != 1 || c.DNSNames[0] != subject || len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) != 0 {
			return fmt.Errorf("reference certificate SAN mismatch")
		}
	}
	if p.ID == ReferenceID {
		expected, _ := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte(subject)}})
		for _, ext := range c.Extensions {
			if ext.Id.Equal(sanOID) && !bytes.Equal(expected, ext.Value) {
				return fmt.Errorf("undeclared SAN general name")
			}
		}
	}
	return nil
}

// Validation assesses a closed interval; Historical grants artifact binding only.
type Validation struct {
	Roots                                                   *x509.CertPool
	Earliest, Latest                                        time.Time
	AllowedIssuers                                          []string
	MinLifetime, MaxLifetime, MaxBackdate, MinimumRemaining time.Duration
	Historical                                              bool
}

func (p Policy) ValidateChain(chain, csr []byte, publicKeyDigest, deviceID string, generation uint64, v Validation) error {
	r, e := p.ValidateCSR(csr, deviceID, generation)
	if e != nil {
		return e
	}
	certs, e := ParseChain(chain)
	if e != nil {
		return e
	}
	leaf := certs[0]
	if !bytes.Equal(r.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) || Hash(r.RawSubjectPublicKeyInfo) != publicKeyDigest {
		return fmt.Errorf("certificate CSR/SPKI binding mismatch")
	}
	return p.ValidatePublicChain(certs, deviceID, generation, v)
}
func (p Policy) ValidatePublicChain(certs []*x509.Certificate, deviceID string, generation uint64, v Validation) error {
	if len(certs) == 0 || len(certs) > 8 || v.Roots == nil || len(v.Roots.Subjects()) == 0 || v.Earliest.IsZero() || v.Latest.Before(v.Earliest) {
		return fmt.Errorf("explicit trust and finite time interval required")
	}
	leaf := certs[0]
	if leaf == nil {
		return fmt.Errorf("certificate chain contains a nil certificate")
	}
	if e := p.ValidateLeaf(leaf, deviceID, generation); e != nil {
		return e
	}
	pool := x509.NewCertPool()
	size := 0
	seen := map[string]bool{}
	for i, c := range certs {
		if c == nil {
			return fmt.Errorf("certificate chain contains a nil certificate")
		}
		if seen[Hash(c.Raw)] || i > 0 && !c.IsCA {
			return fmt.Errorf("duplicate chain or multiple candidate certificates require intervention")
		}
		seen[Hash(c.Raw)] = true
		size += len(c.Raw)
		if size > MaxChainSize || c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			return fmt.Errorf("certificate chain limits or signature mismatch")
		}
		if i > 0 {
			pool.AddCert(c)
		}
	}
	for _, at := range []time.Time{v.Earliest, v.Latest} {
		paths, e := leaf.Verify(x509.VerifyOptions{Roots: v.Roots, Intermediates: pool, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		if e != nil {
			return fmt.Errorf("certificate chain interval validation failed")
		}
		allowed := false
		for _, path := range paths {
			exact := len(certs) <= len(path)
			for i, c := range certs {
				if i >= len(path) || !bytes.Equal(c.Raw, path[i].Raw) {
					exact = false
				}
			}
			issuerAllowed := len(v.AllowedIssuers) == 0
			if len(path) > 1 {
				for _, issuer := range v.AllowedIssuers {
					if Hash(path[1].Raw) == issuer {
						issuerAllowed = true
					}
				}
			}
			intervalFits := true
			for _, c := range path {
				if v.Earliest.Before(c.NotBefore) || !v.Latest.Before(c.NotAfter) {
					intervalFits = false
				}
			}
			if exact && issuerAllowed && intervalFits {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("certificate issuer policy mismatch")
		}
	}
	if !v.Historical {
		life := leaf.NotAfter.Sub(leaf.NotBefore)
		if (v.MinLifetime > 0 && life < v.MinLifetime) || (v.MaxLifetime > 0 && life > v.MaxLifetime) || (v.MaxBackdate > 0 && v.Earliest.Sub(leaf.NotBefore) > v.MaxBackdate) || (v.MinimumRemaining > 0 && leaf.NotAfter.Sub(v.Latest) < v.MinimumRemaining) {
			return fmt.Errorf("certificate lifetime policy mismatch")
		}
	}
	return nil
}

var referenceSubject = regexp.MustCompile(`^g([1-9][0-9]*)\.([a-z][a-z0-9-]{0,47})\.known-device\.invalid$`)

func ValidateReferenceCSR(data []byte, subject string) (*x509.CertificateRequest, error) {
	parts := referenceSubject.FindStringSubmatch(subject)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid reference subject")
	}
	generation, e := strconv.ParseUint(parts[1], 10, 64)
	if e != nil {
		return nil, e
	}
	p, _ := Find(ReferenceID, 1)
	return p.ValidateCSR(data, parts[2], generation)
}
func ValidateReferenceIdentity(c *x509.Certificate, subject string) error {
	p, _ := Find(ReferenceID, 1)
	return p.validateIdentity(c, subject)
}
