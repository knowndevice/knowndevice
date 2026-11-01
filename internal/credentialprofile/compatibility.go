// SPDX-License-Identifier: Apache-2.0

// Package credentialprofile preserves internal imports of the public profile validator.
package credentialprofile

import (
	"crypto/x509"

	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
)

const (
	MaxCSRSize   = credentialprofile.MaxCSRSize
	MaxChainSize = credentialprofile.MaxChainSize
	ReferenceID  = credentialprofile.ReferenceID
	StableID     = credentialprofile.StableID
)

type Policy = credentialprofile.Policy
type Validation = credentialprofile.Validation

func Hash(data []byte) string { return credentialprofile.Hash(data) }
func Find(id string, version int) (Policy, error) {
	return credentialprofile.Find(id, version)
}
func Resolve(id string, version int, digest string) (Policy, error) {
	return credentialprofile.Resolve(id, version, digest)
}
func ParseChain(data []byte) ([]*x509.Certificate, error) {
	return credentialprofile.ParseChain(data)
}
func ValidateReferenceCSR(data []byte, subject string) (*x509.CertificateRequest, error) {
	return credentialprofile.ValidateReferenceCSR(data, subject)
}
func ValidateReferenceIdentity(certificate *x509.Certificate, subject string) error {
	return credentialprofile.ValidateReferenceIdentity(certificate, subject)
}
