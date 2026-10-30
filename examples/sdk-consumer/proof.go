// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"

	"knowndevice.local/knowndevice/adapters/profilehttp"
	"knowndevice.local/knowndevice/sdk/credentialprofile"
	"knowndevice.local/knowndevice/sdk/device"
)

var (
	_ device.Entitlement  = (*profilehttp.Client)(nil)
	_ device.Authority    = (*profilehttp.Client)(nil)
	_ device.Importer     = (*profilehttp.Client)(nil)
	_ device.Registration = (*profilehttp.Client)(nil)
	_ device.Transport    = (*profilehttp.Client)(nil)
	_ device.Application  = (*profilehttp.Client)(nil)
	_ device.Withdrawal   = (*profilehttp.Client)(nil)
	_ device.Clock        = device.SystemClock{}
	_ crypto.Signer       = (*memorySigner)(nil)
)

// memorySigner exposes signing without exporting the test key as public metadata.
type memorySigner struct{ key *ecdsa.PrivateKey }

func newSigner() (*memorySigner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("create in-memory signer failed")
	}
	return &memorySigner{key}, nil
}

func (s *memorySigner) Public() crypto.PublicKey { return s.key.Public() }
func (s *memorySigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(random, digest, opts)
}

type profileProof struct {
	ID              string `json:"id"`
	Version         int    `json:"version"`
	PolicyDigest    string `json:"policyDigest"`
	CSRDigest       string `json:"csrDigest"`
	PublicKeyDigest string `json:"publicKeyDigest"`
}

type proofReport struct {
	Scope                 string         `json:"scope"`
	ModuleResolution      string         `json:"moduleResolution"`
	Profiles              []profileProof `json:"profiles"`
	NativeRoleAssignments string         `json:"nativeRoleAssignments"`
	Roles                 []string       `json:"roles"`
	Process               *processProof  `json:"process,omitempty"`
}

type processProof struct {
	Scope           string `json:"scope"`
	ProtocolVersion string `json:"protocolVersion"`
	ErrorVersion    string `json:"errorVersion"`
	SchemaDigest    string `json:"schemaDigest"`
	ArtifactDigest  string `json:"artifactDigest"`
	SnapshotDigest  string `json:"snapshotDigest"`
	SessionHealth   string `json:"sessionHealth"`
	ClockSource     string `json:"clockSource"`
	ClockTrusted    bool   `json:"clockTrusted"`
}

func validateCSR(policy credentialprofile.Policy, signer crypto.Signer, csr []byte) (profileProof, error) {
	request, err := policy.ValidateCSR(csr, "sdk-consumer", 2)
	if err != nil {
		return profileProof{}, fmt.Errorf("selected profile refused the CSR")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, request.RawSubjectPublicKeyInfo) {
		return profileProof{}, fmt.Errorf("CSR does not match the scoped signer public key")
	}
	return profileProof{ID: policy.ID, Version: policy.Version, PolicyDigest: policy.PolicyDigest, CSRDigest: credentialprofile.Hash(request.Raw), PublicKeyDigest: credentialprofile.Hash(public)}, nil
}

func proveSDK() (proofReport, error) {
	report := proofReport{
		Scope:                 "in-memory-sdk-import-and-validation",
		ModuleResolution:      "workspace-local-replace",
		NativeRoleAssignments: "compile-checked",
		Roles:                 []string{"application", "authority", "clock", "entitlement", "platform", "transport", "withdrawal"},
	}
	for _, id := range []string{credentialprofile.ReferenceID, credentialprofile.StableID} {
		policy, err := credentialprofile.Find(id, 1)
		if err != nil {
			return proofReport{}, fmt.Errorf("selected credential profile is unavailable")
		}
		signer, err := newSigner()
		if err != nil {
			return proofReport{}, err
		}
		csr, err := policy.CreateCSR(signer, "sdk-consumer", 2)
		if err != nil {
			return proofReport{}, fmt.Errorf("profile-constrained CSR creation failed")
		}
		proof, err := validateCSR(policy, signer, csr)
		if err != nil {
			return proofReport{}, err
		}
		report.Profiles = append(report.Profiles, proof)
	}
	return report, nil
}
