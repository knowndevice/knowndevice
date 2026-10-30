// SPDX-License-Identifier: Apache-2.0

// Package process runs trusted, pinned alpha adapters over bounded JSON-RPC stdio.
// A subprocess and its declared permissions do not provide operating-system isolation.
package process

import (
	"io"
	"time"

	"knowndevice.local/knowndevice/api/schemas"
	"knowndevice.local/knowndevice/sdk/credentialprofile"
	"knowndevice.local/knowndevice/sdk/device"
)

const (
	ProtocolVersion    = "knowndevice-process/0.1-alpha.1"
	ErrorVersion       = "knowndevice-process-errors/1"
	SchemaID           = "urn:knowndevice:process:0.1-alpha.1"
	MaxSnapshotBytes   = 128 << 10
	MaxExecutableBytes = 128 << 20
)

// Limits are fixed in this protocol version; negotiation cannot widen them.
type Limits struct {
	MaxLineBytes      int `json:"maxLineBytes"`
	MaxCSRBytes       int `json:"maxCSRBytes"`
	MaxChainBytes     int `json:"maxChainBytes"`
	MaxCertificates   int `json:"maxCertificates"`
	MaxDepth          int `json:"maxDepth"`
	MaxValues         int `json:"maxValues"`
	MaxObjectFields   int `json:"maxObjectFields"`
	MaxArrayItems     int `json:"maxArrayItems"`
	MaxStringBytes    int `json:"maxStringBytes"`
	MaxInFlight       int `json:"maxInFlight"`
	MaxRequests       int `json:"maxRequests"`
	MaxSignerCalls    int `json:"maxSignerCalls"`
	MaxSignatureBytes int `json:"maxSignatureBytes"`
	MaxDigestBytes    int `json:"maxDigestBytes"`
	MaxStderrBytes    int `json:"maxStderrBytes"`
	MaxTimeoutMillis  int `json:"maxTimeoutMillis"`
}

func DefaultLimits() Limits {
	return Limits{1 << 20, 16 << 10, 64 << 10, 8, 32, 10000, 64, 256, 256 << 10, 1, 4096, 32, 512, 64, 1 << 20, 60000}
}

type SchemaIdentity struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func Schema() SchemaIdentity { return SchemaIdentity{SchemaID, "1", device.Hash(schemas.Process)} }

type Permissions struct {
	NetworkOrigins  []string `json:"networkOrigins"`
	FilesystemRead  []string `json:"filesystemRead"`
	FilesystemWrite []string `json:"filesystemWrite"`
	SignerBroker    bool     `json:"signerBroker"`
}

type InitializeParams struct {
	ProtocolVersions     []string                 `json:"protocolVersions"`
	ErrorVersions        []string                 `json:"errorVersions"`
	Schemas              []SchemaIdentity         `json:"schemas"`
	ArtifactDigest       string                   `json:"artifactDigest"`
	SnapshotDigest       string                   `json:"snapshotDigest"`
	CompositionDigest    string                   `json:"compositionDigest"`
	Profile              credentialprofile.Policy `json:"profile"`
	Snapshot             []byte                   `json:"snapshot"`
	RequiredCapabilities []string                 `json:"requiredCapabilities"`
	Permissions          Permissions              `json:"permissions"`
	Limits               Limits                   `json:"limits"`
}

type InitializeResult struct {
	ProtocolVersion   string                   `json:"protocolVersion"`
	ErrorVersion      string                   `json:"errorVersion"`
	Schemas           []SchemaIdentity         `json:"schemas"`
	ArtifactDigest    string                   `json:"artifactDigest"`
	SnapshotDigest    string                   `json:"snapshotDigest"`
	CompositionDigest string                   `json:"compositionDigest"`
	Profile           credentialprofile.Policy `json:"profile"`
	Capabilities      []string                 `json:"capabilities"`
	Permissions       Permissions              `json:"permissions"`
	Limits            Limits                   `json:"limits"`
}

type Scope struct {
	OperationID        string    `json:"operationId"`
	DeviceID           string    `json:"deviceId"`
	DeploymentID       string    `json:"deploymentId"`
	PlanDigest         string    `json:"planDigest"`
	SnapshotDigest     string    `json:"snapshotDigest"`
	CompositionDigest  string    `json:"compositionDigest"`
	ProfileID          string    `json:"profileId"`
	ProfileDigest      string    `json:"profileDigest"`
	ProfileVersion     int       `json:"profileVersion"`
	ExpectedGeneration uint64    `json:"expectedGeneration"`
	TargetGeneration   uint64    `json:"targetGeneration"`
	Deadline           time.Time `json:"deadline"`
}

func scopeFor(p device.Plan, deadline time.Time) Scope {
	return Scope{p.OperationID, p.DeviceID, p.DeploymentID, p.Digest, p.SnapshotDigest, p.CompositionDigest, p.ProfileID, p.ProfileDigest, p.ProfileVersion, p.ExpectedGeneration, p.TargetGeneration, deadline.UTC()}
}

func (s Scope) equal(other Scope) bool {
	a, b := s, other
	a.Deadline, b.Deadline = time.Time{}, time.Time{}
	return a == b && s.Deadline.Equal(other.Deadline)
}

// WireCredential deliberately contains no crypto.Signer or private material.
type WireCredential struct {
	Handle     device.Handle `json:"handle"`
	Chain      [][]byte      `json:"chain"`
	CSR        []byte        `json:"csr"`
	Recovery   bool          `json:"recovery"`
	DeviceID   string        `json:"deviceId"`
	SignerRef  string        `json:"signerRef"`
	PublicSPKI []byte        `json:"publicSPKI"`
}

type AuthorizeParams struct {
	Scope      Scope           `json:"scope"`
	Plan       device.Plan     `json:"plan"`
	Credential *WireCredential `json:"credential"`
}
type IssueParams struct {
	Scope      Scope           `json:"scope"`
	Plan       device.Plan     `json:"plan"`
	CSR        []byte          `json:"csr"`
	Credential *WireCredential `json:"credential"`
}
type ImportParams struct {
	Scope       Scope           `json:"scope"`
	Plan        device.Plan     `json:"plan"`
	CSR         []byte          `json:"csr"`
	Certificate []byte          `json:"certificate"`
	Credential  *WireCredential `json:"credential"`
}
type CredentialParams struct {
	Scope      Scope          `json:"scope"`
	Plan       device.Plan    `json:"plan"`
	Credential WireCredential `json:"credential"`
}
type ProbeParams struct {
	Scope      Scope          `json:"scope"`
	Plan       device.Plan    `json:"plan"`
	Probe      device.Probe   `json:"probe"`
	Credential WireCredential `json:"credential"`
}
type PairParams struct {
	Scope    Scope          `json:"scope"`
	Plan     device.Plan    `json:"plan"`
	Previous WireCredential `json:"previous"`
	Target   WireCredential `json:"target"`
}
type ClockParams struct {
	Floor time.Time `json:"floor"`
}
type ClockResult struct {
	Earliest         time.Time `json:"earliest"`
	Latest           time.Time `json:"latest"`
	DriftPPM         float64   `json:"driftPPM"`
	MaximumAgeMillis int64     `json:"maximumAgeMillis"`
	Trusted          bool      `json:"trusted"`
	Source           string    `json:"source"`
}
type SignParams struct {
	ParentID  string `json:"parentId"`
	SignerRef string `json:"signerRef"`
	Scope     Scope  `json:"scope"`
	Hash      string `json:"hash"`
	Digest    []byte `json:"digest"`
}
type SignResult struct {
	Signature []byte `json:"signature"`
}
type CancelParams struct {
	ParentID string `json:"parentId"`
	Scope    Scope  `json:"scope"`
}
type BoundResult[T any] struct {
	Scope Scope `json:"scope"`
	Value T     `json:"value"`
}
type Empty struct{}
type HealthResult struct {
	Status string `json:"status"`
}

// Options selects an explicit artifact and a new private execution directory.
type Options struct {
	Executable           string
	ArtifactDigest       string
	Args                 []string
	WorkDir              string
	Snapshot             *device.PublicSnapshot
	RequiredCapabilities []string
	Limits               Limits
	Log                  io.Writer
}

// Factory is called only after the public snapshot and negotiation pass.
type ServerOptions struct {
	Snapshot       *device.PublicSnapshot
	Adapters       device.Adapters
	Factory        func(*device.PublicSnapshot) (device.Adapters, error)
	ArtifactDigest string
	Permissions    Permissions
	Limits         Limits
}

var domainMethods = map[string]string{
	"entitlement.authorize": "authorizeParams", "authority.issue": "issueParams", "authority.lookup": "issueParams", "authority.import": "importParams",
	"authority.revoke": "pairParams", "authority.revocationStatus": "pairParams", "platform.register": "credentialParams", "platform.registrationStatus": "credentialParams",
	"transport.probe": "probeParams", "application.activate": "credentialParams", "application.activationStatus": "credentialParams", "withdrawal.withdraw": "pairParams", "withdrawal.status": "pairParams",
}

func statusMethod(method string) bool {
	switch method {
	case "authority.lookup", "authority.revocationStatus", "platform.registrationStatus", "application.activationStatus", "withdrawal.status":
		return true
	}
	return false
}
