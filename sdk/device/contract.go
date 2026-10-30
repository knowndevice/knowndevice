// SPDX-License-Identifier: Apache-2.0

// Package device exposes alpha contracts for profile-bound persistent transitions.
package device

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"time"
)

var (
	ErrUnknown     = errors.New("remote outcome unknown; reconciliation required")
	ErrDenied      = errors.New("authorization or application access denied")
	ErrConflict    = errors.New("writer or generation precondition conflict")
	ErrUnsupported = errors.New("required capability unsupported")
	ErrPlanExpired = errors.New("unfinished plan expired; operator intervention required")
	// ErrNotFound is a reliable server observation that no operation was reserved.
	ErrNotFound = errors.New("operation effect not started")
)

type Phase string

const (
	Planned            Phase = "planned"
	KeyReady           Phase = "key-ready"
	IssueIntent        Phase = "issue-intent"
	Issued             Phase = "issued"
	RegisterIntent     Phase = "register-intent"
	Registered         Phase = "registered"
	Verified           Phase = "verified"
	ActivateIntent     Phase = "activate-intent"
	Activated          Phase = "activated"
	Committed          Phase = "committed"
	BrokerRetireIntent Phase = "broker-retire-intent"
	BrokerRetired      Phase = "broker-retired"
	CARevokeIntent     Phase = "ca-revoke-intent"
	CARevoked          Phase = "ca-revoked"
	DestroyIntent      Phase = "destroy-intent"
	Retired            Phase = "retired"
)

type Plan struct {
	APIVersion             string    `json:"apiVersion"`
	DigestEncodingVersion  int       `json:"digestEncodingVersion,omitempty"`
	OperationID            string    `json:"operationId"`
	DeviceID               string    `json:"deviceId"`
	Mode                   string    `json:"mode"`
	ExpectedGeneration     uint64    `json:"expectedGeneration"`
	TargetGeneration       uint64    `json:"targetGeneration"`
	TargetSlot             string    `json:"targetSlot"`
	ConfigDigest           string    `json:"configDigest"`
	ExpiresAt              time.Time `json:"expiresAt"`
	Digest                 string    `json:"digest"`
	DeploymentID           string    `json:"deploymentId,omitempty"`
	ProfileID              string    `json:"profileId,omitempty"`
	ProfileVersion         int       `json:"profileVersion,omitempty"`
	ProfileDigest          string    `json:"profileDigest,omitempty"`
	CompositionDigest      string    `json:"compositionDigest,omitempty"`
	SnapshotDigest         string    `json:"snapshotDigest,omitempty"`
	ControlTrustDigest     string    `json:"controlTrustDigest,omitempty"`
	ApplicationTrustDigest string    `json:"applicationTrustDigest,omitempty"`
	IssuanceTrustDigest    string    `json:"issuanceTrustDigest,omitempty"`
	RecoveryTrustDigest    string    `json:"recoveryTrustDigest,omitempty"`
	TransportTrustDigest   string    `json:"transportTrustDigest,omitempty"`
}

type Binding struct {
	DeviceID       string `json:"deviceId"`
	OperationID    string `json:"operationId"`
	Generation     uint64 `json:"generation"`
	Slot           string `json:"slot"`
	DeploymentID   string `json:"deploymentId,omitempty"`
	ProfileID      string `json:"profileId,omitempty"`
	ProfileVersion int    `json:"profileVersion,omitempty"`
	ProfileDigest  string `json:"profileDigest,omitempty"`
	ConfigDigest   string `json:"configDigest,omitempty"`
	PlanDigest     string `json:"planDigest,omitempty"`
	SnapshotDigest string `json:"snapshotDigest,omitempty"`
}

// Handle names a confined slot, never private material or an arbitrary path.
type Handle struct {
	Binding         Binding `json:"binding"`
	PublicKeyDigest string  `json:"publicKeyDigest"`
}

type Probe struct {
	OperationID string    `json:"operationId"`
	DeviceID    string    `json:"deviceId"`
	Generation  uint64    `json:"generation"`
	Endpoint    string    `json:"endpoint"`
	Nonce       string    `json:"nonce"`
	Deadline    time.Time `json:"deadline"`
}

type Activation struct {
	OperationID            string               `json:"operationId"`
	PlanDigest             string               `json:"planDigest"`
	DeviceID               string               `json:"deviceId"`
	ApplicationID          string               `json:"applicationId"`
	Generation             uint64               `json:"generation"`
	CertificateFingerprint string               `json:"certificateFingerprint"`
	SessionID              string               `json:"sessionId"`
	Probe                  Probe                `json:"probe"`
	Evidence               *ApplicationEvidence `json:"evidence,omitempty"`
}

type Retirement struct {
	OperationID        string `json:"operationId"`
	PlanDigest         string `json:"planDigest"`
	Generation         uint64 `json:"generation"`
	PolicyDurable      bool   `json:"policyDurable"`
	SessionsTerminated bool   `json:"sessionsTerminated"`
	TLSObservation     string `json:"tlsObservation"`
	// ApplicationAccessDenied refers to an explicit denial on a new connection.
	ApplicationAccessDenied bool                `json:"applicationAccessDenied"`
	Evidence                *WithdrawalEvidence `json:"evidence,omitempty"`
}

type Operation struct {
	Plan                Plan        `json:"plan"`
	Phase               Phase       `json:"phase"`
	Target              *Handle     `json:"target,omitempty"`
	Previous            *Handle     `json:"previous,omitempty"`
	CSR                 []byte      `json:"csr,omitempty"`
	Certificate         []byte      `json:"certificate,omitempty"`
	Probe               *Probe      `json:"probe,omitempty"`
	Activation          *Activation `json:"activation,omitempty"`
	Retirement          *Retirement `json:"retirement,omitempty"`
	Outcome             string      `json:"outcome"`
	Reason              string      `json:"reason,omitempty"`
	Snapshot            []byte      `json:"snapshot,omitempty"`
	PreviousCSR         []byte      `json:"previousCSR,omitempty"`
	PreviousCertificate []byte      `json:"previousCertificate,omitempty"`
}

// State is one fenced journal snapshot. It contains public material only.
type State struct {
	SchemaVersion  int        `json:"schemaVersion"`
	DeviceID       string     `json:"deviceId"`
	Revision       uint64     `json:"revision"`
	Fence          uint64     `json:"fence"`
	Counter        uint64     `json:"counter"`
	Active         *Handle    `json:"active,omitempty"`
	ClockFloor     time.Time  `json:"clockFloor"`
	Operation      *Operation `json:"operation,omitempty"`
	DeploymentID   string     `json:"deploymentId,omitempty"`
	ProfileID      string     `json:"profileId,omitempty"`
	ProfileVersion int        `json:"profileVersion,omitempty"`
	ProfileDigest  string     `json:"profileDigest,omitempty"`
}

type Journal interface {
	Load(context.Context) (State, error)
	Save(context.Context, State, uint64) (State, error)
	Close() error
}

type KeyStore interface {
	Stage(context.Context, Binding) (Handle, error)
	Signer(context.Context, Handle) (crypto.Signer, error)
	Certificate(context.Context, Handle) ([]byte, error)
	StoreCertificate(context.Context, Handle, []byte) error
	Activate(context.Context, Handle) error
	Active(context.Context) (*Handle, error)
	Destroy(context.Context, Handle) error
}

// Credential provides a public chain and signer to trusted in-process adapters.
// It cannot be JSON-serialized; a process receives public artifacts and scoped signing operations.
type Credential struct {
	Handle Handle
	TLS    tls.Certificate
	// CSR is the original public request from a V2 store, never a regenerated request.
	CSR []byte
	// Recovery has no operational generation or slot. DeviceID binds its scope.
	Recovery bool
	DeviceID string
}

type IssueRequest struct {
	Plan       Plan
	CSR        []byte
	Credential *Credential
}

// Authority separates a mutation from lookup of its exact issuance/revocation binding.
// A backend without authenticated status returns ErrUnknown; interface presence grants no retry.
type Authority interface {
	Issue(context.Context, IssueRequest) ([]byte, error)
	Lookup(context.Context, IssueRequest) ([]byte, error)
	Revoke(context.Context, Plan, Credential, Credential) error
	RevocationStatus(context.Context, Plan, Credential, Credential) error
}

// Platform preserves the legacy aggregate interface. New compositions assign separate Adapters roles.
type Platform interface {
	Authorize(context.Context, Plan, *Credential) error
	Register(context.Context, Plan, Credential) error
	Registration(context.Context, Plan, Credential) error
	Probe(context.Context, Probe, Credential) (Probe, error)
	Activate(context.Context, Plan, Credential) (Activation, error)
	ActivationStatus(context.Context, Plan, Credential) (Activation, error)
	Retire(context.Context, Plan, Credential, Credential) (Retirement, error)
	RetirementStatus(context.Context, Plan, Credential, Credential) (Retirement, error)
}
