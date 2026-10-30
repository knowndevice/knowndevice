// SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"time"
)

// CredentialBinding identifies a public artifact, never a CN-selected generation.
type CredentialBinding struct {
	DeploymentID           string `json:"deploymentId"`
	DeviceID               string `json:"deviceId"`
	OperationID            string `json:"operationId"`
	PlanDigest             string `json:"planDigest"`
	ConfigDigest           string `json:"configDigest"`
	SnapshotDigest         string `json:"snapshotDigest"`
	ProfileID              string `json:"profileId"`
	ProfileVersion         int    `json:"profileVersion"`
	ProfileDigest          string `json:"profileDigest"`
	Generation             uint64 `json:"generation"`
	PublicKeyDigest        string `json:"publicKeyDigest"`
	CertificateFingerprint string `json:"certificateFingerprint"`
	CSRDigest              string `json:"csrDigest"`
}

// Evidence carries an authenticated role result; its content cannot authenticate itself.
type Evidence struct {
	APIVersion       string            `json:"apiVersion"`
	Role             string            `json:"role"`
	Action           string            `json:"action"`
	RequestID        string            `json:"requestId"`
	Plan             Plan              `json:"plan"`
	Subject          CredentialBinding `json:"subject"`
	Revision         uint64            `json:"revision"`
	Reference        string            `json:"reference"`
	Source           string            `json:"source"`
	ObservedAt       time.Time         `json:"observedAt"`
	Deadline         time.Time         `json:"deadline"`
	Status           string            `json:"status"`
	IssuanceEarliest time.Time         `json:"issuanceEarliest,omitempty"`
	IssuanceLatest   time.Time         `json:"issuanceLatest,omitempty"`
}
type AccessObservation struct {
	Evidence     Evidence `json:"evidence"`
	Kind         string   `json:"kind"`
	ConnectionID string   `json:"connectionId"`
	Challenge    Probe    `json:"challenge"`
}
type ApplicationEvidence struct {
	Evidence           Evidence          `json:"evidence"`
	Phase              string            `json:"phase"`
	ApplicationID      string            `json:"applicationId"`
	ActivationRevision uint64            `json:"activationRevision"`
	Active             CredentialBinding `json:"active"`
	InstanceID         string            `json:"instanceId"`
	ConnectionID       string            `json:"connectionId"`
	SessionID          string            `json:"sessionId"`
	Challenge          Probe             `json:"challenge"`
	AcceptedScope      []string          `json:"acceptedScope"`
}
type WithdrawalEvidence struct {
	Evidence           Evidence            `json:"evidence"`
	Previous           CredentialBinding   `json:"previous"`
	Target             CredentialBinding   `json:"target"`
	PolicyRevision     uint64              `json:"policyRevision"`
	Scope              string              `json:"scope"`
	SessionsTerminated bool                `json:"sessionsTerminated"`
	Denial             AccessObservation   `json:"denial"`
	Current            ApplicationEvidence `json:"current"`
}

// ConnectionRecord describes a live transport socket, without granting application access.
type ConnectionRecord struct {
	ConnectionID           string             `json:"connectionId"`
	Binding                *CredentialBinding `json:"binding,omitempty"`
	Authenticated          bool               `json:"authenticated"`
	CertificateFingerprint string             `json:"certificateFingerprint,omitempty"`
	PublicKeyDigest        string             `json:"publicKeyDigest,omitempty"`
}

// SessionInventory is an instantaneous observer-only lab read, not withdrawal evidence.
type SessionInventory struct {
	Evidence    Evidence           `json:"evidence"`
	Scope       string             `json:"scope"`
	Complete    bool               `json:"complete"`
	Connections []ConnectionRecord `json:"connections"`
}

// RoleRequest is the bounded local HTTP lab wire. Process transports use negotiated DTOs.
type RoleRequest struct {
	Plan        Plan   `json:"plan"`
	CSR         []byte `json:"csr,omitempty"`
	Certificate []byte `json:"certificate,omitempty"`
	Previous    []byte `json:"previous,omitempty"`
	Probe       Probe  `json:"probe"`
	RequestID   string `json:"requestId"`
}
type RoleResponse struct {
	Status      string               `json:"status"`
	Certificate []byte               `json:"certificate,omitempty"`
	Evidence    *Evidence            `json:"evidence,omitempty"`
	Application *ApplicationEvidence `json:"application,omitempty"`
	Withdrawal  *WithdrawalEvidence  `json:"withdrawal,omitempty"`
	Inventory   *SessionInventory    `json:"inventory,omitempty"`
}

type Entitlement interface {
	Authorize(context.Context, Plan, *Credential) error
}
type Registration interface {
	Register(context.Context, Plan, Credential) error
	Registration(context.Context, Plan, Credential) error
}
type Transport interface {
	Probe(context.Context, Probe, Credential) (Probe, error)
}
type Application interface {
	Activate(context.Context, Plan, Credential) (Activation, error)
	ActivationStatus(context.Context, Plan, Credential) (Activation, error)
}
type Withdrawal interface {
	Retire(context.Context, Plan, Credential, Credential) (Retirement, error)
	RetirementStatus(context.Context, Plan, Credential, Credential) (Retirement, error)
}
type Clock interface {
	Assess(context.Context, time.Time) (ClockAssessment, error)
}

// Roles keeps ownership separate even when one selected implementation supplies several roles.
type Roles struct {
	Entitlement Entitlement
	Platform    Registration
	Transport   Transport
	Application Application
	Withdrawal  Withdrawal
	Clock       Clock
}

func (r Roles) Validate() error {
	for _, role := range []any{r.Entitlement, r.Platform, r.Transport, r.Application, r.Withdrawal, r.Clock} {
		if missingRole(role) {
			return ErrUnsupported
		}
	}
	return nil
}

// LegacyFacade retains the existing engine's sequencing while each action has one role owner.
func (r Roles) LegacyFacade() (Platform, error) {
	if e := r.Validate(); e != nil {
		return nil, e
	}
	return roleFacade{r}, nil
}

type roleFacade struct{ r Roles }

func (f roleFacade) Authorize(c context.Context, p Plan, k *Credential) error {
	return f.r.Entitlement.Authorize(c, p, k)
}
func (f roleFacade) Register(c context.Context, p Plan, k Credential) error {
	return f.r.Platform.Register(c, p, k)
}
func (f roleFacade) Registration(c context.Context, p Plan, k Credential) error {
	return f.r.Platform.Registration(c, p, k)
}
func (f roleFacade) Probe(c context.Context, p Probe, k Credential) (Probe, error) {
	return f.r.Transport.Probe(c, p, k)
}
func (f roleFacade) Activate(c context.Context, p Plan, k Credential) (Activation, error) {
	return f.r.Application.Activate(c, p, k)
}
func (f roleFacade) ActivationStatus(c context.Context, p Plan, k Credential) (Activation, error) {
	return f.r.Application.ActivationStatus(c, p, k)
}
func (f roleFacade) Retire(c context.Context, p Plan, o, k Credential) (Retirement, error) {
	return f.r.Withdrawal.Retire(c, p, o, k)
}
func (f roleFacade) RetirementStatus(c context.Context, p Plan, o, k Credential) (Retirement, error) {
	return f.r.Withdrawal.RetirementStatus(c, p, o, k)
}
