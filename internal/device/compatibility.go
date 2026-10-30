// SPDX-License-Identifier: Apache-2.0

// Package device preserves internal imports of the public alpha SDK contract.
package device

import (
	"io"
	"time"

	"knowndevice.local/knowndevice/sdk/device"
)

const (
	MaxInput = device.MaxInput
	V2       = device.V2

	Planned            = device.Planned
	KeyReady           = device.KeyReady
	IssueIntent        = device.IssueIntent
	Issued             = device.Issued
	RegisterIntent     = device.RegisterIntent
	Registered         = device.Registered
	Verified           = device.Verified
	ActivateIntent     = device.ActivateIntent
	Activated          = device.Activated
	Committed          = device.Committed
	BrokerRetireIntent = device.BrokerRetireIntent
	BrokerRetired      = device.BrokerRetired
	CARevokeIntent     = device.CARevokeIntent
	CARevoked          = device.CARevoked
	DestroyIntent      = device.DestroyIntent
	Retired            = device.Retired
)

var (
	ErrUnknown     = device.ErrUnknown
	ErrDenied      = device.ErrDenied
	ErrConflict    = device.ErrConflict
	ErrUnsupported = device.ErrUnsupported
	ErrPlanExpired = device.ErrPlanExpired
	ErrNotFound    = device.ErrNotFound
)

type (
	Phase               = device.Phase
	Plan                = device.Plan
	Binding             = device.Binding
	Handle              = device.Handle
	Probe               = device.Probe
	Activation          = device.Activation
	Retirement          = device.Retirement
	Operation           = device.Operation
	State               = device.State
	Journal             = device.Journal
	KeyStore            = device.KeyStore
	Credential          = device.Credential
	IssueRequest        = device.IssueRequest
	Authority           = device.Authority
	Importer            = device.Importer
	Platform            = device.Platform
	CredentialBinding   = device.CredentialBinding
	Evidence            = device.Evidence
	AccessObservation   = device.AccessObservation
	ApplicationEvidence = device.ApplicationEvidence
	WithdrawalEvidence  = device.WithdrawalEvidence
	ConnectionRecord    = device.ConnectionRecord
	SessionInventory    = device.SessionInventory
	RoleRequest         = device.RoleRequest
	RoleResponse        = device.RoleResponse
	Entitlement         = device.Entitlement
	Registration        = device.Registration
	Transport           = device.Transport
	Application         = device.Application
	Withdrawal          = device.Withdrawal
	Clock               = device.Clock
	Roles               = device.Roles
	Adapters            = device.Adapters
	ClockAssessment     = device.ClockAssessment
	SystemClock         = device.SystemClock
	Config              = device.Config
	Limits              = device.Limits
	AdapterSpec         = device.AdapterSpec
	Composition         = device.Composition
	RoleConfig          = device.RoleConfig
	TrustConfig         = device.TrustConfig
	RoleSnapshot        = device.RoleSnapshot
	PublicSnapshot      = device.PublicSnapshot
)

func DecodeStrict(r io.Reader, target any) error { return device.DecodeStrict(r, target) }
func LoadConfig(path string) (Config, error)     { return device.LoadConfig(path) }
func CheckVersionFields(data []byte) error       { return device.CheckVersionFields(data) }
func ValidDeviceID(id string) bool               { return device.ValidDeviceID(id) }
func Subject(deviceID string, generation uint64) string {
	return device.Subject(deviceID, generation)
}
func RecoverySubject(deviceID string) string { return device.RecoverySubject(deviceID) }
func RandomID() (string, error)              { return device.RandomID() }
func Hash(data []byte) string                { return device.Hash(data) }
func MatchProbe(request, response Probe, now time.Time) error {
	return device.MatchProbe(request, response, now)
}
func DefaultLimits() Limits                               { return device.DefaultLimits() }
func DecodeSnapshot(data []byte) (*PublicSnapshot, error) { return device.DecodeSnapshot(data) }
func RequiredCapability(role string) (string, error)      { return device.RequiredCapability(role) }
