// SPDX-License-Identifier: Apache-2.0

// Package conformance checks adapter semantics through public SDK contracts.
// Harness hooks are supplied observations, not authentication or hardware evidence.
package conformance

import (
	"context"
	"errors"
	"slices"
	"time"

	"knowndevice.local/knowndevice/sdk/credentialprofile"
	"knowndevice.local/knowndevice/sdk/device"
)

const Version = "knowndevice-conformance/0.1-alpha.1"

var ErrNonconformant = errors.New("adapter conformance checks failed")

// Connector opens a new adapter session over an immutable public snapshot.
// Closing that session must preserve the harness backend's reservations and effects.
type Connector func(context.Context, *device.PublicSnapshot) (device.Adapters, func() error, error)

type Request struct {
	ProfileID string
	Case      string
}

// Factory must create a separate identity and backend for every Open call.
// Implementations can instrument real services; the suite never infers a service's
// lookup, idempotency or persistence guarantees from a Go interface.
type Factory interface {
	Open(context.Context, Request) (*Harness, error)
}

type FactoryFunc func(context.Context, Request) (*Harness, error)

func (f FactoryFunc) Open(ctx context.Context, r Request) (*Harness, error) { return f(ctx, r) }

type Fault string

const (
	NoFault                   Fault = "none"
	LostIssueResponse         Fault = "lost-issue-response"
	LateIssueResponse         Fault = "late-issue-response"
	DeniedScope               Fault = "denied-scope"
	StaleGeneration           Fault = "stale-generation"
	LookupUnavailable         Fault = "lookup-unavailable"
	CandidateOnly             Fault = "candidate-only"
	MissingActivationRevision Fault = "missing-activation-revision"
	MissingFreshObservation   Fault = "missing-fresh-observation"
	TLSOnlyRetirement         Fault = "tls-only-retirement"
	MissingSessions           Fault = "missing-sessions"
	StaleRetirementTarget     Fault = "stale-retirement-target"
)

type Effect string

const (
	IssueEffect Effect = "issue"
	LateReply   Effect = "late-reply"
)

// Observation contains backend counters, not client method-call counts. An issue
// effect means a backend issuance attempt; lookup must never increase that count.
// The provider must observe active generation from its authenticated peer/registry
// binding, never from a subject label, ClientID or device payload.
type Observation struct {
	IssueCalls              uint64   `json:"issueCalls"`
	IssueEffects            uint64   `json:"issueEffects"`
	LookupCalls             uint64   `json:"lookupCalls"`
	RegistrationEffects     uint64   `json:"registrationEffects"`
	ApplicationSelections   uint64   `json:"applicationSelections"`
	ActivationEffects       uint64   `json:"activationEffects"`
	ApplicationObservations uint64   `json:"applicationObservations"`
	WithdrawalEffects       uint64   `json:"withdrawalEffects"`
	RevocationEffects       uint64   `json:"revocationEffects"`
	LateResponses           uint64   `json:"lateResponses"`
	InjectedProofFault      Fault    `json:"injectedProofFault,omitempty"`
	InjectedProofResponses  uint64   `json:"injectedProofResponses"`
	ActiveGeneration        uint64   `json:"activeGeneration"`
	ReservedGeneration      uint64   `json:"reservedGeneration"`
	DeniedGenerations       []uint64 `json:"deniedGenerations"`
}

// Harness prepares an authorized generation 1 and an unissued generation 2.
// Target carries the original CSR, handle and host-held signer. Its chain is empty
// until the suite accepts a bound Issue/Lookup result. This vector does not
// authorize registration, selection or activation in the backend.
// Arm affects the next tested action. LateIssueResponse holds the response until
// Release, even after cancellation. Await observes an effect after dispatch.
// Restart replaces only the adapter session; it must retain backend state.
// Every hook is required. Unsupported hooks fail their case rather than pass it.
type Harness struct {
	Scope        string
	Snapshot     *device.PublicSnapshot
	Plan         device.Plan
	Previous     device.Credential
	Target       device.Credential
	WrongProfile device.Credential
	WrongTrust   device.Credential
	Adapters     device.Adapters
	Arm          func(Fault) error
	Await        func(context.Context, Effect) error
	Release      func() error
	Observe      func() Observation
	Restart      func(context.Context) (device.Adapters, error)
	Close        func() error
}

type Result struct {
	ProfileID string `json:"profileId"`
	Case      string `json:"case"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
}

type Report struct {
	Version string   `json:"version"`
	Scope   string   `json:"scope"`
	Results []Result `json:"results"`
}

type checkCase struct {
	name string
	run  func(context.Context, *Harness) string
}

var cases = []checkCase{
	{"success", success},
	{"lost-issuance-response", lostResponse},
	{"late-issuance-response", lateResponse},
	{"duplicate-issuance", duplicate},
	{"adapter-restart", restart},
	{"cancel-before-dispatch", cancelBefore},
	{"cancel-after-effect", cancelAfter},
	{"denied-scope", deniedScope},
	{"stale-generation", staleGeneration},
	{"wrong-credential-profile", wrongProfile},
	{"wrong-trust-profile", wrongTrust},
	{"lookup-unavailable", lookupUnavailable},
	{"candidate-not-activation", candidateOnly},
	{"activation-revision", activationRevision},
	{"activation-fresh-observation", activationFreshness},
	{"effective-retirement", effectiveRetirement},
	{"retirement-tls-only", retirementTLS},
	{"retirement-missing-sessions", retirementSessions},
	{"retirement-stale-target", retirementTarget},
}

// Cases returns the exact case names in execution order for external CI fixtures.
func Cases() []string {
	names := make([]string, len(cases))
	for i, c := range cases {
		names[i] = c.name
	}
	return names
}

// Run executes both reviewed profiles. A failure is retained and the remaining
// independent cases continue. Reports use fixed reasons and never include an
// adapter's error text, credential bytes, private paths or callback payloads.
func Run(ctx context.Context, factory Factory) (Report, error) {
	report := Report{Version: Version, Results: []Result{}}
	failed := nilValue(factory)
	for _, profile := range []string{credentialprofile.ReferenceID, credentialprofile.StableID} {
		for _, c := range cases {
			result := Result{ProfileID: profile, Case: c.name, Status: "fail"}
			if nilValue(factory) {
				result.Reason = "factory unavailable"
			} else if ctx.Err() != nil {
				result.Reason = "suite context ended"
			} else {
				caseCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				h, err := factory.Open(caseCtx, Request{ProfileID: profile, Case: c.name})
				if err != nil {
					result.Reason = "harness initialization failed"
				} else if reason := validHarness(h, profile); reason != "" {
					result.Reason = reason
				} else {
					if report.Scope == "" {
						report.Scope = h.Scope
					}
					if report.Scope != h.Scope {
						result.Reason = "mixed harness scopes"
					} else {
						result.Reason = c.run(caseCtx, h)
					}
				}
				if h != nil && h.Close != nil && h.Close() != nil && result.Reason == "" {
					result.Reason = "harness cleanup failed"
				}
				cancel()
				if result.Reason == "" {
					result.Status = "pass"
				}
			}
			failed = failed || result.Status != "pass"
			report.Results = append(report.Results, result)
		}
	}
	if failed {
		return report, ErrNonconformant
	}
	return report, nil
}

func validHarness(h *Harness, profile string) string {
	if h == nil || h.Scope != "in-memory-model" && h.Scope != "service-harness" || h.Snapshot == nil || h.Arm == nil || h.Await == nil || h.Release == nil || h.Observe == nil || h.Restart == nil || h.Close == nil || h.Adapters.Validate() != nil {
		return "incomplete harness"
	}
	if h.Snapshot.Validate() != nil || h.Snapshot.Profile.ID != profile || h.Snapshot.ValidatePlan(h.Plan) != nil || h.Plan.Validate(time.Now().UTC()) != nil || h.Plan.Mode != "rotate" || h.Plan.ExpectedGeneration != 1 || h.Plan.TargetGeneration != 2 || h.Previous.Handle.Binding.Generation != 1 || h.Target.Handle.Binding != h.Plan.Binding() {
		return "harness vectors do not match scope"
	}
	if _, err := publicBinding(h.Previous); err != nil {
		return "invalid previous credential vector"
	}
	if h.Target.Recovery || h.Target.Handle.Validate() != nil || len(h.Target.TLS.Certificate) != 0 {
		return "invalid unissued target credential vector"
	}
	o := h.Observe()
	if o.ActiveGeneration != 1 || o.ReservedGeneration != 0 || !noEffects(o) || o.IssueCalls != 0 || o.LookupCalls != 0 || len(o.DeniedGenerations) != 0 {
		return "harness is not fresh"
	}
	return ""
}

func noEffects(o Observation) bool {
	return o.IssueEffects == 0 && o.RegistrationEffects == 0 && o.ApplicationSelections == 0 && o.ActivationEffects == 0 && o.WithdrawalEffects == 0 && o.RevocationEffects == 0
}

func sameEffects(a, b Observation) bool {
	return a.IssueEffects == b.IssueEffects && a.RegistrationEffects == b.RegistrationEffects && a.ApplicationSelections == b.ApplicationSelections && a.ActivationEffects == b.ActivationEffects && a.ApplicationObservations == b.ApplicationObservations && a.WithdrawalEffects == b.WithdrawalEffects && a.RevocationEffects == b.RevocationEffects && a.ActiveGeneration == b.ActiveGeneration && a.ReservedGeneration == b.ReservedGeneration && slices.Equal(a.DeniedGenerations, b.DeniedGenerations)
}

func issueRequest(h *Harness) device.IssueRequest {
	return device.IssueRequest{Plan: h.Plan, CSR: h.Target.CSR, Credential: &h.Previous}
}
