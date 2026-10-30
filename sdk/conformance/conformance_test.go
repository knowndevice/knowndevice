// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/sdk/conformance"
	"knowndevice.local/knowndevice/sdk/conformance/fixture"
	"knowndevice.local/knowndevice/sdk/device"
)

func TestBuiltinPublicSuite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	report, err := conformance.Run(ctx, fixture.Factory{})
	for _, result := range report.Results {
		if result.Status != "pass" {
			t.Errorf("%s/%s: %s", result.ProfileID, result.Case, result.Reason)
		}
	}
	if err != nil || report.Scope != "in-memory-model" || len(report.Results) != 2*len(conformance.Cases()) {
		t.Fatalf("suite result: %v, scope=%s, count=%d", err, report.Scope, len(report.Results))
	}
}

type brokenAuthority struct{ device.Authority }

func (brokenAuthority) Issue(context.Context, device.IssueRequest) ([]byte, error) {
	return nil, errors.New("SECRET-MARKER arbitrary backend failure")
}

func TestSuiteRejectsArbitraryErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	factory := conformance.FactoryFunc(func(ctx context.Context, request conformance.Request) (*conformance.Harness, error) {
		if request.Case != "lost-issuance-response" && request.Case != "cancel-before-dispatch" && request.Case != "stale-generation" {
			return nil, device.ErrUnsupported
		}
		h, err := (fixture.Factory{}).Open(ctx, request)
		if err == nil {
			h.Adapters.Authority = brokenAuthority{h.Adapters.Authority}
		}
		return h, err
	})
	report, err := conformance.Run(ctx, factory)
	if !errors.Is(err, conformance.ErrNonconformant) || report.Scope != "in-memory-model" {
		t.Fatal("arbitrary errors were accepted")
	}
	for _, result := range report.Results {
		if result.Case == "lost-issuance-response" || result.Case == "cancel-before-dispatch" || result.Case == "stale-generation" {
			if result.Status != "fail" {
				t.Errorf("arbitrary error passed %s", result.Case)
			}
		}
	}
	data, _ := json.Marshal(report)
	if strings.Contains(string(data), "SECRET-MARKER") {
		t.Fatal("report exposed backend text")
	}
}

type alteredApplication struct {
	device.Application
	mutate func(*device.Activation)
	prior  *device.Activation
	replay bool
}

func (a *alteredApplication) Activate(ctx context.Context, p device.Plan, k device.Credential) (device.Activation, error) {
	result, err := a.Application.Activate(ctx, p, k)
	if err == nil {
		a.mutate(&result)
		copy := result
		a.prior = &copy
	}
	return result, err
}

func (a *alteredApplication) ActivationStatus(ctx context.Context, p device.Plan, k device.Credential) (device.Activation, error) {
	result, err := a.Application.ActivationStatus(ctx, p, k)
	if err == nil && a.replay && a.prior != nil {
		return *a.prior, nil
	}
	return result, err
}

type alteredWithdrawal struct {
	device.Withdrawal
	mutate func(*device.Retirement)
}

func (w alteredWithdrawal) Retire(ctx context.Context, p device.Plan, previous, target device.Credential) (device.Retirement, error) {
	result, err := w.Withdrawal.Retire(ctx, p, previous, target)
	if err == nil {
		w.mutate(&result)
	}
	return result, err
}

func rejectChangedAdapter(t *testing.T, caseName, reason string, change func(*conformance.Harness)) {
	t.Helper()
	opened := 0
	factory := conformance.FactoryFunc(func(ctx context.Context, request conformance.Request) (*conformance.Harness, error) {
		if request.Case != caseName {
			return nil, device.ErrUnsupported
		}
		h, err := (fixture.Factory{}).Open(ctx, request)
		if err == nil {
			opened++
			change(h)
		}
		return h, err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := conformance.Run(ctx, factory)
	if !errors.Is(err, conformance.ErrNonconformant) || opened != 2 {
		t.Fatalf("negative suite did not open both reviewed profiles: opened=%d err=%v", opened, err)
	}
	checked := 0
	for _, result := range report.Results {
		if result.Case == caseName {
			checked++
			if result.Status != "fail" || result.Reason != reason {
				t.Errorf("%s: got %s/%s, want fail/%s", result.ProfileID, result.Status, result.Reason, reason)
			}
		}
	}
	if checked != 2 {
		t.Fatal("negative suite omitted a profile")
	}
}

func TestSuiteRejectsIncompleteApplicationSuccess(t *testing.T) {
	variants := map[string]func(*device.Activation){
		"missing-proof": func(a *device.Activation) { a.Evidence = nil },
		"candidate":     func(a *device.Activation) { a.Evidence.Phase = "candidate-verified" },
		"revision":      func(a *device.Activation) { a.Evidence.ActivationRevision = 0 },
		"revision-mismatch": func(a *device.Activation) {
			a.Evidence.Evidence.Revision++
		},
		"missing-live-connection": func(a *device.Activation) { a.Evidence.ConnectionID = "" },
		"wrong-peer":              func(a *device.Activation) { a.Evidence.Active.PublicKeyDigest = strings.Repeat("e", 64) },
		"wrong-source":            func(a *device.Activation) { a.Evidence.Evidence.Source = strings.Repeat("f", 64) },
		"undeclared-scope":        func(a *device.Activation) { a.Evidence.AcceptedScope = []string{"backlog-transfer"} },
		"stale-observation": func(a *device.Activation) {
			a.Evidence.Evidence.ObservedAt = time.Now().UTC().Add(-6 * time.Second)
		},
		"deadline": func(a *device.Activation) {
			a.Probe.Deadline = time.Now().UTC().Add(500 * time.Millisecond)
			a.Evidence.Challenge = a.Probe
			a.Evidence.Evidence.Deadline = a.Probe.Deadline
		},
	}
	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			rejectChangedAdapter(t, "success", "activation lacks complete fresh application proof", func(h *conformance.Harness) {
				h.Adapters.Application = &alteredApplication{Application: h.Adapters.Application, mutate: mutate}
			})
		})
	}
}

func TestSuiteRejectsReplayedApplicationStatus(t *testing.T) {
	rejectChangedAdapter(t, "success", "activation lookup did not return a new bound observation", func(h *conformance.Harness) {
		h.Adapters.Application = &alteredApplication{Application: h.Adapters.Application, mutate: func(*device.Activation) {}, replay: true}
	})
}

func TestSuiteRejectsIncompleteWithdrawalSuccess(t *testing.T) {
	variants := map[string]func(*device.Retirement){
		"missing-proof":      func(r *device.Retirement) { r.Evidence = nil },
		"ca-revoke-only":     func(r *device.Retirement) { r.ApplicationAccessDenied = false },
		"tls-alert-only":     func(r *device.Retirement) { r.TLSObservation = "denied" },
		"policy-not-durable": func(r *device.Retirement) { r.PolicyDurable = false },
		"missing-sessions":   func(r *device.Retirement) { r.Evidence.SessionsTerminated = false },
		"missing-denial":     func(r *device.Retirement) { r.Evidence.Denial.Kind = "unknown" },
		"wrong-policy-scope": func(r *device.Retirement) { r.Evidence.Scope = "shared-deployment" },
		"stale-target":       func(r *device.Retirement) { r.Evidence.Target.Generation-- },
		"stale-policy":       func(r *device.Retirement) { r.Evidence.PolicyRevision++ },
		"same-nonce":         func(r *device.Retirement) { r.Evidence.Denial.Challenge.Nonce = r.Evidence.Current.Challenge.Nonce },
		"target-before-denial": func(r *device.Retirement) {
			r.Evidence.Current.Evidence.ObservedAt = r.Evidence.Denial.Evidence.ObservedAt.Add(-time.Millisecond)
		},
	}
	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			rejectChangedAdapter(t, "effective-retirement", "retirement lacks effective withdrawal proof", func(h *conformance.Harness) {
				h.Adapters.Withdrawal = alteredWithdrawal{Withdrawal: h.Adapters.Withdrawal, mutate: mutate}
			})
		})
	}
}

func TestSuiteRejectsEffectsHiddenByMethodSuccess(t *testing.T) {
	rejectChangedAdapter(t, "success", "issuance effect counters or preserved generation differ", func(h *conformance.Harness) {
		observe := h.Observe
		h.Observe = func() conformance.Observation {
			o := observe()
			o.IssueEffects = 0
			return o
		}
	})
}

type alteredClock struct {
	device.Clock
	mutate func(*device.ClockAssessment)
}

func (c alteredClock) Assess(ctx context.Context, floor time.Time) (device.ClockAssessment, error) {
	a, err := c.Clock.Assess(ctx, floor)
	if err == nil {
		c.mutate(&a)
	}
	return a, err
}

func TestSuiteUsesAdapterClockInterval(t *testing.T) {
	variants := map[string]func(*device.ClockAssessment){
		"stale": func(a *device.ClockAssessment) {
			a.AssessedAt = time.Now().Add(-a.MaximumAge - time.Second)
		},
		"maximum-age": func(a *device.ClockAssessment) { a.MaximumAge = 11 * time.Second },
		"drift":       func(a *device.ClockAssessment) { a.DriftPPM = 51 },
		"wide-interval": func(a *device.ClockAssessment) {
			a.Earliest = a.Earliest.Add(-3 * time.Second)
		},
	}
	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			rejectChangedAdapter(t, "success", "issuance did not return the bound credential", func(h *conformance.Harness) {
				h.Adapters.Clock = alteredClock{Clock: h.Adapters.Clock, mutate: mutate}
			})
		})
	}
}

func TestSuiteClosesHarnessReturnedWithInitializationError(t *testing.T) {
	closed := 0
	_, err := conformance.Run(context.Background(), conformance.FactoryFunc(func(context.Context, conformance.Request) (*conformance.Harness, error) {
		return &conformance.Harness{Close: func() error { closed++; return nil }}, device.ErrUnsupported
	}))
	if !errors.Is(err, conformance.ErrNonconformant) || closed != 2*len(conformance.Cases()) {
		t.Fatal("initialization failure leaked a returned harness")
	}
}

func TestSuiteRejectsTypedNilFactory(t *testing.T) {
	var factory conformance.FactoryFunc
	report, err := conformance.Run(context.Background(), factory)
	if !errors.Is(err, conformance.ErrNonconformant) || len(report.Results) != 2*len(conformance.Cases()) {
		t.Fatal("typed nil factory was accepted")
	}
}

type panicSigner struct{}

func (*panicSigner) Public() crypto.PublicKey { panic("typed nil signer was dereferenced") }
func (*panicSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("typed nil signer was invoked")
}

func TestSuiteRejectsTypedNilSigner(t *testing.T) {
	rejectChangedAdapter(t, "success", "invalid previous credential vector", func(h *conformance.Harness) {
		var signer *panicSigner
		h.Previous.TLS.PrivateKey = signer
	})
}

type denyingEntitlement struct{}

func (denyingEntitlement) Authorize(context.Context, device.Plan, *device.Credential) error {
	return device.ErrDenied
}

func TestSuiteRequiresPositiveEntitlement(t *testing.T) {
	rejectChangedAdapter(t, "success", "current authorized peer was refused entitlement", func(h *conformance.Harness) {
		h.Adapters.Entitlement = denyingEntitlement{}
	})
}

type refusingApplication struct{ device.Application }

func (refusingApplication) Activate(context.Context, device.Plan, device.Credential) (device.Activation, error) {
	return device.Activation{}, device.ErrDenied
}

type refusingWithdrawal struct{ device.Withdrawal }

func (refusingWithdrawal) Retire(context.Context, device.Plan, device.Credential, device.Credential) (device.Retirement, error) {
	return device.Retirement{}, device.ErrUnknown
}

func TestSuiteRequiresNamedWireFaultDelivery(t *testing.T) {
	for _, name := range []string{"candidate-not-activation", "activation-revision", "activation-fresh-observation"} {
		t.Run(name, func(t *testing.T) {
			rejectChangedAdapter(t, name, "named incomplete activation proof was not delivered", func(h *conformance.Harness) {
				h.Adapters.Application = refusingApplication{h.Adapters.Application}
			})
		})
	}
	for _, name := range []string{"retirement-tls-only", "retirement-missing-sessions", "retirement-stale-target"} {
		t.Run(name, func(t *testing.T) {
			rejectChangedAdapter(t, name, "named incomplete withdrawal proof was not delivered", func(h *conformance.Harness) {
				h.Adapters.Withdrawal = refusingWithdrawal{h.Adapters.Withdrawal}
			})
		})
	}
}
