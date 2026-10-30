// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"context"
	"errors"
	"time"

	"knowndevice.local/knowndevice/sdk/credentialprofile"
	"knowndevice.local/knowndevice/sdk/device"
)

func expectedChain(ctx context.Context, h *Harness, chain []byte) bool {
	certs, err := credentialprofile.ParseChain(chain)
	early, late, clockErr := assessedInterval(ctx, h)
	if err != nil || clockErr != nil || !validChainAt(h, h.Target, chain, false, early, late) {
		return false
	}
	if len(h.Target.TLS.Certificate) > 0 {
		if len(certs) != len(h.Target.TLS.Certificate) {
			return false
		}
		for i, c := range certs {
			if !bytes.Equal(c.Raw, h.Target.TLS.Certificate[i]) {
				return false
			}
		}
	} else {
		candidate := h.Target
		candidate.TLS.Certificate = make([][]byte, len(certs))
		for i, c := range certs {
			candidate.TLS.Certificate[i] = c.Raw
		}
		candidate.TLS.Leaf = certs[0]
		if _, err := publicBinding(candidate); err != nil {
			return false
		}
		h.Target = candidate
	}
	return true
}

func authorized(ctx context.Context, h *Harness) string {
	before := h.Observe()
	if err := h.Adapters.Entitlement.Authorize(ctx, h.Plan, &h.Previous); err != nil {
		return "current authorized peer was refused entitlement"
	}
	after := h.Observe()
	if !sameEffects(after, before) || after.IssueCalls != before.IssueCalls || after.LookupCalls != before.LookupCalls || after.LateResponses != before.LateResponses || after.InjectedProofFault != before.InjectedProofFault || after.InjectedProofResponses != before.InjectedProofResponses {
		return "entitlement authorization caused a backend effect"
	}
	return ""
}

func issued(ctx context.Context, h *Harness) string {
	if reason := authorized(ctx, h); reason != "" {
		return reason
	}
	chain, err := h.Adapters.Authority.Issue(ctx, issueRequest(h))
	if err != nil || !expectedChain(ctx, h, chain) {
		return "issuance did not return the bound credential"
	}
	o := h.Observe()
	if o.IssueCalls != 1 || o.IssueEffects != 1 || o.ReservedGeneration != 2 || o.ActiveGeneration != 1 || o.RegistrationEffects != 0 || o.ApplicationSelections != 0 || o.ActivationEffects != 0 || o.WithdrawalEffects != 0 || o.RevocationEffects != 0 {
		return "issuance effect counters or preserved generation differ"
	}
	return ""
}

func prepared(ctx context.Context, h *Harness) string {
	if reason := issued(ctx, h); reason != "" {
		return reason
	}
	if err := h.Adapters.Platform.Register(ctx, h.Plan, h.Target); err != nil {
		return "registration failed"
	}
	if err := h.Adapters.Platform.Registration(ctx, h.Plan, h.Target); err != nil {
		return "registration lookup failed"
	}
	role, _ := h.Snapshot.Role("transport")
	nonce, err := device.RandomID()
	if err != nil {
		return "challenge allocation failed"
	}
	probe := device.Probe{OperationID: h.Plan.OperationID, DeviceID: h.Plan.DeviceID, Generation: 2, Endpoint: role.Endpoint, Nonce: nonce, Deadline: time.Now().UTC().Add(10 * time.Second)}
	response, err := h.Adapters.Transport.Probe(ctx, probe, h.Target)
	if err != nil || device.MatchProbe(probe, response, time.Now().UTC().Add(time.Second)) != nil {
		return "fresh candidate access observation failed"
	}
	o := h.Observe()
	if o.RegistrationEffects != 1 || o.ActiveGeneration != 1 || o.ApplicationSelections != 0 || o.ActivationEffects != 0 || o.WithdrawalEffects != 0 || o.RevocationEffects != 0 {
		return "candidate verification changed activation or retirement"
	}
	return ""
}

func activated(ctx context.Context, h *Harness) string {
	if reason := prepared(ctx, h); reason != "" {
		return reason
	}
	_, err := h.Adapters.Application.ActivationStatus(ctx, h.Plan, h.Target)
	if !errors.Is(err, device.ErrNotFound) {
		return "activation absence was not an explicit bound status"
	}
	a, err := h.Adapters.Application.Activate(ctx, h.Plan, h.Target)
	if err != nil || !validActivation(ctx, h, a) {
		return "activation lacks complete fresh application proof"
	}
	before := h.Observe()
	status, err := h.Adapters.Application.ActivationStatus(ctx, h.Plan, h.Target)
	if err != nil || !validActivation(ctx, h, status) || status.Evidence.ActivationRevision != a.Evidence.ActivationRevision || status.Probe.Nonce == a.Probe.Nonce || status.Evidence.Evidence.ObservedAt.Before(a.Evidence.Evidence.ObservedAt) {
		return "activation lookup did not return a new bound observation"
	}
	o := h.Observe()
	if o.ActiveGeneration != 2 || o.ApplicationSelections != 1 || o.ActivationEffects != 1 || o.ApplicationObservations <= before.ApplicationObservations || o.WithdrawalEffects != 0 || o.RevocationEffects != 0 || len(o.DeniedGenerations) != 0 {
		return "activation counters or previous access differ"
	}
	return ""
}

func retired(ctx context.Context, h *Harness) string {
	if reason := activated(ctx, h); reason != "" {
		return reason
	}
	r, err := h.Adapters.Withdrawal.Retire(ctx, h.Plan, h.Previous, h.Target)
	if err != nil || !validRetirement(ctx, h, r) {
		return "retirement lacks effective withdrawal proof"
	}
	before := h.Observe()
	status, err := h.Adapters.Withdrawal.RetirementStatus(ctx, h.Plan, h.Previous, h.Target)
	if err != nil || !validRetirement(ctx, h, status) || status.Evidence.PolicyRevision != r.Evidence.PolicyRevision || status.Evidence.Current.Challenge.Nonce == r.Evidence.Current.Challenge.Nonce {
		return "withdrawal lookup did not refresh target use"
	}
	o := h.Observe()
	if o.ActiveGeneration != 2 || o.WithdrawalEffects != 1 || o.RevocationEffects != 0 || len(o.DeniedGenerations) != 1 || o.DeniedGenerations[0] != 1 || o.ApplicationObservations <= before.ApplicationObservations {
		return "effective withdrawal counters differ"
	}
	return ""
}

func success(ctx context.Context, h *Harness) string {
	if _, err := h.Adapters.Clock.Assess(ctx, time.Now().UTC().Add(time.Hour)); !errors.Is(err, device.ErrDenied) && !errors.Is(err, device.ErrUnknown) {
		return "clock floor rollback was not explicitly refused"
	}
	if reason := retired(ctx, h); reason != "" {
		return reason
	}
	if err := h.Adapters.Authority.Revoke(ctx, h.Plan, h.Previous, h.Target); err != nil {
		return "passive revocation failed after withdrawal"
	}
	if err := h.Adapters.Authority.RevocationStatus(ctx, h.Plan, h.Previous, h.Target); err != nil {
		return "passive revocation lookup failed"
	}
	o := h.Observe()
	if o.IssueCalls != 1 || o.IssueEffects != 1 || o.ActiveGeneration != 2 || o.RegistrationEffects != 1 || o.ApplicationSelections != 1 || o.ActivationEffects != 1 || o.WithdrawalEffects != 1 || o.RevocationEffects != 1 {
		return "completed lifecycle effect counters differ"
	}
	return ""
}

func recovered(ctx context.Context, h *Harness) string {
	a, err := h.Restart(ctx)
	if err != nil || a.Validate() != nil {
		return "adapter restart failed"
	}
	h.Adapters = a
	chain, err := a.Authority.Lookup(ctx, issueRequest(h))
	if err != nil || !expectedChain(ctx, h, chain) {
		return "exact issuance lookup failed after restart"
	}
	o := h.Observe()
	if o.IssueCalls != 1 || o.IssueEffects != 1 || o.LookupCalls != 1 || o.ReservedGeneration != 2 || o.ActiveGeneration != 1 || o.ActivationEffects != 0 || o.WithdrawalEffects != 0 {
		return "reconciliation replayed issuance or changed active generation"
	}
	return ""
}

func lostResponse(ctx context.Context, h *Harness) string {
	if h.Arm(LostIssueResponse) != nil {
		return "required lost-response hook unavailable"
	}
	if reason := authorized(ctx, h); reason != "" {
		return reason
	}
	_, err := h.Adapters.Authority.Issue(ctx, issueRequest(h))
	if !errors.Is(err, device.ErrUnknown) {
		return "lost issuance response did not remain unknown"
	}
	if h.Observe().IssueEffects != 1 || h.Observe().ReservedGeneration != 2 {
		return "lost response lost the issuance reservation"
	}
	if h.Arm(NoFault) != nil {
		return "fault reset failed"
	}
	return recovered(ctx, h)
}

func interrupted(ctx context.Context, h *Harness, deadline bool) string {
	if h.Arm(LateIssueResponse) != nil {
		return "required late-response hook unavailable"
	}
	if reason := authorized(ctx, h); reason != "" {
		return reason
	}
	callCtx, cancel := context.WithCancel(ctx)
	if deadline {
		cancel()
		callCtx, cancel = context.WithTimeout(ctx, 750*time.Millisecond)
	}
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := h.Adapters.Authority.Issue(callCtx, issueRequest(h))
		done <- err
	}()
	effectReady := make(chan error, 1)
	go func() { effectReady <- h.Await(ctx, IssueEffect) }()
	select {
	case err := <-effectReady:
		if err != nil {
			return "issuance effect was not observed before cancellation"
		}
	case <-done:
		return "issuance call ended before the held effect was observed"
	case <-ctx.Done():
		return "issuance effect was not observed before cancellation"
	}
	if !deadline {
		cancel()
	}
	select {
	case err := <-done:
		if !errors.Is(err, device.ErrUnknown) {
			return "interrupted dispatched issuance did not remain unknown"
		}
	case <-ctx.Done():
		return "cancelled adapter call did not finish"
	}
	if h.Release() != nil || h.Await(ctx, LateReply) != nil {
		return "late response release was not observed"
	}
	o := h.Observe()
	if o.IssueEffects != 1 || o.ReservedGeneration != 2 || o.ActiveGeneration != 1 || o.LateResponses != 1 || o.ActivationEffects != 0 || o.WithdrawalEffects != 0 {
		return "cancellation removed intent or advanced a late result"
	}
	if h.Arm(NoFault) != nil {
		return "fault reset failed"
	}
	return recovered(ctx, h)
}

func lateResponse(ctx context.Context, h *Harness) string { return interrupted(ctx, h, true) }
func cancelAfter(ctx context.Context, h *Harness) string  { return interrupted(ctx, h, false) }

func duplicate(ctx context.Context, h *Harness) string {
	if reason := issued(ctx, h); reason != "" {
		return reason
	}
	chain, err := h.Adapters.Authority.Issue(ctx, issueRequest(h))
	if err != nil || !expectedChain(ctx, h, chain) {
		return "duplicate exact issuance did not retain the existing result"
	}
	o := h.Observe()
	if o.IssueCalls != 2 || o.IssueEffects != 1 || o.ActiveGeneration != 1 {
		return "duplicate exact issuance dispatched another effect"
	}
	return ""
}

func restart(ctx context.Context, h *Harness) string {
	if reason := issued(ctx, h); reason != "" {
		return reason
	}
	return recovered(ctx, h)
}

func cancelBefore(ctx context.Context, h *Harness) string {
	callCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, err := h.Adapters.Authority.Issue(callCtx, issueRequest(h))
	if !errors.Is(err, context.Canceled) && !errors.Is(err, device.ErrUnknown) {
		return "pre-dispatch cancellation was not explicit"
	}
	o := h.Observe()
	if !noEffects(o) || o.IssueCalls != 0 || o.ReservedGeneration != 0 || o.ActiveGeneration != 1 {
		return "pre-dispatch cancellation caused a backend effect"
	}
	return ""
}

func deniedScope(ctx context.Context, h *Harness) string {
	changed := h.Plan
	changed.DeploymentID = "another-deployment"
	changed.Digest, _ = changed.CalculateDigest()
	err := h.Adapters.Entitlement.Authorize(ctx, changed, &h.Previous)
	if !errors.Is(err, device.ErrDenied) && !errors.Is(err, device.ErrConflict) || !noEffects(h.Observe()) {
		return "changed request scope was not explicitly refused"
	}
	if h.Arm(DeniedScope) != nil {
		return "required scope-refusal hook unavailable"
	}
	err = h.Adapters.Entitlement.Authorize(ctx, h.Plan, &h.Previous)
	if !errors.Is(err, device.ErrDenied) || !noEffects(h.Observe()) || h.Observe().ActiveGeneration != 1 {
		return "scope refusal was not explicit or caused an effect"
	}
	return ""
}

func staleGeneration(ctx context.Context, h *Harness) string {
	if reason := activated(ctx, h); reason != "" {
		return reason
	}
	before := h.Observe()
	// The old actual peer remains cryptographically valid, but is no longer
	// the active issuer authority. A subject label cannot revive generation 1.
	_, err := h.Adapters.Authority.Issue(ctx, issueRequest(h))
	o := h.Observe()
	if !errors.Is(err, device.ErrConflict) && !errors.Is(err, device.ErrDenied) || o.IssueEffects != before.IssueEffects || o.RegistrationEffects != before.RegistrationEffects || o.ApplicationSelections != before.ApplicationSelections || o.ActivationEffects != before.ActivationEffects || o.WithdrawalEffects != 0 || o.RevocationEffects != 0 || o.ReservedGeneration != 2 || o.ActiveGeneration != 2 {
		return "stale generation was not fenced without effects"
	}
	return ""
}

func wrongProfile(ctx context.Context, h *Harness) string {
	err := h.Adapters.Platform.Register(ctx, h.Plan, h.WrongProfile)
	if !errors.Is(err, device.ErrDenied) && !errors.Is(err, device.ErrConflict) || !noEffects(h.Observe()) || h.Observe().ActiveGeneration != 1 {
		return "wrong credential profile was not explicitly refused"
	}
	return ""
}

func wrongTrust(ctx context.Context, h *Harness) string {
	err := h.Adapters.Platform.Register(ctx, h.Plan, h.WrongTrust)
	if !errors.Is(err, device.ErrDenied) && !errors.Is(err, device.ErrConflict) || !noEffects(h.Observe()) || h.Observe().ActiveGeneration != 1 {
		return "wrong trust profile was not explicitly refused"
	}
	return ""
}

func lookupUnavailable(ctx context.Context, h *Harness) string {
	if h.Arm(LostIssueResponse) != nil {
		return "required lost-response hook unavailable"
	}
	if reason := authorized(ctx, h); reason != "" {
		return reason
	}
	_, err := h.Adapters.Authority.Issue(ctx, issueRequest(h))
	if !errors.Is(err, device.ErrUnknown) || h.Arm(LookupUnavailable) != nil {
		return "unknown issuance fixture was not established"
	}
	a, err := h.Restart(ctx)
	if err != nil {
		return "adapter restart failed"
	}
	h.Adapters = a
	_, err = a.Authority.Lookup(ctx, issueRequest(h))
	if !errors.Is(err, device.ErrUnknown) && !errors.Is(err, device.ErrUnsupported) {
		return "unavailable lookup incorrectly established absence or success"
	}
	o := h.Observe()
	if o.IssueCalls != 1 || o.IssueEffects != 1 || o.LookupCalls != 1 || o.ReservedGeneration != 2 || o.ActiveGeneration != 1 {
		return "unavailable lookup replayed or removed unknown issuance"
	}
	return ""
}

func badActivation(ctx context.Context, h *Harness, fault Fault) string {
	if reason := prepared(ctx, h); reason != "" {
		return reason
	}
	if h.Arm(fault) != nil {
		return "required incomplete-activation hook unavailable"
	}
	before := h.Observe()
	_, err := h.Adapters.Application.Activate(ctx, h.Plan, h.Target)
	if !refusal(err) {
		return "incomplete activation was reported as success"
	}
	o := h.Observe()
	if o.InjectedProofFault != fault || o.InjectedProofResponses == 0 {
		return "named incomplete activation proof was not delivered"
	}
	a, err := h.Restart(ctx)
	if err != nil {
		return "adapter restart failed"
	}
	h.Adapters = a
	_, err = a.Application.ActivationStatus(ctx, h.Plan, h.Target)
	if !refusal(err) {
		return "incomplete activation status was reported as success"
	}
	status := h.Observe()
	if status.InjectedProofFault != fault || status.InjectedProofResponses <= o.InjectedProofResponses {
		return "named incomplete activation status proof was not delivered"
	}
	if !sameEffects(status, before) || status.IssueCalls != before.IssueCalls || status.LookupCalls != before.LookupCalls {
		return "incomplete activation authorized CAS or retired the previous generation"
	}
	return ""
}

func candidateOnly(ctx context.Context, h *Harness) string {
	return badActivation(ctx, h, CandidateOnly)
}
func activationRevision(ctx context.Context, h *Harness) string {
	return badActivation(ctx, h, MissingActivationRevision)
}
func activationFreshness(ctx context.Context, h *Harness) string {
	return badActivation(ctx, h, MissingFreshObservation)
}

func effectiveRetirement(ctx context.Context, h *Harness) string {
	_, err := h.Adapters.Withdrawal.Retire(ctx, h.Plan, h.Previous, h.Target)
	if !errors.Is(err, device.ErrDenied) && !errors.Is(err, device.ErrConflict) || !noEffects(h.Observe()) || h.Observe().ActiveGeneration != 1 {
		return "withdrawal before issuance and activation was not refused"
	}
	return retired(ctx, h)
}

func badRetirement(ctx context.Context, h *Harness, fault Fault) string {
	if reason := activated(ctx, h); reason != "" {
		return reason
	}
	if h.Arm(fault) != nil {
		return "required incomplete-withdrawal hook unavailable"
	}
	before := h.Observe()
	_, err := h.Adapters.Withdrawal.Retire(ctx, h.Plan, h.Previous, h.Target)
	if !errors.Is(err, device.ErrUnknown) && !errors.Is(err, device.ErrUnsupported) && !errors.Is(err, device.ErrDenied) {
		return "incomplete withdrawal was reported as effective"
	}
	o := h.Observe()
	if o.InjectedProofFault != fault || o.InjectedProofResponses == 0 {
		return "named incomplete withdrawal proof was not delivered"
	}
	a, err := h.Restart(ctx)
	if err != nil {
		return "adapter restart failed"
	}
	h.Adapters = a
	_, err = a.Withdrawal.RetirementStatus(ctx, h.Plan, h.Previous, h.Target)
	if !errors.Is(err, device.ErrUnknown) && !errors.Is(err, device.ErrUnsupported) && !errors.Is(err, device.ErrDenied) {
		return "incomplete withdrawal status was reported as effective"
	}
	status := h.Observe()
	if status.InjectedProofFault != fault || status.InjectedProofResponses <= o.InjectedProofResponses {
		return "named incomplete withdrawal status proof was not delivered"
	}
	if !sameEffects(status, before) || status.IssueCalls != before.IssueCalls || status.LookupCalls != before.LookupCalls {
		return "incomplete withdrawal retired or revoked the previous generation"
	}
	return ""
}

func retirementTLS(ctx context.Context, h *Harness) string {
	return badRetirement(ctx, h, TLSOnlyRetirement)
}
func retirementSessions(ctx context.Context, h *Harness) string {
	return badRetirement(ctx, h, MissingSessions)
}
func retirementTarget(ctx context.Context, h *Harness) string {
	return badRetirement(ctx, h, StaleRetirementTarget)
}
