// SPDX-License-Identifier: Apache-2.0

package process

import (
	"context"
	"math"
	"time"

	"github.com/knowndevice/knowndevice/sdk/device"
)

func (c *Client) Authorize(ctx context.Context, p device.Plan, k *device.Credential) error {
	if err := validateCaller(c.snapshot, p, k); err != nil {
		return err
	}
	var result BoundResult[Empty]
	return c.invoke(ctx, "entitlement.authorize", p, []device.Credential{*k}, func(s Scope, w []WireCredential) any { return AuthorizeParams{s, p, &w[0]} }, "boundEmpty", &result)
}
func (c *Client) issue(ctx context.Context, method string, r device.IssueRequest) ([]byte, error) {
	if _, err := c.snapshot.Profile.ValidateCSR(r.CSR, r.Plan.DeviceID, r.Plan.TargetGeneration); err != nil {
		return nil, device.ErrDenied
	}
	if err := validateCaller(c.snapshot, r.Plan, r.Credential); err != nil {
		return nil, err
	}
	var result BoundResult[[]byte]
	err := c.invoke(ctx, method, r.Plan, []device.Credential{*r.Credential}, func(s Scope, w []WireCredential) any { return IssueParams{s, r.Plan, r.CSR, &w[0]} }, "boundCertificate", &result)
	if err == nil {
		err = validateCertificate(c.snapshot, r.Plan, r.CSR, result.Value)
		if err != nil {
			c.stop(false)
		}
	}
	return result.Value, err
}
func (c *Client) Issue(ctx context.Context, r device.IssueRequest) ([]byte, error) {
	return c.issue(ctx, "authority.issue", r)
}
func (c *Client) Lookup(ctx context.Context, r device.IssueRequest) ([]byte, error) {
	return c.issue(ctx, "authority.lookup", r)
}
func (c *Client) Import(ctx context.Context, r device.IssueRequest, certificate []byte) error {
	if err := validateCaller(c.snapshot, r.Plan, r.Credential); err != nil {
		return err
	}
	if validateCertificate(c.snapshot, r.Plan, r.CSR, certificate) != nil {
		return device.ErrDenied
	}
	var result BoundResult[Empty]
	return c.invoke(ctx, "authority.import", r.Plan, []device.Credential{*r.Credential}, func(s Scope, w []WireCredential) any { return ImportParams{s, r.Plan, r.CSR, certificate, &w[0]} }, "boundEmpty", &result)
}
func (c *Client) registration(ctx context.Context, method string, p device.Plan, k device.Credential) error {
	if err := validateTarget(c.snapshot, p, k); err != nil {
		return err
	}
	var result BoundResult[Empty]
	return c.invoke(ctx, method, p, []device.Credential{k}, func(s Scope, w []WireCredential) any { return CredentialParams{s, p, w[0]} }, "boundEmpty", &result)
}
func (c *Client) Register(ctx context.Context, p device.Plan, k device.Credential) error {
	return c.registration(ctx, "platform.register", p, k)
}
func (c *Client) Registration(ctx context.Context, p device.Plan, k device.Credential) error {
	return c.registration(ctx, "platform.registrationStatus", p, k)
}
func (c *Client) Probe(ctx context.Context, probe device.Probe, k device.Credential) (device.Probe, error) {
	c.mu.Lock()
	p, exists := c.plans[probe.OperationID]
	c.mu.Unlock()
	if !exists {
		return device.Probe{}, device.ErrConflict
	}
	if err := validateTarget(c.snapshot, p, k); err != nil {
		return device.Probe{}, err
	}
	role, _ := c.snapshot.Role("transport")
	if probe.OperationID != p.OperationID || probe.DeviceID != p.DeviceID || probe.Generation != p.TargetGeneration || probe.Endpoint != role.Endpoint || !signerID.MatchString(probe.Nonce) || probe.Deadline.After(p.ExpiresAt) {
		return device.Probe{}, device.ErrDenied
	}
	var result BoundResult[device.Probe]
	err := c.invoke(ctx, "transport.probe", p, []device.Credential{k}, func(s Scope, w []WireCredential) any { return ProbeParams{s, p, probe, w[0]} }, "boundProbe", &result)
	if err == nil {
		err = device.MatchProbe(probe, result.Value, time.Now().UTC())
		if err != nil {
			c.stop(false)
			err = device.ErrUnknown
		}
	}
	return result.Value, err
}
func (c *Client) activation(ctx context.Context, method string, p device.Plan, k device.Credential) (device.Activation, error) {
	if err := validateTarget(c.snapshot, p, k); err != nil {
		return device.Activation{}, err
	}
	var result BoundResult[device.Activation]
	err := c.invoke(ctx, method, p, []device.Credential{k}, func(s Scope, w []WireCredential) any { return CredentialParams{s, p, w[0]} }, "boundActivation", &result)
	if err == nil {
		err = validateActivation(c.snapshot, p, k, result.Value)
		if err != nil {
			c.stop(false)
		}
	}
	return result.Value, err
}
func (c *Client) Activate(ctx context.Context, p device.Plan, k device.Credential) (device.Activation, error) {
	return c.activation(ctx, "application.activate", p, k)
}
func (c *Client) ActivationStatus(ctx context.Context, p device.Plan, k device.Credential) (device.Activation, error) {
	return c.activation(ctx, "application.activationStatus", p, k)
}
func (c *Client) pair(ctx context.Context, method string, p device.Plan, previous, target device.Credential) (device.Retirement, error) {
	if err := validatePair(c.snapshot, p, previous, target); err != nil {
		return device.Retirement{}, err
	}
	params := func(s Scope, w []WireCredential) any { return PairParams{s, p, w[0], w[1]} }
	if method == "authority.revoke" || method == "authority.revocationStatus" {
		var result BoundResult[Empty]
		err := c.invoke(ctx, method, p, []device.Credential{previous, target}, params, "boundEmpty", &result)
		return device.Retirement{}, err
	}
	var result BoundResult[device.Retirement]
	err := c.invoke(ctx, method, p, []device.Credential{previous, target}, params, "boundRetirement", &result)
	if err == nil {
		err = validateRetirement(c.snapshot, p, previous, target, result.Value)
		if err != nil {
			c.stop(false)
		}
	}
	return result.Value, err
}
func (c *Client) Retire(ctx context.Context, p device.Plan, previous, target device.Credential) (device.Retirement, error) {
	return c.pair(ctx, "withdrawal.withdraw", p, previous, target)
}
func (c *Client) RetirementStatus(ctx context.Context, p device.Plan, previous, target device.Credential) (device.Retirement, error) {
	return c.pair(ctx, "withdrawal.status", p, previous, target)
}
func (c *Client) Revoke(ctx context.Context, p device.Plan, previous, target device.Credential) error {
	_, err := c.pair(ctx, "authority.revoke", p, previous, target)
	return err
}
func (c *Client) RevocationStatus(ctx context.Context, p device.Plan, previous, target device.Credential) error {
	_, err := c.pair(ctx, "authority.revocationStatus", p, previous, target)
	return err
}

func (c *Client) Assess(ctx context.Context, floor time.Time) (device.ClockAssessment, error) {
	if !has(c.capabilities, "clock.assess") {
		return device.ClockAssessment{}, device.ErrUnsupported
	}
	select {
	case c.clock <- struct{}{}:
		defer func() { <-c.clock }()
	case <-ctx.Done():
		return device.ClockAssessment{}, ctx.Err()
	case <-c.done:
		return device.ClockAssessment{}, device.ErrUnknown
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.snapshot.RequestTimeoutSeconds)*time.Second)
	defer cancel()
	started := time.Now()
	var result ClockResult
	if err := c.control(ctx, "clock.assess", ClockParams{floor}, "clockResult", &result); err != nil {
		return device.ClockAssessment{}, err
	}
	received := time.Now()
	elapsed := received.Sub(started)
	maxAge := time.Duration(result.MaximumAgeMillis) * time.Millisecond
	if elapsed < 0 || elapsed >= maxAge || maxAge > time.Duration(c.snapshot.Limits.MaximumAssessmentAgeSeconds)*time.Second || math.IsNaN(result.DriftPPM) || math.IsInf(result.DriftPPM, 0) || result.DriftPPM != float64(c.snapshot.Limits.DriftPPM) || !result.Trusted || result.Source != c.snapshot.ClockTrust {
		c.stop(false)
		return device.ClockAssessment{}, device.ErrUnknown
	}
	a := device.ClockAssessment{Earliest: result.Earliest.Add(-elapsed), Latest: result.Latest.Add(elapsed), AssessedAt: received, DriftPPM: result.DriftPPM, MaximumAge: maxAge - elapsed, Trusted: result.Trusted, Source: result.Source}
	if a.Latest.Sub(a.Earliest) > 2*time.Duration(c.snapshot.Limits.MaximumUncertaintyMillis)*time.Millisecond {
		return device.ClockAssessment{}, device.ErrDenied
	}
	if _, _, err := a.Interval(received, floor); err != nil {
		return device.ClockAssessment{}, err
	}
	return a, nil
}

var _ device.Authority = (*Client)(nil)
var _ device.Importer = (*Client)(nil)
var _ device.Platform = (*Client)(nil)
var _ device.Clock = (*Client)(nil)
