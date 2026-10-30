// SPDX-License-Identifier: Apache-2.0

// Package profilehttp implements the internal generated-data HTTP composition.
package profilehttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/knowndevice/knowndevice/adapters/credentials"
	"github.com/knowndevice/knowndevice/adapters/process"
	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
	"github.com/knowndevice/knowndevice/sdk/device"
)

type Client struct {
	snapshot *device.PublicSnapshot
	mu       sync.Mutex
	plans    map[string]device.Plan
	clock    device.Clock
	dial     func(context.Context, string, string) (net.Conn, error)
}

func New(snapshot *device.PublicSnapshot) (*Client, error) {
	if snapshot == nil {
		return nil, device.ErrUnsupported
	}
	s, e := device.DecodeSnapshot(snapshot.Bytes())
	if e != nil {
		return nil, e
	}
	return &Client{snapshot: s, plans: map[string]device.Plan{}, clock: device.SystemClock{Uncertainty: time.Second, MaximumAge: time.Duration(s.Limits.MaximumAssessmentAgeSeconds) * time.Second, DriftPPM: float64(s.Limits.DriftPPM)}}, nil
}
func (c *Client) SetPlan(p device.Plan) error {
	if e := c.snapshot.ValidatePlan(p); e != nil {
		return e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.plans[p.OperationID]; ok && old != p {
		return device.ErrConflict
	}
	c.plans[p.OperationID] = p
	return nil
}
func (c *Client) Roles() device.Roles {
	return device.Roles{Entitlement: c, Platform: c, Transport: c, Application: c, Withdrawal: c, Clock: c.clock}
}
func (c *Client) interval(ctx context.Context) (time.Time, time.Time, error) {
	a, e := c.clock.Assess(ctx, time.Time{})
	if e != nil {
		return time.Time{}, time.Time{}, e
	}
	return a.Interval(time.Now(), time.Time{})
}
func contains(pins []string, want string) bool {
	for _, p := range pins {
		if p == want {
			return true
		}
	}
	return false
}

func matchesDecision(path, status string, evidence device.Evidence) bool {
	var role, success string
	switch path {
	case "/entitlement":
		role, success = "entitlement", "authorized"
	case "/issue", "/lookup", "/import":
		role, success = "authority", "issued"
	case "/register", "/registration":
		role, success = "platform", "registered"
	case "/activate", "/activation-status":
		role, success = "application", "activated"
	case "/withdraw", "/withdrawal-status":
		role, success = "withdrawal", "withdrawn"
	case "/revoke", "/revocation-status":
		role, success = "authority", "revoked"
	case "/challenge":
		role, success = "transport", "completed"
	default:
		return false
	}
	if evidence.Role != role {
		return false
	}
	// The real transport reports accepted access inside its generic ok envelope.
	if path == "/challenge" && status == "ok" {
		return evidence.Status == "accepted"
	}
	if path == "/activate" && status == "ok" && evidence.Status == "completed" {
		return true
	}
	if evidence.Status != status {
		return false
	}
	switch status {
	case "not-started":
		switch path {
		case "/lookup", "/registration", "/activation-status", "/withdrawal-status", "/revocation-status":
			return true
		}
		return false
	case "ok", "unknown", "denied", "conflict":
		return true
	default:
		return status == success
	}
}

func (c *Client) validateCaller(ctx context.Context, k *device.Credential, historical bool) error {
	if k == nil || credentials.ValidateCredential(*k) != nil {
		return device.ErrDenied
	}
	early, late, e := c.interval(ctx)
	if e != nil {
		return e
	}
	if k.Recovery {
		if k.DeviceID != c.snapshot.DeviceID || device.Hash(k.TLS.Certificate[0]) != c.snapshot.RecoveryLeafPin {
			return device.ErrDenied
		}
		roots, e := c.snapshot.Roots("recovery")
		if e != nil {
			return e
		}
		role, _ := c.snapshot.Role("recovery")
		intermediates := x509.NewCertPool()
		for _, der := range k.TLS.Certificate[1:] {
			cert, parseErr := x509.ParseCertificate(der)
			if parseErr != nil {
				return device.ErrDenied
			}
			intermediates.AddCert(cert)
		}
		leaf, parseErr := x509.ParseCertificate(k.TLS.Certificate[0])
		if parseErr != nil {
			return device.ErrDenied
		}
		paths, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: early, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		if credentials.ValidateRecovery(*k, roots, early) != nil || credentials.ValidateRecovery(*k, roots, late) != nil || verifyErr != nil || role.ValidateVerifiedInterval(paths, early, late) != nil {
			return device.ErrDenied
		}
		return nil
	}
	b := k.Handle.Binding
	if c.snapshot.ValidateBinding(b) != nil {
		return device.ErrConflict
	}
	certs := make([]*x509.Certificate, 0, len(k.TLS.Certificate))
	for _, der := range k.TLS.Certificate {
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return device.ErrDenied
		}
		certs = append(certs, cert)
	}
	if historical {
		early = certs[0].NotBefore
		late = early
	}
	v, e := c.snapshot.Validation(early, late, false, historical)
	if e != nil {
		return e
	}
	if c.snapshot.Profile.ValidatePublicChain(certs, b.DeviceID, b.Generation, v) != nil {
		return device.ErrDenied
	}
	return nil
}
func (c *Client) post(ctx context.Context, role, path string, k *device.Credential, input device.RoleRequest, historical bool) (device.RoleResponse, error) {
	if input.Plan.APIVersion != device.V2 || c.snapshot.ValidatePlan(input.Plan) != nil {
		return device.RoleResponse{}, device.ErrConflict
	}
	if e := c.validateCaller(ctx, k, historical); e != nil {
		return device.RoleResponse{}, e
	}
	_, late, e := c.interval(ctx)
	if e != nil {
		return device.RoleResponse{}, e
	}
	if !late.Before(input.Plan.ExpiresAt) {
		return device.RoleResponse{}, device.ErrPlanExpired
	}
	r, e := c.snapshot.Role(role)
	if e != nil {
		return device.RoleResponse{}, e
	}
	roots, e := c.snapshot.Roots(role)
	if e != nil {
		return device.RoleResponse{}, e
	}
	requestID, e := device.RandomID()
	if e != nil {
		return device.RoleResponse{}, e
	}
	input.RequestID = requestID
	data, e := json.Marshal(input)
	if e != nil || len(data) > device.MaxInput {
		return device.RoleResponse{}, device.ErrDenied
	}
	config := &tls.Config{RootCAs: roots, ServerName: r.PeerName, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{k.TLS}, SessionTicketsDisabled: true}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		early, late, e := c.interval(ctx)
		if e != nil {
			return e
		}
		if !late.Before(input.Plan.ExpiresAt) {
			return device.ErrPlanExpired
		}
		if e = c.validateCaller(ctx, k, historical); e != nil {
			return e
		}
		if len(state.PeerCertificates) == 0 {
			return device.ErrDenied
		}
		leaf := state.PeerCertificates[0]
		if len(r.LeafPins) > 0 && !contains(r.LeafPins, device.Hash(leaf.Raw)) || len(r.SPKIPins) > 0 && !contains(r.SPKIPins, device.Hash(leaf.RawSubjectPublicKeyInfo)) {
			return device.ErrDenied
		}
		intermediates := x509.NewCertPool()
		for _, crt := range state.PeerCertificates[1:] {
			intermediates.AddCert(crt)
		}
		paths, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: r.PeerName, CurrentTime: early, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if e != nil || r.ValidateVerifiedInterval(paths, early, late) != nil {
			return device.ErrDenied
		}
		return nil
	}
	timeout := time.Duration(c.snapshot.RequestTimeoutSeconds) * time.Second
	dial := c.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	transport := &http.Transport{TLSClientConfig: config, DialContext: dial, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 16 << 10, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint, e := url.Parse(r.Endpoint)
	if e != nil {
		return device.RoleResponse{}, device.ErrDenied
	}
	endpoint.Path = path
	ctx, cancel := context.WithDeadline(ctx, input.Plan.ExpiresAt)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(data))
	if e != nil {
		return device.RoleResponse{}, device.ErrDenied
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, e := client.Do(req)
	if e != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	defer response.Body.Close()
	content, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if e != nil || content != "application/json" {
		return device.RoleResponse{}, device.ErrUnknown
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, device.MaxInput+1))
	if e != nil || len(body) > device.MaxInput {
		return device.RoleResponse{}, device.ErrUnknown
	}
	var result device.RoleResponse
	if e = device.DecodeStrict(bytes.NewReader(body), &result); e != nil {
		return result, device.ErrUnknown
	}
	_, late, e = c.interval(ctx)
	if e != nil {
		return result, e
	}
	if !late.Before(input.Plan.ExpiresAt) {
		return result, device.ErrPlanExpired
	}
	if response.TLS == nil || config.VerifyConnection(*response.TLS) != nil {
		return result, device.ErrUnknown
	}
	if result.Evidence != nil {
		v := result.Evidence
		if v.APIVersion != device.V2 || v.Plan != input.Plan || v.RequestID != requestID || v.Action != path[1:] || !matchesDecision(path, result.Status, *v) || v.Revision == 0 || v.Reference == "" || (!contains(r.LeafPins, v.Source) && !contains(r.SPKIPins, v.Source)) || v.ObservedAt.After(late) || !late.Before(v.Deadline) {
			return result, device.ErrUnknown
		}
	}
	// Generic errors never establish effect absence or credential withdrawal.
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return result, device.ErrUnknown
	}
	switch result.Status {
	case "not-started":
		if result.Evidence == nil {
			return result, device.ErrUnknown
		}
		return result, device.ErrNotFound
	case "unknown":
		return result, device.ErrUnknown
	case "conflict":
		if result.Evidence == nil {
			return result, device.ErrUnknown
		}
		return result, device.ErrConflict
	case "denied":
		if result.Evidence == nil {
			return result, device.ErrUnknown
		}
		return result, device.ErrDenied
	case "ok", "completed", "issued", "registered", "activated", "withdrawn", "revoked", "authorized":
		if result.Evidence == nil {
			return result, device.ErrUnknown
		}
		return result, nil
	default:
		return result, device.ErrUnknown
	}
}
func (c *Client) call(ctx context.Context, path string, p device.Plan, k *device.Credential) (device.RoleResponse, error) {
	if e := c.SetPlan(p); e != nil {
		return device.RoleResponse{}, e
	}
	return c.post(ctx, "control", path, k, device.RoleRequest{Plan: p}, false)
}
func (c *Client) Authorize(ctx context.Context, p device.Plan, k *device.Credential) error {
	r, e := c.call(ctx, "/entitlement", p, k)
	if e == nil && r.Evidence == nil {
		return device.ErrUnknown
	}
	return e
}
func (c *Client) issue(ctx context.Context, path string, r device.IssueRequest) ([]byte, error) {
	if e := c.SetPlan(r.Plan); e != nil {
		return nil, e
	}
	if len(r.CSR) > credentialprofile.MaxCSRSize {
		return nil, device.ErrDenied
	}
	csr, e := c.snapshot.Profile.ValidateCSR(r.CSR, r.Plan.DeviceID, r.Plan.TargetGeneration)
	if e != nil {
		return nil, device.ErrDenied
	}
	result, e := c.post(ctx, "control", path, r.Credential, device.RoleRequest{Plan: r.Plan, CSR: r.CSR}, false)
	if e != nil {
		return nil, e
	}
	if e = c.validateIssuanceResult(ctx, r, csr, result); e != nil {
		return nil, e
	}
	return result.Certificate, nil
}

func (c *Client) validateIssuanceResult(ctx context.Context, r device.IssueRequest, csr *x509.CertificateRequest, result device.RoleResponse) error {
	if result.Evidence == nil {
		return device.ErrUnknown
	}
	early, late, e := c.interval(ctx)
	if e != nil {
		return e
	}
	v, e := c.snapshot.Validation(early, late, false, false)
	if e != nil {
		return e
	}
	if e = c.snapshot.Profile.ValidateChain(result.Certificate, r.CSR, device.Hash(csr.RawSubjectPublicKeyInfo), r.Plan.DeviceID, r.Plan.TargetGeneration, v); e != nil {
		return device.ErrUnknown
	}
	certs, err := credentialprofile.ParseChain(result.Certificate)
	if err != nil {
		return device.ErrUnknown
	}
	issuedEarly, issuedLate := result.Evidence.IssuanceEarliest, result.Evidence.IssuanceLatest
	if issuedEarly.IsZero() || issuedLate.Before(issuedEarly) || issuedLate.Sub(issuedEarly) > time.Duration(2*c.snapshot.Limits.MaximumUncertaintyMillis)*time.Millisecond || issuedLate.After(late) || certs[0].NotBefore.Before(issuedEarly.Add(-time.Duration(c.snapshot.Limits.MaxBackdateSeconds)*time.Second)) {
		return device.ErrUnknown
	}
	b := result.Evidence.Subject
	if b.DeploymentID != r.Plan.DeploymentID || b.DeviceID != r.Plan.DeviceID || b.OperationID != r.Plan.OperationID || b.PlanDigest != r.Plan.Digest || b.ConfigDigest != r.Plan.ConfigDigest || b.SnapshotDigest != r.Plan.SnapshotDigest || b.ProfileID != r.Plan.ProfileID || b.ProfileVersion != r.Plan.ProfileVersion || b.ProfileDigest != r.Plan.ProfileDigest || b.Generation != r.Plan.TargetGeneration || b.CSRDigest != device.Hash(csr.Raw) || b.PublicKeyDigest != device.Hash(csr.RawSubjectPublicKeyInfo) || b.CertificateFingerprint != device.Hash(certs[0].Raw) {
		return device.ErrUnknown
	}
	return nil
}
func (c *Client) Issue(ctx context.Context, r device.IssueRequest) ([]byte, error) {
	return c.issue(ctx, "/issue", r)
}
func (c *Client) Lookup(ctx context.Context, r device.IssueRequest) ([]byte, error) {
	return c.issue(ctx, "/lookup", r)
}
func (c *Client) Import(ctx context.Context, r device.IssueRequest, chain []byte) error {
	if e := c.SetPlan(r.Plan); e != nil {
		return e
	}
	csr, e := c.snapshot.Profile.ValidateCSR(r.CSR, r.Plan.DeviceID, r.Plan.TargetGeneration)
	if e != nil {
		return device.ErrDenied
	}
	early, late, e := c.interval(ctx)
	if e != nil {
		return e
	}
	v, e := c.snapshot.Validation(early, late, false, false)
	if e != nil {
		return e
	}
	if e = c.snapshot.Profile.ValidateChain(chain, r.CSR, device.Hash(csr.RawSubjectPublicKeyInfo), r.Plan.DeviceID, r.Plan.TargetGeneration, v); e != nil {
		return device.ErrDenied
	}
	result, e := c.post(ctx, "control", "/import", r.Credential, device.RoleRequest{Plan: r.Plan, CSR: r.CSR, Certificate: chain}, false)
	if e != nil {
		return e
	}
	if !bytes.Equal(result.Certificate, chain) {
		return device.ErrUnknown
	}
	return c.validateIssuanceResult(ctx, r, csr, result)
}
func (c *Client) register(ctx context.Context, path string, p device.Plan, k device.Credential) error {
	if e := c.SetPlan(p); e != nil {
		return e
	}
	if k.Recovery || k.Handle.Binding != p.Binding() {
		return device.ErrDenied
	}
	chain, e := credentials.PublicChain(k)
	if e != nil {
		return device.ErrDenied
	}
	r, e := c.post(ctx, "control", path, &k, device.RoleRequest{Plan: p, Certificate: chain}, false)
	if e == nil && r.Evidence == nil {
		return device.ErrUnknown
	}
	return e
}
func (c *Client) Register(ctx context.Context, p device.Plan, k device.Credential) error {
	return c.register(ctx, "/register", p, k)
}
func (c *Client) Registration(ctx context.Context, p device.Plan, k device.Credential) error {
	return c.register(ctx, "/registration", p, k)
}
func (c *Client) Probe(ctx context.Context, p device.Probe, k device.Credential) (device.Probe, error) {
	c.mu.Lock()
	plan, ok := c.plans[p.OperationID]
	c.mu.Unlock()
	if !ok {
		return device.Probe{}, device.ErrConflict
	}
	r, e := c.post(ctx, "transport", "/challenge", &k, device.RoleRequest{Plan: plan, Probe: p}, false)
	if e != nil {
		return device.Probe{}, e
	}
	_, late, e := c.interval(ctx)
	if e != nil {
		return device.Probe{}, e
	}
	if r.Evidence == nil || r.Evidence.Role != "transport" || r.Evidence.Subject.PublicKeyDigest != k.Handle.PublicKeyDigest || r.Evidence.Subject.CertificateFingerprint != device.Hash(k.TLS.Certificate[0]) || r.Evidence.Subject.Generation != k.Handle.Binding.Generation || r.Evidence.Reference == "" || r.Evidence.Deadline != p.Deadline || !late.Before(p.Deadline) {
		return device.Probe{}, device.ErrDenied
	}
	return p, device.MatchProbe(p, p, late)
}
func (c *Client) activation(ctx context.Context, path string, p device.Plan, k device.Credential) (device.Activation, error) {
	if e := c.SetPlan(p); e != nil {
		return device.Activation{}, e
	}
	if k.Recovery || k.Handle.Binding != p.Binding() {
		return device.Activation{}, device.ErrDenied
	}
	r, e := c.post(ctx, "control", path, &k, device.RoleRequest{Plan: p}, false)
	if e != nil {
		return device.Activation{}, e
	}
	if r.Application == nil {
		return device.Activation{}, device.ErrUnknown
	}
	a := r.Application
	role, e := c.snapshot.Role("application")
	if e != nil {
		return device.Activation{}, e
	}
	if !contains(role.LeafPins, a.Evidence.Source) || a.Evidence.Role != "application" || a.Evidence.Plan != p || a.Phase != "activated" || a.ActivationRevision == 0 {
		return device.Activation{}, device.ErrDenied
	}
	activation := device.Activation{OperationID: p.OperationID, PlanDigest: p.Digest, DeviceID: p.DeviceID, ApplicationID: a.ApplicationID, Generation: a.Active.Generation, CertificateFingerprint: a.Active.CertificateFingerprint, SessionID: a.SessionID, Probe: a.Challenge, Evidence: a}
	if err := process.ValidateActivation(c.snapshot, p, k, activation); err != nil {
		return device.Activation{}, err
	}
	return activation, nil
}
func (c *Client) Activate(ctx context.Context, p device.Plan, k device.Credential) (device.Activation, error) {
	if e := c.SetPlan(p); e != nil {
		return device.Activation{}, e
	}
	chain, e := credentials.PublicChain(k)
	if e != nil {
		return device.Activation{}, device.ErrDenied
	}
	if _, e = c.post(ctx, "application", "/activate", &k, device.RoleRequest{Plan: p, Certificate: chain}, false); e != nil {
		return device.Activation{}, e
	}
	return c.activation(ctx, "/activate", p, k)
}
func (c *Client) ActivationStatus(ctx context.Context, p device.Plan, k device.Credential) (device.Activation, error) {
	return c.activation(ctx, "/activation-status", p, k)
}
func (c *Client) withdrawal(ctx context.Context, path string, p device.Plan, previous, target device.Credential) (device.Retirement, error) {
	if e := c.SetPlan(p); e != nil {
		return device.Retirement{}, e
	}
	oldChain, e := credentials.PublicChain(previous)
	if e != nil {
		return device.Retirement{}, device.ErrDenied
	}
	r, e := c.post(ctx, "control", path, &target, device.RoleRequest{Plan: p, Previous: oldChain}, false)
	if e != nil {
		return device.Retirement{}, e
	}
	if r.Withdrawal == nil {
		return device.Retirement{}, device.ErrUnknown
	}
	// An actual old-key connection supplies denial; a public chain cannot do so.
	nonce, e := device.RandomID()
	if e != nil {
		return device.Retirement{}, e
	}
	probe := device.Probe{OperationID: p.OperationID, DeviceID: p.DeviceID, Generation: previous.Handle.Binding.Generation, Endpoint: c.snapshotEndpoint("transport"), Nonce: nonce, Deadline: time.Now().UTC().Add(10 * time.Second)}
	if probe.Deadline.After(p.ExpiresAt) {
		probe.Deadline = p.ExpiresAt
	}
	denied, denialErr := c.post(ctx, "transport", "/challenge", &previous, device.RoleRequest{Plan: p, Probe: probe}, true)
	if !errors.Is(denialErr, device.ErrDenied) || denied.Evidence == nil || denied.Evidence.Role != "transport" || denied.Evidence.Subject.CertificateFingerprint != device.Hash(previous.TLS.Certificate[0]) || denied.Evidence.Subject.PublicKeyDigest != previous.Handle.PublicKeyDigest {
		return device.Retirement{}, device.ErrUnknown
	}
	r, e = c.post(ctx, "control", "/withdrawal-status", &target, device.RoleRequest{Plan: p, Previous: oldChain}, false)
	if e != nil {
		return device.Retirement{}, e
	}
	w := r.Withdrawal
	if w == nil || !w.SessionsTerminated || w.PolicyRevision == 0 || w.Denial.Kind != "denied" || w.Previous.CertificateFingerprint != device.Hash(previous.TLS.Certificate[0]) || w.Previous.PublicKeyDigest != previous.Handle.PublicKeyDigest || w.Target.CertificateFingerprint != device.Hash(target.TLS.Certificate[0]) || w.Target.PublicKeyDigest != target.Handle.PublicKeyDigest || w.Scope != c.snapshot.Composition.WithdrawalScope {
		return device.Retirement{}, device.ErrUnknown
	}
	retirement := device.Retirement{OperationID: p.OperationID, PlanDigest: p.Digest, Generation: p.ExpectedGeneration, PolicyDurable: true, SessionsTerminated: true, TLSObservation: "accepted", ApplicationAccessDenied: true, Evidence: w}
	if err := process.ValidateRetirement(c.snapshot, p, previous, target, retirement); err != nil {
		return device.Retirement{}, err
	}
	return retirement, nil
}
func (c *Client) snapshotEndpoint(role string) string {
	r, _ := c.snapshot.Role(role)
	return r.Endpoint
}
func (c *Client) Retire(ctx context.Context, p device.Plan, previous, target device.Credential) (device.Retirement, error) {
	return c.withdrawal(ctx, "/withdraw", p, previous, target)
}
func (c *Client) RetirementStatus(ctx context.Context, p device.Plan, previous, target device.Credential) (device.Retirement, error) {
	return c.withdrawal(ctx, "/withdrawal-status", p, previous, target)
}
func (c *Client) revoke(ctx context.Context, path string, p device.Plan, previous, target device.Credential) error {
	if e := c.SetPlan(p); e != nil {
		return e
	}
	b := previous.Handle.Binding
	if c.snapshot.ValidateBinding(b) != nil || b.Generation != p.ExpectedGeneration || len(previous.TLS.Certificate) == 0 {
		return device.ErrConflict
	}
	csr, e := c.snapshot.Profile.ValidateCSR(previous.CSR, b.DeviceID, b.Generation)
	if e != nil || device.Hash(csr.RawSubjectPublicKeyInfo) != previous.Handle.PublicKeyDigest {
		return device.ErrDenied
	}
	expected := device.CredentialBinding{DeploymentID: b.DeploymentID, DeviceID: b.DeviceID, OperationID: b.OperationID, PlanDigest: b.PlanDigest, ConfigDigest: b.ConfigDigest, SnapshotDigest: b.SnapshotDigest, ProfileID: b.ProfileID, ProfileVersion: b.ProfileVersion, ProfileDigest: b.ProfileDigest, Generation: b.Generation, PublicKeyDigest: previous.Handle.PublicKeyDigest, CertificateFingerprint: device.Hash(previous.TLS.Certificate[0]), CSRDigest: device.Hash(csr.Raw)}
	chain, e := credentials.PublicChain(previous)
	if e != nil {
		return device.ErrDenied
	}
	r, e := c.post(ctx, "control", path, &target, device.RoleRequest{Plan: p, Previous: chain}, false)
	if e == nil || errors.Is(e, device.ErrNotFound) {
		if r.Evidence == nil || r.Evidence.Role != "authority" || r.Evidence.Subject != expected || r.Evidence.Status != r.Status || r.Evidence.Deadline != p.ExpiresAt || errors.Is(e, device.ErrNotFound) && r.Status != "not-started" || e == nil && r.Status != "ok" && r.Status != "revoked" {
			return device.ErrUnknown
		}
	}
	return e
}
func (c *Client) Revoke(ctx context.Context, p device.Plan, previous, target device.Credential) error {
	return c.revoke(ctx, "/revoke", p, previous, target)
}
func (c *Client) RevocationStatus(ctx context.Context, p device.Plan, previous, target device.Credential) error {
	return c.revoke(ctx, "/revocation-status", p, previous, target)
}

var _ device.Authority = (*Client)(nil)
var _ device.Platform = (*Client)(nil)
