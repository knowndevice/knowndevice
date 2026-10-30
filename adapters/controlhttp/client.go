// SPDX-License-Identifier: Apache-2.0

// Package controlhttp implements the alpha reference control and application API.
package controlhttp

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"knowndevice.local/knowndevice/adapters/credentials"
	"knowndevice.local/knowndevice/adapters/internal/httpclient"
	"knowndevice.local/knowndevice/adapters/mqttprobe"
	"knowndevice.local/knowndevice/sdk/device"
)

type ProbeTransport interface {
	Probe(context.Context, device.Probe, device.Credential) (device.Probe, error)
}

type DenialObserver interface {
	ObserveDenial(context.Context, device.Credential) (mqttprobe.Observation, error)
}

type Options struct {
	ControlURL       string
	ApplicationURL   string
	ControlRoots     *x509.CertPool
	ApplicationRoots *x509.CertPool
	CertificateRoots *x509.CertPool
	ApplicationID    string
	ProbeEndpoint    string
	Timeout          time.Duration
	ProbeTransport   ProbeTransport
	DenialObserver   DenialObserver
	Now              func() time.Time
	dialContext      func(context.Context, string, string) (net.Conn, error)
}

// Request carries the complete approved plan even for status reconciliation.
// Certificate and CSR are public PEM bytes encoded as JSON base64 strings.
type Request struct {
	Plan        device.Plan        `json:"plan"`
	CSR         []byte             `json:"csr,omitempty"`
	Certificate []byte             `json:"certificate,omitempty"`
	Handle      *device.Handle     `json:"handle,omitempty"`
	Activation  *device.Activation `json:"activation,omitempty"`
}

type Response struct {
	OperationID string             `json:"operationId"`
	PlanDigest  string             `json:"planDigest"`
	DeviceID    string             `json:"deviceId"`
	Generation  uint64             `json:"generation"`
	Status      string             `json:"status"`
	Certificate []byte             `json:"certificate,omitempty"`
	Activation  *device.Activation `json:"activation,omitempty"`
	Retirement  *device.Retirement `json:"retirement,omitempty"`
}

type Client struct {
	control       *httpclient.Client
	application   *httpclient.Client
	roots         *x509.CertPool
	applicationID string
	probeEndpoint string
	probe         ProbeTransport
	denial        DenialObserver
	now           func() time.Time
	mu            sync.Mutex
	seen          map[string]time.Time
}

var _ device.Authority = (*Client)(nil)
var _ device.Platform = (*Client)(nil)

func New(options Options) (*Client, error) {
	if !device.ValidDeviceID(options.ApplicationID) || options.ProbeEndpoint == "" {
		return nil, fmt.Errorf("application identity and probe endpoint are required")
	}
	control, err := httpclient.New(httpclient.Options{URL: options.ControlURL, Roots: options.ControlRoots, Timeout: options.Timeout, DialContext: options.dialContext})
	if err != nil {
		return nil, err
	}
	application, err := httpclient.New(httpclient.Options{URL: options.ApplicationURL, Roots: options.ApplicationRoots, Timeout: options.Timeout, DialContext: options.dialContext})
	if err != nil {
		return nil, err
	}
	if options.CertificateRoots == nil {
		options.CertificateRoots = options.ControlRoots
	}
	if len(options.CertificateRoots.Subjects()) == 0 {
		return nil, fmt.Errorf("certificate issuance trust roots are required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.DenialObserver == nil {
		options.DenialObserver, _ = options.ProbeTransport.(DenialObserver)
	}
	return &Client{control: control, application: application, roots: options.CertificateRoots.Clone(), applicationID: options.ApplicationID, probeEndpoint: options.ProbeEndpoint, probe: options.ProbeTransport, denial: options.DenialObserver, now: options.Now, seen: make(map[string]time.Time)}, nil
}

func (c *Client) call(ctx context.Context, application bool, path string, request Request, credential *device.Credential, generation uint64, mutation bool) (Response, error) {
	now := c.now()
	if mutation {
		if err := request.Plan.Validate(now); err != nil {
			return Response{}, err
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, request.Plan.ExpiresAt)
		defer cancel()
	} else if err := request.Plan.Validate(request.Plan.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		return Response{}, err
	}
	if credential == nil {
		return Response{}, fmt.Errorf("control operations require a scoped mTLS credential: %w", device.ErrDenied)
	}
	credentialDevice := credential.Handle.Binding.DeviceID
	if credential.Recovery {
		credentialDevice = credential.DeviceID
		if application || (request.Plan.Mode != "enroll" && request.Plan.Mode != "recover") || (path != "/v1/authorize" && path != "/v1/issue" && path != "/v1/issue/status" && path != "/v1/issue/import") {
			return Response{}, fmt.Errorf("recovery credential has no operational control scope: %w", device.ErrDenied)
		}
	}
	if credentialDevice != request.Plan.DeviceID {
		return Response{}, fmt.Errorf("control credential device mismatch: %w", device.ErrDenied)
	}
	client := c.control
	if application {
		client = c.application
	}
	var response Response
	if err := client.Post(ctx, path, credential, request, &response); err != nil {
		return Response{}, err
	}
	if response.OperationID != request.Plan.OperationID || response.PlanDigest != request.Plan.Digest || response.DeviceID != request.Plan.DeviceID || response.Generation != generation {
		return Response{}, fmt.Errorf("control response does not bind the approved plan: %w", device.ErrUnknown)
	}
	switch response.Status {
	case "ok":
		return response, nil
	case "unknown":
		return Response{}, device.ErrUnknown
	case "denied":
		return Response{}, device.ErrDenied
	case "unsupported":
		return Response{}, device.ErrUnsupported
	case "conflict":
		return Response{}, device.ErrConflict
	case "not-found":
		if mutation {
			return Response{}, fmt.Errorf("mutation response cannot establish absence: %w", device.ErrUnknown)
		}
		return Response{}, device.ErrNotFound
	default:
		return Response{}, fmt.Errorf("unrecognized control result: %w", device.ErrUnknown)
	}
}

func targetRequest(plan device.Plan, credential device.Credential) (Request, error) {
	if credential.Recovery || credential.Handle.Binding != plan.Binding() {
		return Request{}, fmt.Errorf("target credential does not bind the approved plan: %w", device.ErrDenied)
	}
	chain, err := credentials.PublicChain(credential)
	if err != nil {
		return Request{}, err
	}
	return Request{Plan: plan, Certificate: chain, Handle: &credential.Handle}, nil
}

func previousRequest(plan device.Plan, credential, current device.Credential) (Request, error) {
	if credential.Recovery || credential.Handle.Binding.DeviceID != plan.DeviceID || credential.Handle.Binding.Generation != plan.ExpectedGeneration || plan.ExpectedGeneration == 0 {
		return Request{}, fmt.Errorf("previous credential does not bind the approved plan: %w", device.ErrDenied)
	}
	if current.Recovery || current.Handle.Binding != plan.Binding() {
		return Request{}, fmt.Errorf("current authorization does not bind the active target: %w", device.ErrDenied)
	}
	if err := credentials.ValidateCredential(current); err != nil {
		return Request{}, err
	}
	chain, err := credentials.PublicChain(credential)
	if err != nil {
		return Request{}, err
	}
	return Request{Plan: plan, Certificate: chain, Handle: &credential.Handle}, nil
}

func (c *Client) Authorize(ctx context.Context, plan device.Plan, credential *device.Credential) error {
	_, err := c.call(ctx, false, "/v1/authorize", Request{Plan: plan}, credential, plan.TargetGeneration, true)
	return err
}

func (c *Client) issue(ctx context.Context, request device.IssueRequest, status bool) ([]byte, error) {
	subject := device.Subject(request.Plan.DeviceID, request.Plan.TargetGeneration)
	if _, err := credentials.ValidateCSR(request.CSR, subject); err != nil {
		return nil, err
	}
	path := "/v1/issue"
	if status {
		path += "/status"
	}
	response, err := c.call(ctx, false, path, Request{Plan: request.Plan, CSR: request.CSR}, request.Credential, request.Plan.TargetGeneration, !status)
	if err != nil {
		return nil, err
	}
	if err := credentials.ValidateCertificate(response.Certificate, request.CSR, subject, c.roots, c.now()); err != nil {
		return nil, fmt.Errorf("control result failed certificate validation: %w", device.ErrUnknown)
	}
	return response.Certificate, nil
}

func (c *Client) Issue(ctx context.Context, request device.IssueRequest) ([]byte, error) {
	return c.issue(ctx, request, false)
}
func (c *Client) Lookup(ctx context.Context, request device.IssueRequest) ([]byte, error) {
	return c.issue(ctx, request, true)
}

// Import reconciles an existing unknown issuance using recovered public material.
// The control service must recheck entitlement and the exact durable reservation;
// this method never asks step-ca to issue another certificate.
func (c *Client) Import(ctx context.Context, request device.IssueRequest, chain []byte) error {
	if err := credentials.ValidateCertificate(chain, request.CSR, device.Subject(request.Plan.DeviceID, request.Plan.TargetGeneration), c.roots, c.now()); err != nil {
		return err
	}
	_, err := c.call(ctx, false, "/v1/issue/import", Request{Plan: request.Plan, CSR: request.CSR, Certificate: chain}, request.Credential, request.Plan.TargetGeneration, true)
	return err
}

func (c *Client) targetStatus(ctx context.Context, path string, plan device.Plan, credential device.Credential, mutation bool) error {
	request, err := targetRequest(plan, credential)
	if err != nil {
		return err
	}
	_, err = c.call(ctx, false, path, request, &credential, plan.TargetGeneration, mutation)
	return err
}

func (c *Client) Register(ctx context.Context, plan device.Plan, credential device.Credential) error {
	return c.targetStatus(ctx, "/v1/register", plan, credential, true)
}
func (c *Client) Registration(ctx context.Context, plan device.Plan, credential device.Credential) error {
	return c.targetStatus(ctx, "/v1/registration", plan, credential, false)
}

func (c *Client) Probe(ctx context.Context, request device.Probe, credential device.Credential) (device.Probe, error) {
	if c.probe == nil {
		return device.Probe{}, device.ErrUnsupported
	}
	if credential.Recovery || request.Endpoint != c.probeEndpoint || request.DeviceID != credential.Handle.Binding.DeviceID || request.Generation != credential.Handle.Binding.Generation || request.OperationID != credential.Handle.Binding.OperationID {
		return device.Probe{}, fmt.Errorf("probe credential or endpoint mismatch: %w", device.ErrDenied)
	}
	if err := device.MatchProbe(request, request, c.now()); err != nil {
		return device.Probe{}, err
	}
	response, err := c.probe.Probe(ctx, request, credential)
	if err != nil {
		return device.Probe{}, err
	}
	if err := device.MatchProbe(request, response, c.now()); err != nil {
		return device.Probe{}, err
	}
	return response, nil
}

func (c *Client) activation(ctx context.Context, plan device.Plan, credential device.Credential, status bool) (device.Activation, error) {
	request, err := targetRequest(plan, credential)
	if err != nil {
		return device.Activation{}, err
	}
	path := "/v1/activate"
	if status {
		path = "/v1/activation"
	}
	response, err := c.call(ctx, true, path, request, &credential, plan.TargetGeneration, !status)
	if err != nil {
		return device.Activation{}, err
	}
	activation := response.Activation
	fingerprint, err := credentials.CertificateFingerprint(request.Certificate)
	if err != nil || activation == nil || activation.OperationID != plan.OperationID || activation.PlanDigest != plan.Digest || activation.DeviceID != plan.DeviceID || activation.ApplicationID != c.applicationID || activation.Generation != plan.TargetGeneration || activation.CertificateFingerprint != fingerprint {
		return device.Activation{}, fmt.Errorf("application acknowledgment binding mismatch: %w", device.ErrUnknown)
	}
	probe := activation.Probe
	if probe.Endpoint != c.probeEndpoint || probe.DeviceID != plan.DeviceID || probe.OperationID != plan.OperationID || probe.Generation != plan.TargetGeneration || device.MatchProbe(probe, probe, c.now()) != nil {
		return device.Activation{}, fmt.Errorf("application acknowledgment lacks a fresh bound probe: %w", device.ErrDenied)
	}
	c.mu.Lock()
	for nonce, deadline := range c.seen {
		if !deadline.After(c.now()) {
			delete(c.seen, nonce)
		}
	}
	if _, exists := c.seen[probe.Nonce]; exists || len(c.seen) >= 1024 {
		c.mu.Unlock()
		return device.Activation{}, fmt.Errorf("application acknowledgment replays a probe: %w", device.ErrDenied)
	}
	c.seen[probe.Nonce] = probe.Deadline
	c.mu.Unlock()
	request.Activation = activation
	controlPath := "/v1/activated"
	if status {
		controlPath = "/v1/activation-status"
	}
	if _, err := c.call(ctx, false, controlPath, request, &credential, plan.TargetGeneration, !status); err != nil {
		return device.Activation{}, err
	}
	return *activation, nil
}

func (c *Client) Activate(ctx context.Context, plan device.Plan, credential device.Credential) (device.Activation, error) {
	return c.activation(ctx, plan, credential, false)
}
func (c *Client) ActivationStatus(ctx context.Context, plan device.Plan, credential device.Credential) (device.Activation, error) {
	return c.activation(ctx, plan, credential, true)
}

func (c *Client) retire(ctx context.Context, plan device.Plan, credential, current device.Credential, status bool) (device.Retirement, error) {
	request, err := previousRequest(plan, credential, current)
	if err != nil {
		return device.Retirement{}, err
	}
	path := "/v1/retire"
	if status {
		path = "/v1/retirement"
	}
	response, err := c.call(ctx, false, path, request, &current, plan.ExpectedGeneration, !status)
	if err != nil {
		return device.Retirement{}, err
	}
	retirement := response.Retirement
	if retirement == nil || retirement.OperationID != plan.OperationID || retirement.PlanDigest != plan.Digest || retirement.Generation != plan.ExpectedGeneration {
		return device.Retirement{}, fmt.Errorf("retirement acknowledgment binding mismatch: %w", device.ErrUnknown)
	}
	if !retirement.PolicyDurable || !retirement.SessionsTerminated {
		return device.Retirement{}, fmt.Errorf("effective broker retirement not established: %w", device.ErrUnknown)
	}
	if c.denial != nil {
		observation, err := c.denial.ObserveDenial(ctx, credential)
		if err != nil || !observation.ApplicationAccessDenied || (observation.TLSObservation != "accepted" && observation.TLSObservation != "denied") {
			return device.Retirement{}, fmt.Errorf("previous access denial not observed: %w", device.ErrUnknown)
		}
		retirement.ApplicationAccessDenied = true
		retirement.TLSObservation = observation.TLSObservation
		return *retirement, nil
	}
	leaf, _ := credentials.ValidateTLSCertificate(credential.TLS)
	if !c.now().Before(leaf.NotAfter) {
		return device.Retirement{}, device.ErrUnsupported
	}
	if c.probe == nil {
		return device.Retirement{}, device.ErrUnsupported
	}
	nonce, err := device.RandomID()
	if err != nil {
		return device.Retirement{}, err
	}
	challenge := device.Probe{DeviceID: plan.DeviceID, OperationID: credential.Handle.Binding.OperationID, Generation: plan.ExpectedGeneration, Endpoint: c.probeEndpoint, Nonce: nonce, Deadline: c.now().UTC().Add(30 * time.Second)}
	_, err = c.probe.Probe(ctx, challenge, credential)
	if !errors.Is(err, device.ErrDenied) || !errors.Is(err, mqttprobe.ErrACL) {
		return device.Retirement{}, fmt.Errorf("previous MQTT access denial not observed: %w", device.ErrUnknown)
	}
	retirement.ApplicationAccessDenied = true
	retirement.TLSObservation = "accepted"
	return *retirement, nil
}

func (c *Client) Retire(ctx context.Context, plan device.Plan, previous, current device.Credential) (device.Retirement, error) {
	return c.retire(ctx, plan, previous, current, false)
}
func (c *Client) RetirementStatus(ctx context.Context, plan device.Plan, previous, current device.Credential) (device.Retirement, error) {
	return c.retire(ctx, plan, previous, current, true)
}

func (c *Client) revoke(ctx context.Context, plan device.Plan, credential, current device.Credential, status bool) error {
	request, err := previousRequest(plan, credential, current)
	if err != nil {
		return err
	}
	path := "/v1/revoke"
	if status {
		path = "/v1/revocation"
	}
	_, err = c.call(ctx, false, path, request, &current, plan.ExpectedGeneration, !status)
	return err
}

func (c *Client) Revoke(ctx context.Context, plan device.Plan, previous, current device.Credential) error {
	return c.revoke(ctx, plan, previous, current, false)
}
func (c *Client) RevocationStatus(ctx context.Context, plan device.Plan, previous, current device.Credential) error {
	return c.revoke(ctx, plan, previous, current, true)
}
