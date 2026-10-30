// SPDX-License-Identifier: Apache-2.0

// Package stepca implements the step-ca v0.29.0 sign and passive revoke API.
package stepca

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/knowndevice/knowndevice/adapters/credentials"
	"github.com/knowndevice/knowndevice/adapters/internal/httpclient"
	"github.com/knowndevice/knowndevice/sdk/device"
)

type TokenRequest struct {
	Purpose string
	Plan    device.Plan
	CSR     []byte
	Serial  string
}

// TokenProvider runs in the reference control service. Tokens never enter the
// device journal or result; the service must authorize the exact plan first.
type TokenProvider func(context.Context, TokenRequest) (string, error)

type Options struct {
	URL           string
	Roots         *x509.CertPool
	Timeout       time.Duration
	TokenProvider TokenProvider
	Now           func() time.Time
	dialContext   func(context.Context, string, string) (net.Conn, error)
}

type Client struct {
	http  *httpclient.Client
	roots *x509.CertPool
	token TokenProvider
	now   func() time.Time
}

var _ device.Authority = (*Client)(nil)

func New(options Options) (*Client, error) {
	if options.TokenProvider == nil {
		return nil, fmt.Errorf("a scoped in-memory CA token provider is required")
	}
	client, err := httpclient.New(httpclient.Options{URL: options.URL, Roots: options.Roots, Timeout: options.Timeout, DialContext: options.dialContext})
	if err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Client{http: client, roots: options.Roots.Clone(), token: options.TokenProvider, now: options.Now}, nil
}

type signRequest struct {
	CSR string `json:"csr"`
	OTT string `json:"ott"`
}

type signResponse struct {
	Certificate string          `json:"crt"`
	CA          string          `json:"ca"`
	Chain       []string        `json:"certChain"`
	TLSOptions  json.RawMessage `json:"tlsOptions,omitempty"`
}

func tokenFailure(err error) error {
	for _, sentinel := range []error{device.ErrDenied, device.ErrConflict, device.ErrUnsupported} {
		if errors.Is(err, sentinel) {
			return fmt.Errorf("CA token provider refused the scope: %w", sentinel)
		}
	}
	return fmt.Errorf("CA token provider result unavailable: %w", device.ErrUnknown)
}

func (c *Client) Issue(ctx context.Context, request device.IssueRequest) ([]byte, error) {
	if err := request.Plan.Validate(c.now()); err != nil {
		return nil, err
	}
	subject := device.Subject(request.Plan.DeviceID, request.Plan.TargetGeneration)
	if _, err := credentials.ValidateCSR(request.CSR, subject); err != nil {
		return nil, err
	}
	if request.Credential != nil {
		credential := *request.Credential
		if err := credentials.ValidateCredential(credential); err != nil {
			return nil, err
		}
		if credential.Recovery {
			if credential.DeviceID != request.Plan.DeviceID || (request.Plan.Mode != "enroll" && request.Plan.Mode != "recover") {
				return nil, fmt.Errorf("recovery credential issuance scope mismatch: %w", device.ErrDenied)
			}
		} else if credential.Handle.Binding.DeviceID != request.Plan.DeviceID || credential.Handle.Binding.Generation != request.Plan.ExpectedGeneration {
			return nil, fmt.Errorf("operational credential issuance scope mismatch: %w", device.ErrDenied)
		}
	}
	ctx, cancel := context.WithDeadline(ctx, request.Plan.ExpiresAt)
	defer cancel()
	token, err := c.token(ctx, TokenRequest{Purpose: "sign", Plan: request.Plan, CSR: append([]byte(nil), request.CSR...)})
	if err != nil {
		return nil, tokenFailure(err)
	}
	if token == "" || len(token) > 16<<10 {
		return nil, fmt.Errorf("CA token provider returned invalid material: %w", device.ErrDenied)
	}
	var response signResponse
	if err := c.http.Post(ctx, "/sign", request.Credential, signRequest{CSR: string(request.CSR), OTT: token}, &response); err != nil {
		return nil, fmt.Errorf("CA issuance outcome not established: %w", device.ErrUnknown)
	}
	var chain []byte
	if len(response.Chain) > 0 {
		if len(response.Chain) > 8 || response.Certificate != response.Chain[0] || (response.CA != "" && (len(response.Chain) < 2 || response.CA != response.Chain[1])) {
			return nil, fmt.Errorf("CA response chain inconsistent: %w", device.ErrUnknown)
		}
		for _, certificate := range response.Chain {
			chain = append(chain, []byte(certificate)...)
		}
	} else {
		chain = []byte(response.Certificate + response.CA)
	}
	if err := credentials.ValidateCertificate(chain, request.CSR, subject, c.roots, c.now()); err != nil {
		return nil, fmt.Errorf("CA result failed certificate validation: %w", device.ErrUnknown)
	}
	return chain, nil
}

// Lookup cannot establish an issuance outcome: step-ca exposes no operation-ID
// lookup. Repeating /sign with another token could issue a second certificate.
func (*Client) Lookup(context.Context, device.IssueRequest) ([]byte, error) {
	return nil, device.ErrUnknown
}

func (c *Client) Revoke(ctx context.Context, plan device.Plan, credential, current device.Credential) error {
	if err := plan.Validate(c.now()); err != nil {
		return err
	}
	if err := credentials.ValidateCredential(credential); err != nil {
		return err
	}
	if credential.Recovery || credential.Handle.Binding.DeviceID != plan.DeviceID || credential.Handle.Binding.Generation != plan.ExpectedGeneration {
		return fmt.Errorf("revocation credential does not match the previous generation: %w", device.ErrDenied)
	}
	if current.Recovery || current.Handle.Binding != plan.Binding() {
		return fmt.Errorf("current revocation authorization does not bind the target: %w", device.ErrDenied)
	}
	if err := credentials.ValidateCredential(current); err != nil {
		return err
	}
	certificate, err := x509.ParseCertificate(credential.TLS.Certificate[0])
	if err != nil || certificate.Subject.CommonName != device.Subject(plan.DeviceID, plan.ExpectedGeneration) {
		return fmt.Errorf("revocation certificate identity mismatch: %w", device.ErrDenied)
	}
	return c.revoke(ctx, plan, certificate, &current)
}

// RevokeCertificate is for the authorized control service, which has only public
// device material. A scoped provisioner token authorizes revocation. The service
// must bind this artifact to its exact reservation and authenticated caller first.
func (c *Client) RevokeCertificate(ctx context.Context, plan device.Plan, chain []byte) error {
	if err := plan.Validate(c.now()); err != nil {
		return err
	}
	certificates, err := credentials.ParseCertificateChain(chain)
	if err != nil {
		return err
	}
	certificate := certificates[0]
	subject := device.Subject(plan.DeviceID, plan.ExpectedGeneration)
	if plan.ExpectedGeneration == 0 || credentials.ValidateIdentity(certificate, subject) != nil {
		return fmt.Errorf("revocation certificate identity mismatch: %w", device.ErrDenied)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	// Expired generations can be revoked. Historical chain validation establishes
	// the issued artifact only; it does not make it usable for TLS or recovery.
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: c.roots, Intermediates: intermediates, DNSName: subject, CurrentTime: certificate.NotBefore, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("revocation certificate trust binding failed: %w", device.ErrDenied)
	}
	return c.revoke(ctx, plan, certificate, nil)
}

func (c *Client) revoke(ctx context.Context, plan device.Plan, certificate *x509.Certificate, credential *device.Credential) error {
	ctx, cancel := context.WithDeadline(ctx, plan.ExpiresAt)
	defer cancel()
	token, err := c.token(ctx, TokenRequest{Purpose: "revoke", Plan: plan, Serial: certificate.SerialNumber.String()})
	if err != nil {
		return tokenFailure(err)
	}
	if token == "" || len(token) > 16<<10 {
		return fmt.Errorf("CA token provider returned invalid material: %w", device.ErrDenied)
	}
	request := struct {
		Serial     string `json:"serial"`
		OTT        string `json:"ott"`
		ReasonCode int    `json:"reasonCode"`
		Reason     string `json:"reason"`
		Passive    bool   `json:"passive"`
	}{Serial: certificate.SerialNumber.String(), OTT: token, ReasonCode: 4, Reason: "credential generation superseded", Passive: true}
	var response struct {
		Status string `json:"status"`
	}
	if err := c.http.Post(ctx, "/revoke", credential, request, &response); err != nil {
		return fmt.Errorf("CA revocation outcome not established: %w", device.ErrUnknown)
	}
	if response.Status != "ok" {
		return fmt.Errorf("CA revocation not established: %w", device.ErrUnknown)
	}
	return nil
}

func (*Client) RevocationStatus(context.Context, device.Plan, device.Credential, device.Credential) error {
	return device.ErrUnknown
}

func ValidateCertificate(chain, csr []byte, subject string, roots *x509.CertPool, now time.Time) error {
	return credentials.ValidateCertificate(chain, csr, subject, roots, now)
}
