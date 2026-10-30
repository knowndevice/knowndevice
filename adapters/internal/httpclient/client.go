// SPDX-License-Identifier: Apache-2.0

// Package httpclient owns the TLS and resource limits of the reference clients.
package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/knowndevice/knowndevice/adapters/credentials"
	"github.com/knowndevice/knowndevice/adapters/internal/strictjson"
	"github.com/knowndevice/knowndevice/sdk/device"
)

const MaxBody = 256 << 10

type Options struct {
	URL         string
	Roots       *x509.CertPool
	Timeout     time.Duration
	DialContext func(context.Context, string, string) (net.Conn, error)
}

type Client struct {
	base    *url.URL
	roots   *x509.CertPool
	timeout time.Duration
	dial    func(context.Context, string, string) (net.Conn, error)
}

func New(options Options) (*Client, error) {
	base, err := url.Parse(options.URL)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") || base.RawPath != "" {
		return nil, fmt.Errorf("an HTTPS origin without credentials, path, query or fragment is required")
	}
	if options.Roots == nil || len(options.Roots.Subjects()) == 0 {
		return nil, fmt.Errorf("explicit HTTPS trust roots are required")
	}
	if options.Timeout <= 0 || options.Timeout > time.Minute {
		return nil, fmt.Errorf("HTTPS timeout must be positive and at most one minute")
	}
	dial := options.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: options.Timeout}).DialContext
	}
	base.Path = ""
	return &Client{base: base, roots: options.Roots.Clone(), timeout: options.Timeout, dial: dial}, nil
}

// Post never retries, follows redirects, consults a proxy, or reports remote text.
func (c *Client) Post(ctx context.Context, path string, credential *device.Credential, input, output any) error {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
		return fmt.Errorf("invalid reference endpoint")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(input)
	if err != nil || len(data) > MaxBody {
		return fmt.Errorf("invalid or oversized reference request")
	}
	tlsConfig := &tls.Config{RootCAs: c.roots, MinVersion: tls.VersionTLS12}
	if credential != nil {
		if err := credentials.ValidateCredential(*credential); err != nil {
			return err
		}
		if credential.Recovery {
			if err := credentials.ValidateRecovery(*credential, c.roots, time.Now()); err != nil {
				return err
			}
		}
		tlsConfig.Certificates = []tls.Certificate{credential.TLS}
	}
	transport := &http.Transport{DialContext: c.dial, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: c.timeout, ResponseHeaderTimeout: c.timeout, MaxResponseHeaderBytes: 16 << 10, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: c.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint := *c.base
	endpoint.Path = path
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("invalid reference request")
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("HTTPS response unavailable: %w", device.ErrUnknown)
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("reference request denied: %w", device.ErrDenied)
	case http.StatusConflict:
		return fmt.Errorf("reference precondition conflict: %w", device.ErrConflict)
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return fmt.Errorf("reference endpoint unavailable: %w", device.ErrUnsupported)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTPS result not established: %w", device.ErrUnknown)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("invalid HTTPS response type: %w", device.ErrUnknown)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		return fmt.Errorf("HTTPS response incomplete or oversized: %w", device.ErrUnknown)
	}
	if err := strictjson.Decode(body, output); err != nil {
		return fmt.Errorf("invalid HTTPS response: %w", device.ErrUnknown)
	}
	return nil
}
