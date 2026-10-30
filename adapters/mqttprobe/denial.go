// SPDX-License-Identifier: Apache-2.0

package mqttprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync/atomic"
	"time"

	"knowndevice.local/knowndevice/adapters/credentials"
	"knowndevice.local/knowndevice/sdk/device"
)

type Observation struct {
	TLSObservation          string
	ApplicationAccessDenied bool
}

// ObserveDenial is a negative diagnostic only. It cannot authorize an old key,
// establish device health, activate a generation or grant recovery permission.
func (c *Client) ObserveDenial(ctx context.Context, previous device.Credential) (Observation, error) {
	if previous.Recovery {
		return Observation{}, fmt.Errorf("recovery is outside retirement scope: %w", device.ErrDenied)
	}
	if err := credentials.ValidateCredential(previous); err != nil {
		return Observation{}, err
	}
	leaf, err := credentials.ValidateTLSCertificate(previous.TLS)
	if err != nil {
		return Observation{}, err
	}
	now := c.options.Now().UTC()
	if now.Before(leaf.NotBefore) {
		return Observation{}, fmt.Errorf("previous certificate not yet valid: %w", device.ErrDenied)
	}
	if now.Before(leaf.NotAfter) {
		nonce, err := device.RandomID()
		if err != nil {
			return Observation{}, err
		}
		binding := previous.Handle.Binding
		probe := device.Probe{OperationID: binding.OperationID, DeviceID: binding.DeviceID, Generation: binding.Generation, Endpoint: c.options.Endpoint, Nonce: nonce, Deadline: now.Add(30 * time.Second)}
		_, err = c.Probe(ctx, probe, previous)
		if errors.Is(err, ErrACL) && errors.Is(err, device.ErrDenied) {
			return Observation{TLSObservation: "accepted", ApplicationAccessDenied: true}, nil
		}
		return Observation{}, fmt.Errorf("explicit previous MQTT denial not observed: %w", device.ErrUnknown)
	}
	endpoint, err := validateOptions(c.options)
	if err != nil {
		return Observation{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.options.Timeout)
	defer cancel()
	dial := c.options.dialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: c.options.Timeout}).DialContext
	}
	raw, err := dial(ctx, "tcp", endpoint.Host)
	if err != nil {
		return Observation{}, fmt.Errorf("previous TLS denial not observed: %w", device.ErrUnknown)
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return Observation{}, fmt.Errorf("previous TLS diagnostic deadline unavailable: %w", device.ErrUnknown)
	}
	certificate := previous.TLS
	certificate.Leaf = leaf
	var verified atomic.Bool
	network := tls.Client(raw, &tls.Config{RootCAs: c.options.Roots.Clone(), ServerName: endpoint.Hostname(), Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, VerifyConnection: func(state tls.ConnectionState) error {
		verified.Store(len(state.VerifiedChains) > 0 && len(state.PeerCertificates) > 0)
		if !verified.Load() {
			return fmt.Errorf("server trust not verified")
		}
		return nil
	}})
	// The TLS 1.3 client can finish before the server checks its client chain.
	// Require server CertificateVerify and Finished first, then read the protected
	// peer alert. A chain callback alone precedes those authentication checks.
	if err := network.HandshakeContext(ctx); err != nil {
		return Observation{}, fmt.Errorf("authenticated previous TLS denial not observed: %w", device.ErrUnknown)
	}
	state := network.ConnectionState()
	if !verified.Load() || !state.HandshakeComplete || state.Version != tls.VersionTLS13 {
		return Observation{}, fmt.Errorf("authenticated previous TLS denial not established: %w", device.ErrUnknown)
	}
	var data [1]byte
	n, err := network.Read(data[:])
	if n == 0 && certificateAlert(err) {
		return Observation{TLSObservation: "denied", ApplicationAccessDenied: true}, nil
	}
	return Observation{}, fmt.Errorf("protected peer certificate denial not observed: %w", device.ErrUnknown)
}

func certificateAlert(err error) bool {
	var remote *net.OpError
	if !errors.As(err, &remote) || remote.Op != "remote error" {
		return false
	}
	var alert tls.AlertError
	if errors.As(remote.Err, &alert) {
		return alert == 42 || alert == 45 || alert == 46
	}
	// Go 1.27.2 TCP uses the private crypto/tls.alert uint8, while its exported
	// AlertError wrapper is used by QUIC. Unknown representations fail closed.
	value := reflect.ValueOf(remote.Err)
	if !value.IsValid() || value.Kind() != reflect.Uint8 || value.Type().PkgPath() != "crypto/tls" || value.Type().Name() != "alert" {
		return false
	}
	code := value.Uint()
	return code == 42 || code == 45 || code == 46
}
