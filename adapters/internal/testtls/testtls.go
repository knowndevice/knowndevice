// SPDX-License-Identifier: Apache-2.0

// Package testtls supplies real TLS over net.Pipe without requiring a listener.
package testtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"knowndevice.local/knowndevice/sdk/device"
)

type Profile struct {
	Root    *x509.Certificate
	RootKey *ecdsa.PrivateKey
	Roots   *x509.CertPool
	Now     time.Time
	Server  tls.Certificate
}

func Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func New(t *testing.T) *Profile {
	t.Helper()
	profile := &Profile{RootKey: Key(t), Now: time.Now().UTC()}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "adapter test root"}, NotBefore: profile.Now.Add(-time.Hour), NotAfter: profile.Now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &profile.RootKey.PublicKey, profile.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	profile.Root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	profile.Roots = x509.NewCertPool()
	profile.Roots.AddCert(profile.Root)
	serverKey := Key(t)
	server, _ := profile.Sign(t, "lab.known-device.invalid", serverKey.Public(), func(certificate *x509.Certificate) {
		certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	})
	profile.Server = tls.Certificate{Certificate: [][]byte{server.Raw, profile.Root.Raw}, PrivateKey: serverKey, Leaf: server}
	return profile
}

func (p *Profile) Sign(t *testing.T, subject string, public any, change func(*x509.Certificate)) (*x509.Certificate, []byte) {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: subject}, DNSNames: []string{subject}, NotBefore: p.Now.Add(-time.Minute), NotAfter: p.Now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	if change != nil {
		change(certificate)
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, p.Root, public, p.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Root.Raw})...)
	return certificate, chain
}

func CSR(t *testing.T, subject string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}, DNSNames: []string{subject}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func (p *Profile) Credential(t *testing.T, binding device.Binding) device.Credential {
	t.Helper()
	key := Key(t)
	leaf, _ := p.Sign(t, device.Subject(binding.DeviceID, binding.Generation), key.Public(), nil)
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return device.Credential{Handle: device.Handle{Binding: binding, PublicKeyDigest: device.Hash(public)}, TLS: tls.Certificate{Certificate: [][]byte{leaf.Raw, p.Root.Raw}, PrivateKey: key, Leaf: leaf}}
}

func (p *Profile) Recovery(t *testing.T, id string) device.Credential {
	t.Helper()
	key := Key(t)
	leaf, _ := p.Sign(t, device.RecoverySubject(id), key.Public(), nil)
	return device.Credential{Recovery: true, DeviceID: id, TLS: tls.Certificate{Certificate: [][]byte{leaf.Raw, p.Root.Raw}, PrivateKey: key, Leaf: leaf}}
}

func Plan(t *testing.T, now time.Time) device.Plan {
	t.Helper()
	plan := device.Plan{APIVersion: "knowndevice/v1alpha1", DeviceID: "device-a", OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Mode: "rotate", ExpectedGeneration: 1, TargetGeneration: 2, TargetSlot: "B", ConfigDigest: device.Hash([]byte("test config")), ExpiresAt: now.Add(5 * time.Minute)}
	var err error
	plan.Digest, err = plan.CalculateDigest()
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

type Listener struct {
	incoming chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func NewListener(t *testing.T) *Listener {
	t.Helper()
	listener := &Listener{incoming: make(chan net.Conn), done: make(chan struct{})}
	t.Cleanup(func() { listener.Close() })
	return listener
}
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.incoming:
		return connection, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *Listener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (*Listener) Addr() net.Addr { return pipeAddress("TLS test pipe") }

type pipeAddress string

func (pipeAddress) Network() string  { return "pipe" }
func (p pipeAddress) String() string { return string(p) }
func (l *Listener) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.incoming <- server:
		return client, nil
	case <-ctx.Done():
		client.Close()
		server.Close()
		return nil, ctx.Err()
	case <-l.done:
		client.Close()
		server.Close()
		return nil, net.ErrClosed
	}
}

func HTTP(t *testing.T, profile *Profile, handler http.Handler) *Listener {
	return HTTPWithClientAuth(t, profile, handler, tls.RequireAndVerifyClientCert)
}

func HTTPWithClientAuth(t *testing.T, profile *Profile, handler http.Handler, auth tls.ClientAuthType) *Listener {
	t.Helper()
	listener := NewListener(t)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{profile.Server}, ClientCAs: profile.Roots, ClientAuth: auth, MinVersion: tls.VersionTLS12}}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { server.Close() })
	return listener
}
