// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/internal/device"
)

func testLocalRoleCertificate(t *testing.T) (*x509.Certificate, *x509.Certificate, tls.Certificate) {
	t.Helper()
	rootKey, e := newKey()
	if e != nil {
		t.Fatal(e)
	}
	_, root, e := cert("test role HTTPS root", nil, rootKey, nil, nil, true, nil)
	if e != nil {
		t.Fatal(e)
	}
	serverKey, e := newKey()
	if e != nil {
		t.Fatal(e)
	}
	_, serverLeaf, e := cert("localhost", []string{"localhost"}, serverKey, root, rootKey, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if e != nil {
		t.Fatal(e)
	}
	return root, serverLeaf, tls.Certificate{Certificate: [][]byte{serverLeaf.Raw}, Leaf: serverLeaf, PrivateKey: serverKey}
}

func localRoleURL(t *testing.T, original string) string {
	t.Helper()
	u, e := url.Parse(original)
	if e != nil {
		t.Fatal(e)
	}
	u.Host = net.JoinHostPort("localhost", u.Port())
	return u.String()
}

func TestAuthorityProxyUsesFreshNonReplayableConnections(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Skipf("loopback socket unavailable in this test environment: %v", e)
	}
	defer listener.Close()
	dir, cfg, snapshot := testLab(t)
	rootKey, e := newKey()
	if e != nil {
		t.Fatal(e)
	}
	_, root, e := cert("test authority HTTPS root", nil, rootKey, nil, nil, true, nil)
	if e != nil {
		t.Fatal(e)
	}
	serverKey, e := newKey()
	if e != nil {
		t.Fatal(e)
	}
	_, serverLeaf, e := cert("localhost", []string{"localhost"}, serverKey, root, rootKey, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if e != nil {
		t.Fatal(e)
	}
	short := *serverLeaf
	short.NotAfter = time.Now().Add(3 * time.Second)
	shortDER, e := x509.CreateCertificate(rand.Reader, &short, root, &serverKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	var shortSelected atomic.Bool
	var connections, requests atomic.Int32
	backend := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.GetBody != nil || r.Header.Get("Idempotency-Key") != "" || r.Header.Get("X-Idempotency-Key") != "" {
			t.Error("authority backend received a replay hint")
		}
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/close" {
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("{}"))
	})}}
	backend.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	backend.TLS = &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		der := serverLeaf.Raw
		if shortSelected.Load() {
			der = shortDER
		}
		return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: serverKey}, nil
	}}
	backend.StartTLS()
	defer backend.Close()
	for i := range snapshot.Trust {
		if snapshot.Trust[i].Role == "authority-transport" {
			snapshot.Trust[i].Endpoint = localRoleURL(t, backend.URL)
			snapshot.Trust[i].PeerName = "localhost"
			snapshot.Trust[i].Anchors = [][]byte{root.Raw}
			snapshot.Trust[i].AllowedIssuers = []string{device.Hash(root.Raw)}
		}
	}
	cfg.CAURL = localRoleURL(t, backend.URL)
	control := &control{dir: dir, config: cfg, snapshot: snapshot}
	proxy, e := control.caProxy()
	if e != nil {
		t.Fatal(e)
	}
	frontListener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	front := &httptest.Server{Listener: frontListener, Config: &http.Server{Handler: proxy}}
	front.Start()
	defer front.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	call := func(path string) int {
		t.Helper()
		r, e := http.NewRequest("POST", front.URL+path, bytes.NewBufferString("{}"))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Idempotency-Key", "must-not-replay")
		r.Header.Set("X-Idempotency-Key", "must-not-replay")
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	for range 2 {
		if call("/sign") != http.StatusCreated {
			t.Fatal("pinned authority response refused")
		}
	}
	if connections.Load() != 2 || requests.Load() != 2 {
		t.Fatal("authority operations reused a TLS connection")
	}
	if call("/close") != http.StatusBadGateway || requests.Load() != 3 {
		t.Fatal("unknown authority request was retried")
	}
	shortSelected.Store(true)
	time.Sleep(2200 * time.Millisecond)
	if call("/sign") != http.StatusBadGateway || requests.Load() != 3 {
		t.Fatal("authority request crossed its full validity interval")
	}
}

func TestLabCheckpointCancellationPreservesExactMarker(t *testing.T) {
	dir, _, snapshot := testLab(t)
	p := testPlan(t, snapshot, 0, 1)
	if e := writeJSON(filepath.Join(dir, "fixtures", "policy.json"), policy{PauseAt: "application:candidate-verified"}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if e := labCheckpoint(ctx, dir, "application", "candidate-verified", p); e != device.ErrUnknown {
		t.Fatal("canceled checkpoint allowed the next effect")
	}
	var marker map[string]string
	if e := readJSON(filepath.Join(dir, "application", "checkpoint-"+p.OperationID+"-candidate-verified.json"), &marker); e != nil || marker["operationId"] != p.OperationID || marker["planDigest"] != p.Digest {
		t.Fatal("checkpoint lost the exact public operation marker")
	}
}

func TestApplicationCallbackIssuerAndBodyDeadline(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Skipf("loopback socket unavailable in this test environment: %v", e)
	}
	defer listener.Close()
	dir, _, snapshot := testLab(t)
	root, serverLeaf, applicationCredential := testLocalRoleCertificate(t)
	observerCredential, e := credentialAt(dir, "observer")
	if e != nil {
		t.Fatal(e)
	}
	var requests atomic.Int32
	callback := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(2200 * time.Millisecond)
		_, _ = w.Write([]byte("{\"status\":\"ok\"}"))
	})}}
	callback.TLS = &tls.Config{Certificates: []tls.Certificate{applicationCredential}, MinVersion: tls.VersionTLS13}
	callback.StartTLS()
	defer callback.Close()
	for i := range snapshot.Trust {
		if snapshot.Trust[i].Role == "application" {
			snapshot.Trust[i].Endpoint = localRoleURL(t, callback.URL)
			snapshot.Trust[i].PeerName = "localhost"
			snapshot.Trust[i].Anchors = [][]byte{root.Raw}
			snapshot.Trust[i].LeafPins = []string{device.Hash(serverLeaf.Raw)}
			snapshot.Trust[i].SPKIPins = []string{device.Hash(serverLeaf.RawSubjectPublicKeyInfo)}
			snapshot.Trust[i].AllowedIssuers = []string{device.Hash([]byte("wrong callback issuer"))}
		}
	}
	p := testPlan(t, snapshot, 0, 1)
	var output device.RoleResponse
	if e = post(context.Background(), snapshot, "application", "/status", &observerCredential, device.RoleRequest{Plan: p}, &output); e == nil || requests.Load() != 0 {
		t.Fatal("application callback accepted an unapproved issuer")
	}
	for i := range snapshot.Trust {
		if snapshot.Trust[i].Role == "application" {
			snapshot.Trust[i].AllowedIssuers = []string{device.Hash(snapshot.Trust[i].Anchors[0])}
		}
	}
	p = testPlan(t, snapshot, 0, 1)
	transport, e := snapshot.Role("transport")
	if e != nil {
		t.Fatal(e)
	}
	nonce, e := device.RandomID()
	if e != nil {
		t.Fatal(e)
	}
	probe := device.Probe{OperationID: p.OperationID, DeviceID: p.DeviceID, Generation: p.TargetGeneration, Endpoint: transport.Endpoint, Nonce: nonce, Deadline: time.Now().UTC().Add(3 * time.Second)}
	if e = post(context.Background(), snapshot, "application", "/observe", &observerCredential, device.RoleRequest{Plan: p, Probe: probe}, &output); e == nil || requests.Load() != 1 {
		t.Fatal("body read crossed a challenge deadline without refusal")
	}
}

type delayedSigner struct {
	crypto.Signer
	delay time.Duration
	calls *atomic.Int32
}

func (s delayedSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	s.calls.Add(1)
	time.Sleep(s.delay)
	return s.Signer.Sign(random, digest, options)
}

// The timerless parent models a delayed cancellation notification. Checks must
// inspect its actual deadline even when Err and Done still report no cancel.
type timerlessDeadline struct {
	context.Context
	at time.Time
}

func (c timerlessDeadline) Deadline() (time.Time, bool) { return c.at, true }

func TestDelayedAuthorityHandshakePastDeadlineSendsNoSign(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Skipf("loopback socket unavailable in this test environment: %v", e)
	}
	defer listener.Close()
	dir, cfg, snapshot := testLab(t)
	serverTLS, e := serviceTLS(dir, "issuance", snapshot, []string{"control"})
	if e != nil {
		t.Fatal(e)
	}
	root, serverLeaf, serverCredential := testLocalRoleCertificate(t)
	serverTLS.Certificates = []tls.Certificate{serverCredential}
	var requests atomic.Int32
	backend := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("{}"))
	})}, TLS: serverTLS}
	backend.StartTLS()
	defer backend.Close()
	for i := range snapshot.Trust {
		if snapshot.Trust[i].Role == "issuance" {
			snapshot.Trust[i].Endpoint = localRoleURL(t, backend.URL)
			snapshot.Trust[i].PeerName = "localhost"
			snapshot.Trust[i].Anchors = [][]byte{root.Raw}
			snapshot.Trust[i].LeafPins = []string{device.Hash(serverLeaf.Raw)}
			snapshot.Trust[i].SPKIPins = []string{device.Hash(serverLeaf.RawSubjectPublicKeyInfo)}
			snapshot.Trust[i].AllowedIssuers = []string{device.Hash(root.Raw)}
		}
	}
	caller, e := credentialAt(dir, "authority-caller")
	if e != nil {
		t.Fatal(e)
	}
	var signerCalls atomic.Int32
	caller.PrivateKey = delayedSigner{Signer: caller.PrivateKey.(crypto.Signer), delay: 2200 * time.Millisecond, calls: &signerCalls}
	p := testPlan(t, snapshot, 0, 1)
	p.ExpiresAt = time.Now().UTC().Add(3 * time.Second)
	p.Digest, e = p.CalculateDigest()
	if e != nil {
		t.Fatal(e)
	}
	r := testReservation(t, snapshot, p)
	r.IssueSent = true
	control := &control{dir: dir, config: cfg, snapshot: snapshot, authorityCaller: caller}
	ctx := timerlessDeadline{Context: context.Background(), at: time.Now().Add(100 * time.Millisecond)}
	started := time.Now()
	if _, e = control.sign(ctx, &r); e == nil || requests.Load() != 0 || signerCalls.Load() != 1 || time.Since(started) < 2200*time.Millisecond {
		t.Fatalf("authority effect followed a delayed handshake past deadline: err=%v requests=%d signer calls=%d elapsed=%s plan remaining=%s", e, requests.Load(), signerCalls.Load(), time.Since(started), time.Until(p.ExpiresAt))
	}
	if e = control.revoke(ctx, &r, &r); e == nil || requests.Load() != 0 {
		t.Fatal("authority revoke followed an expired deadline")
	}
}

func TestAuthorityTokenExpiryIsBoundToPlanInterval(t *testing.T) {
	dir, cfg, snapshot := testLab(t)
	p := testPlan(t, snapshot, 0, 1)
	p.ExpiresAt = time.Now().UTC().Add(5 * time.Second)
	p.Digest, _ = p.CalculateDigest()
	r := testReservation(t, snapshot, p)
	control := &control{dir: dir, config: cfg, snapshot: snapshot}
	token, e := control.token(p, "sign", "", r.CSR)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("invalid scoped token")
	}
	payload, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		t.Fatal(e)
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if e = json.Unmarshal(payload, &claims); e != nil || claims.Exp > p.ExpiresAt.Add(-time.Second).Unix() || claims.Exp <= time.Now().Unix() {
		t.Fatal("authority token exceeds the plan time interval")
	}
}

func TestRevocationStatusUsesDurableSendIntentAndNeverReplaysUnknown(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Skipf("loopback socket unavailable in this test environment: %v", e)
	}
	defer listener.Close()
	dir, cfg, snapshot := testLab(t)
	serverTLS, e := serviceTLS(dir, "issuance", snapshot, []string{"control"})
	if e != nil {
		t.Fatal(e)
	}
	issuerRoot, issuerLeaf, issuerCredential := testLocalRoleCertificate(t)
	serverTLS.Certificates = []tls.Certificate{issuerCredential}
	var requests atomic.Int32
	backend := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("{\"status\":\"ok\"}"))
	})}, TLS: serverTLS}
	backend.StartTLS()
	defer backend.Close()
	rootKey, e := newKey()
	if e != nil {
		t.Fatal(e)
	}
	_, operationalRoot, e := cert("test operational root", nil, rootKey, nil, nil, true, nil)
	if e != nil {
		t.Fatal(e)
	}
	intermediateKey, e := newKey()
	if e != nil {
		t.Fatal(e)
	}
	intermediatePEM, intermediate, e := cert("test operational issuer", nil, intermediateKey, operationalRoot, rootKey, true, nil)
	if e != nil {
		t.Fatal(e)
	}
	for i := range snapshot.Trust {
		switch snapshot.Trust[i].Role {
		case "operational":
			snapshot.Trust[i].Anchors = [][]byte{operationalRoot.Raw}
			snapshot.Trust[i].AllowedIssuers = []string{device.Hash(intermediate.Raw)}
		case "issuance":
			snapshot.Trust[i].Endpoint = localRoleURL(t, backend.URL)
			snapshot.Trust[i].PeerName = "localhost"
			snapshot.Trust[i].Anchors = [][]byte{issuerRoot.Raw}
			snapshot.Trust[i].LeafPins = []string{device.Hash(issuerLeaf.Raw)}
			snapshot.Trust[i].SPKIPins = []string{device.Hash(issuerLeaf.RawSubjectPublicKeyInfo)}
		}
	}
	deviceData, e := os.ReadFile(filepath.Join(dir, "device.json"))
	if e != nil {
		t.Fatal(e)
	}
	var deviceConfig device.Config
	if e = json.Unmarshal(deviceData, &deviceConfig); e != nil {
		t.Fatal(e)
	}
	deviceConfig.StateDir = filepath.Join(dir, "device")
	deviceConfig.RecoveryCertificate = filepath.Join(dir, "recovery", "cert.pem")
	deviceConfig.RecoveryKey = filepath.Join(dir, "recovery", "key.pem")
	for i := range deviceConfig.Trust.Roles {
		rs, e := snapshot.Role(deviceConfig.Trust.Roles[i].Role)
		if e != nil {
			t.Fatal(e)
		}
		rootPath := filepath.Join(dir, "test-"+rs.Role+"-root.crt")
		if e = writeAtomic(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rs.Anchors[0]})); e != nil {
			t.Fatal(e)
		}
		deviceConfig.Trust.Roles[i].RootCertificates = []string{rootPath}
		deviceConfig.Trust.Roles[i].Endpoint = rs.Endpoint
		deviceConfig.Trust.Roles[i].PeerName = rs.PeerName
		deviceConfig.Trust.Roles[i].LeafPins = rs.LeafPins
		deviceConfig.Trust.Roles[i].SPKIPins = rs.SPKIPins
		deviceConfig.Trust.Roles[i].AllowedIssuers = rs.AllowedIssuers
	}
	cfg.DeviceConfig = filepath.Join(dir, "device-native-fixture.json")
	if e = writeJSON(cfg.DeviceConfig, deviceConfig); e != nil {
		t.Fatal(e)
	}
	snapshot, e = deviceConfig.ResolveSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	cfg.Snapshot = snapshot.Bytes()
	cfg.ConfigDigest = snapshot.Digest()
	if e = writeJSON(filepath.Join(dir, "services.json"), cfg); e != nil {
		t.Fatal(e)
	}
	control, e := openControl(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { control.store.close() }()
	ctx := context.Background()
	var ready struct {
		Status string `json:"status"`
	}
	if e = post(ctx, snapshot, "issuance", "/revoke", &control.authorityCaller, map[string]string{"serial": "mock-readiness"}, &ready); e != nil || ready.Status != "ok" || requests.Load() != 1 {
		t.Fatal("mock revocation backend was not reachable through the selected TLS role")
	}
	requests.Store(0)
	install := func(expected, target uint64) (*reservation, *x509.Certificate) {
		t.Helper()
		p := testPlan(t, snapshot, expected, target)
		r := testReservation(t, snapshot, p)
		saved, e := control.store.reserve(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		csr, e := snapshot.Profile.ValidateCSR(saved.CSR, p.DeviceID, p.TargetGeneration)
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now().UTC().Truncate(time.Second)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(target) + 100), Subject: pkix.Name{CommonName: snapshot.Profile.Subject(p.DeviceID, p.TargetGeneration)}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(1170 * time.Second), SignatureAlgorithm: x509.ECDSAWithSHA256, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
		der, e := x509.CreateCertificate(rand.Reader, leaf, intermediate, csr.PublicKey, intermediateKey)
		if e != nil {
			t.Fatal(e)
		}
		chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), intermediatePEM...)
		if e = control.install(ctx, saved, chain); e != nil {
			t.Fatal(e)
		}
		saved.Registered = true
		if e = control.store.save(ctx, saved); e != nil {
			t.Fatal(e)
		}
		if e = control.store.activate(ctx, saved, device.ApplicationEvidence{}); e != nil {
			t.Fatal(e)
		}
		parsed, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		return saved, parsed
	}
	old, _ := install(0, 1)
	target, targetLeaf := install(1, 2)
	// This fixture starts after the separately tested completed withdrawal. No
	// request can supply or replace the server's trusted durable phase record.
	target.Withdrawal = &device.WithdrawalEvidence{Previous: old.Candidate, Target: target.Candidate, Scope: snapshot.Composition.WithdrawalScope, PolicyRevision: target.Revision + 1, SessionsTerminated: true, Denial: device.AccessObservation{Kind: "denied"}}
	if e = control.store.save(ctx, target); e != nil {
		t.Fatal(e)
	}
	requestID, e := device.RandomID()
	if e != nil {
		t.Fatal(e)
	}
	in := device.RoleRequest{Plan: target.Plan, Previous: old.Certificate, RequestID: requestID}
	call := func(path string) (device.RoleResponse, error) {
		t.Helper()
		req := httptest.NewRequest("POST", "https://profile-control:8443"+path, nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{targetLeaf, intermediate}}
		return control.handle(req, in)
	}
	absent, e := call("/revocation-status")
	if !errors.Is(e, device.ErrNotFound) || absent.Evidence == nil || absent.Evidence.Subject != old.Candidate || absent.Evidence.Plan != target.Plan || absent.Evidence.Action != "revocation-status" || absent.Evidence.Status != "not-started" || absent.Evidence.Revision != target.Revision || absent.Evidence.Source != source(snapshot, "control") || requests.Load() != 0 {
		t.Fatal("pre-send status did not establish the exact authoritative absence")
	}
	target.RevocationSent = true
	if e = control.store.save(ctx, target); e != nil {
		t.Fatal(e)
	}
	control.store.close()
	control, e = openControl(dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/revocation-status", "/revoke", "/revocation-status", "/revoke"} {
		if _, e = call(path); !errors.Is(e, device.ErrUnknown) || requests.Load() != 0 {
			t.Fatalf("unknown revocation through %s: error=%v backendRequests=%d", path, e, requests.Load())
		}
	}
}
