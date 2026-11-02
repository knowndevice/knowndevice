// SPDX-License-Identifier: Apache-2.0

package reference

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/adapters/controlhttp"
	"github.com/knowndevice/knowndevice/adapters/mqttprobe"
	"github.com/knowndevice/knowndevice/internal/controller"
	"github.com/knowndevice/knowndevice/internal/device"
)

// fakeLink models one broker connection. reply decides what the responder
// sends back for the n-th readiness request on this connection.
type fakeLink struct {
	mu           sync.Mutex
	messages     chan mqttprobe.Message
	errors       chan error
	done         chan struct{}
	subscribeErr error
	reply        func(n int, payload []byte) []mqttprobe.Message
	published    int
	closed       bool
}

func newFakeLink(reply func(int, []byte) []mqttprobe.Message) *fakeLink {
	return &fakeLink{messages: make(chan mqttprobe.Message, 64), errors: make(chan error, 1), done: make(chan struct{}), reply: reply}
}

func (l *fakeLink) Subscribe(context.Context, string) error { return l.subscribeErr }
func (l *fakeLink) Publish(_ context.Context, topic string, payload []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if topic != readyRequestTopic {
		return errors.New("unexpected topic " + topic)
	}
	l.published++
	if l.reply != nil {
		for _, m := range l.reply(l.published, payload) {
			l.messages <- m
		}
	}
	return nil
}
func (l *fakeLink) Messages() <-chan mqttprobe.Message { return l.messages }
func (l *fakeLink) Errors() <-chan error               { return l.errors }
func (l *fakeLink) Done() <-chan struct{}              { return l.done }
func (l *fakeLink) Close(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

func echo(_ int, payload []byte) []mqttprobe.Message {
	return []mqttprobe.Message{{Topic: readyResponseTopic, Payload: bytes.Clone(payload)}}
}

func awaitWith(t *testing.T, bound time.Duration, dial func(context.Context) (brokerLink, error)) (error, time.Duration) {
	t.Helper()
	s := &control{dial: dial}
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	start := time.Now()
	err := s.awaitResponder(ctx)
	return err, time.Since(start)
}

func TestAwaitResponderReturnsOnExactEcho(t *testing.T) {
	link := newFakeLink(echo)
	err, _ := awaitWith(t, 2*time.Second, func(context.Context) (brokerLink, error) { return link, nil })
	if err != nil {
		t.Fatalf("exact echo not accepted: %v", err)
	}
	if !link.closed {
		t.Fatal("readiness connection left open")
	}
}

func TestConnectResponderRetriesFailedConnectionsAndSubscriptions(t *testing.T) {
	cut, refused, ready := newFakeLink(nil), newFakeLink(nil), newFakeLink(nil)
	cut.subscribeErr = fmt.Errorf("MQTT subscription result unavailable: %w", device.ErrUnknown)
	refused.subscribeErr = errors.New("MQTT SUBSCRIBE refused")
	opens := []func() (brokerLink, error){
		func() (brokerLink, error) { return nil, errors.New("broker down") },
		func() (brokerLink, error) { return cut, nil },
		func() (brokerLink, error) { return refused, nil },
		func() (brokerLink, error) { return ready, nil },
	}
	attempt := 0
	var log bytes.Buffer
	got := connectResponder(func(context.Context) (brokerLink, error) {
		attempt++
		return opens[attempt-1]()
	}, time.Second, time.Millisecond, &log)
	if got != brokerLink(ready) || attempt != len(opens) {
		t.Fatalf("connected after %d attempts to %v", attempt, got)
	}
	if !cut.closed || !refused.closed || ready.closed {
		t.Fatalf("closed cut=%v refused=%v ready=%v", cut.closed, refused.closed, ready.closed)
	}
	if lines := strings.Count(log.String(), "responder subscription failed: "); lines != 2 {
		t.Fatalf("logged %d subscription failures:\n%s", lines, log.String())
	}
}

func TestAwaitResponderRepublishesUntilResponderSubscribes(t *testing.T) {
	link := newFakeLink(func(n int, payload []byte) []mqttprobe.Message {
		if n < 3 {
			return nil
		}
		return echo(n, payload)
	})
	err, _ := awaitWith(t, 3*time.Second, func(context.Context) (brokerLink, error) { return link, nil })
	if err != nil || link.published < 3 {
		t.Fatalf("late subscriber not observed: %v after %d requests", err, link.published)
	}
}

func TestAwaitResponderRejectsMismatchedReplies(t *testing.T) {
	link := newFakeLink(func(_ int, payload []byte) []mqttprobe.Message {
		other, _ := json.Marshal(readiness{Nonce: strings.Repeat("a", 32)})
		return []mqttprobe.Message{
			{Topic: readyResponseTopic, Payload: other},
			{Topic: readyResponseTopic, Payload: bytes.Clone(payload), Retained: true},
			{Topic: "kd/gateway-1/g1/response", Payload: bytes.Clone(payload)},
		}
	})
	err, elapsed := awaitWith(t, 600*time.Millisecond, func(context.Context) (brokerLink, error) { return link, nil })
	if !errors.Is(err, device.ErrUnknown) {
		t.Fatalf("stale, retained or foreign reply accepted: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("wait exceeded its bound: %v", elapsed)
	}
}

func TestAwaitResponderUnknownWithoutResponder(t *testing.T) {
	link := newFakeLink(nil)
	err, elapsed := awaitWith(t, 500*time.Millisecond, func(context.Context) (brokerLink, error) { return link, nil })
	if !errors.Is(err, device.ErrUnknown) || elapsed > 2*time.Second {
		t.Fatalf("missing responder: %v after %v", err, elapsed)
	}
}

func TestAwaitResponderRedialsUnavailableOrEndedBroker(t *testing.T) {
	dials := 0
	ended := newFakeLink(nil)
	close(ended.done)
	err, _ := awaitWith(t, 3*time.Second, func(context.Context) (brokerLink, error) {
		dials++
		switch dials {
		case 1:
			return nil, device.ErrUnknown
		case 2:
			return ended, nil
		default:
			return newFakeLink(echo), nil
		}
	})
	if err != nil || dials != 3 {
		t.Fatalf("broker reconnect not retried: %v after %d dials", err, dials)
	}
	if !ended.closed {
		t.Fatal("ended connection not closed")
	}
}

func TestAwaitResponderDeniedSubscriptionStaysUnknown(t *testing.T) {
	err, _ := awaitWith(t, 400*time.Millisecond, func(context.Context) (brokerLink, error) {
		link := newFakeLink(echo)
		link.subscribeErr = device.ErrDenied
		return link, nil
	})
	if !errors.Is(err, device.ErrUnknown) {
		t.Fatalf("broker policy was applied, so the outcome must stay unknown: %v", err)
	}
}

func TestResponderEchoesOnlyWellFormedReadiness(t *testing.T) {
	cfg := device.Config{DeviceID: "gateway-1", MQTTEndpoint: "tls://broker-control:8883"}
	valid, _ := json.Marshal(readiness{Nonce: strings.Repeat("0123456789abcdef", 2)})
	topic, payload, ok := responderReply(t.TempDir(), cfg, mqttprobe.Message{Topic: readyRequestTopic, Payload: valid}, time.Now())
	if !ok || topic != readyResponseTopic || !bytes.Equal(payload, valid) {
		t.Fatalf("readiness not echoed: %q %q %v", topic, payload, ok)
	}
	for name, msg := range map[string]mqttprobe.Message{
		"retained":      {Topic: readyRequestTopic, Payload: valid, Retained: true},
		"short nonce":   {Topic: readyRequestTopic, Payload: []byte(`{"nonce":"abc"}`)},
		"unknown field": {Topic: readyRequestTopic, Payload: []byte(`{"nonce":"0123456789abcdef0123456789abcdef","x":1}`)},
		"not json":      {Topic: readyRequestTopic, Payload: []byte("ready")},
		"device topic":  {Topic: "kd/gateway-1/g1/request", Payload: valid},
	} {
		if _, _, ok := responderReply(t.TempDir(), cfg, msg, time.Now()); ok {
			t.Errorf("%s: responder replied", name)
		}
	}
}

func TestACLLimitsControlToReadinessTopics(t *testing.T) {
	s := openSeeded(t)
	written, err := s.writeACL(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "broker", "acl"))
	if err != nil || string(b) != written {
		t.Fatalf("returned ACL differs from the file: %v", err)
	}
	block := "user broker-control\ntopic write " + readyRequestTopic + "\ntopic read " + readyResponseTopic + "\n"
	if !strings.HasSuffix(written, block) || strings.Count(written, "user broker-control") != 1 {
		t.Fatalf("control ACL is not limited to readiness topics:\n%s", written)
	}
}

// fakeBroker stands in for restarting Mosquitto: it counts restarts and marks
// a broker as running.
func fakeBroker(s *control, restarts *int, fail error) func(context.Context) error {
	return func(context.Context) error {
		*restarts++
		if fail != nil {
			return fail
		}
		s.exited = make(chan struct{})
		return nil
	}
}

func silentResponder(context.Context) (brokerLink, error) { return newFakeLink(nil), nil }
func readyResponder(context.Context) (brokerLink, error)  { return newFakeLink(echo), nil }

func TestReloadRestartsOnlyUntilPolicyIsApplied(t *testing.T) {
	s := &control{config: device.Config{RequestTimeoutSeconds: 1}}
	restarts := 0
	dials := 0
	s.dial = func(ctx context.Context) (brokerLink, error) { dials++; return readyResponder(ctx) }
	s.restart = fakeBroker(s, &restarts, device.ErrUnknown)
	if err := s.reloadBroker(context.Background(), "acl-1"); err == nil || dials != 0 || s.applied != "" {
		t.Fatalf("failed restart must not wait or record the policy: %v, dials %d", err, dials)
	}
	s.restart = fakeBroker(s, &restarts, nil)
	if err := s.reloadBroker(context.Background(), "acl-1"); err != nil || restarts != 2 || s.applied != "acl-1" {
		t.Fatalf("policy not applied after a failed restart: %v, restarts %d", err, restarts)
	}
	if err := s.reloadBroker(context.Background(), "acl-1"); err != nil || restarts != 2 {
		t.Fatalf("unchanged policy restarted the broker again: %v, restarts %d", err, restarts)
	}
	if err := s.reloadBroker(context.Background(), "acl-2"); err != nil || restarts != 3 {
		t.Fatalf("changed policy did not restart the broker: %v, restarts %d", err, restarts)
	}
	close(s.exited)
	if err := s.reloadBroker(context.Background(), "acl-2"); err != nil || restarts != 4 {
		t.Fatalf("ended broker was not restarted: %v, restarts %d", err, restarts)
	}
}

func TestReloadBoundStaysBelowRequestTimeout(t *testing.T) {
	s := &control{config: device.Config{RequestTimeoutSeconds: 1}, dial: silentResponder}
	restarts := 0
	s.restart = fakeBroker(s, &restarts, nil)
	start := time.Now()
	err := s.reloadBroker(context.Background(), "acl")
	if elapsed := time.Since(start); !errors.Is(err, device.ErrUnknown) || elapsed >= time.Second {
		t.Fatalf("silent responder: %v after %v", err, elapsed)
	}
}

func TestRegistrationStaysUnknownUntilResponderAnswers(t *testing.T) {
	s := openSeeded(t)
	plan, err := controller.NewPlan(s.config, device.State{DeviceID: s.config.DeviceID}, "enroll", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, chain := targetCertificate(t, device.Subject(plan.DeviceID, plan.TargetGeneration))
	insert(t, s, reservation{Plan: plan, Certificate: chain, IssueSent: true})
	in := controlhttp.Request{Plan: plan, Handle: &device.Handle{Binding: plan.Binding()}}
	restarts := 0
	s.restart = fakeBroker(s, &restarts, nil)
	s.dial = silentResponder
	if status := call(t, s, "/v1/register", in, leaf); status != "unknown" {
		t.Fatalf("registration without responder answered %q", status)
	}
	r, err := s.get(context.Background(), plan.OperationID)
	if err != nil || r == nil || !r.Registering || r.Registered {
		t.Fatalf("registration recorded before the responder answered: %v", err)
	}
	acl, err := os.ReadFile(filepath.Join(s.dir, "broker", "acl"))
	if err != nil || !strings.Contains(string(acl), "user "+device.Subject(plan.DeviceID, plan.TargetGeneration)+"\n") {
		t.Fatal("applied broker policy missing after unknown registration")
	}
	s.dial = readyResponder
	if status := call(t, s, "/v1/register", in, leaf); status != "ok" {
		t.Fatalf("registration after responder answered: %q", status)
	}
	r, err = s.get(context.Background(), plan.OperationID)
	if err != nil || r == nil || !r.Registered || restarts != 1 {
		t.Fatalf("registration not completed or broker restarted again: %v, restarts %d", err, restarts)
	}
}

func TestRetirementRetryAfterUnknownIsNotDenied(t *testing.T) {
	s := openSeeded(t)
	first, err := controller.NewPlan(s.config, device.State{DeviceID: s.config.DeviceID}, "enroll", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, oldChain := targetCertificate(t, device.Subject(first.DeviceID, first.TargetGeneration))
	insert(t, s, reservation{Plan: first, Certificate: oldChain, IssueSent: true, Registered: true, Activated: true})
	active := &device.Handle{Binding: first.Binding()}
	plan, err := controller.NewPlan(s.config, device.State{DeviceID: s.config.DeviceID, Counter: first.TargetGeneration, Active: active}, "rotate", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, chain := targetCertificate(t, device.Subject(plan.DeviceID, plan.TargetGeneration))
	// A previous attempt passed the application check, saved Retiring and
	// applied the policy, then timed out waiting for the responder.
	insert(t, s, reservation{Plan: plan, Certificate: chain, IssueSent: true, Registered: true, Activated: true, Retiring: true})
	if _, err := s.db.Exec("UPDATE metadata SET value=? WHERE name='active'", plan.TargetGeneration); err != nil {
		t.Fatal(err)
	}
	in := controlhttp.Request{Plan: plan, Certificate: oldChain, Handle: &device.Handle{Binding: device.Binding{DeviceID: plan.DeviceID, Generation: plan.ExpectedGeneration}}}
	restarts := 0
	s.restart = fakeBroker(s, &restarts, nil)
	s.dial = silentResponder
	if status := call(t, s, "/v1/retire", in, leaf); status != "unknown" {
		t.Fatalf("retirement retry without responder answered %q", status)
	}
	acl, err := os.ReadFile(filepath.Join(s.dir, "broker", "acl"))
	if err != nil || strings.Contains(string(acl), "user "+device.Subject(first.DeviceID, first.TargetGeneration)+"\n") {
		t.Fatal("retired generation still in the broker policy")
	}
	if r, err := s.get(context.Background(), plan.OperationID); err != nil || r.Retirement != nil {
		t.Fatalf("retirement recorded before the responder answered: %v", err)
	}
	s.dial = readyResponder
	if status := call(t, s, "/v1/retire", in, leaf); status != "ok" {
		t.Fatalf("retirement retry after responder answered: %q", status)
	}
	r, err := s.get(context.Background(), plan.OperationID)
	if err != nil || r.Retirement == nil || r.Retirement.Generation != plan.ExpectedGeneration || restarts != 1 {
		t.Fatalf("retirement not completed or broker restarted again: %v, restarts %d", err, restarts)
	}
}

func insert(t *testing.T, s *control, r reservation) {
	t.Helper()
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO operations(id,target,digest,body) VALUES(?,?,?,?)", r.Plan.OperationID, r.Plan.TargetGeneration, r.Plan.Digest, body); err != nil {
		t.Fatal(err)
	}
}

func call(t *testing.T, s *control, path string, in controlhttp.Request, peer *x509.Certificate) string {
	t.Helper()
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	out := httptest.NewRecorder()
	s.request(out, req)
	var response controlhttp.Response
	if err := json.Unmarshal(out.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response.Status
}

func openSeeded(t *testing.T) *control {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "lab")
	if err := seed(dir); err != nil {
		t.Fatal(err)
	}
	s, err := openControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.config.RootCertificate = filepath.Join(dir, "root.crt")
	s.config.RequestTimeoutSeconds = 1
	t.Cleanup(func() {
		s.db.Close()
		s.lock.Close()
	})
	return s
}

func targetCertificate(t *testing.T, subject string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: subject}, DNSNames: []string{subject}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
