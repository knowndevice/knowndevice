// SPDX-License-Identifier: Apache-2.0

package controlhttp

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/adapters/credentials"
	"github.com/knowndevice/knowndevice/adapters/internal/testtls"
	"github.com/knowndevice/knowndevice/adapters/mqttprobe"
	"github.com/knowndevice/knowndevice/sdk/device"
)

type probeFunc func(context.Context, device.Probe, device.Credential) (device.Probe, error)

func (f probeFunc) Probe(ctx context.Context, request device.Probe, credential device.Credential) (device.Probe, error) {
	return f(ctx, request, credential)
}

func boundResponse(request Request, generation uint64) Response {
	return Response{OperationID: request.Plan.OperationID, PlanDigest: request.Plan.Digest, DeviceID: request.Plan.DeviceID, Generation: generation, Status: "ok"}
}

func TestHTTPContractCarriesExactPlanAndSigner(t *testing.T) {
	profile := testtls.New(t)
	plan := testtls.Plan(t, profile.Now)
	previous := profile.Credential(t, device.Binding{DeviceID: plan.DeviceID, OperationID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Generation: 1, Slot: "A"})
	target := profile.Credential(t, plan.Binding())
	csr := testtls.CSR(t, device.Subject(plan.DeviceID, 2), target.TLS.PrivateKey.(*ecdsa.PrivateKey))
	chain, err := credentials.PublicChain(target)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := credentials.CertificateFingerprint(chain)
	var mu sync.Mutex
	paths := make(map[string]int)
	server := testtls.HTTP(t, profile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request Request
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			t.Error(err)
		}
		if request.Plan != plan {
			t.Error("endpoint lost the exact approved plan")
		}
		mu.Lock()
		paths[r.URL.Path]++
		mu.Unlock()
		generation := plan.TargetGeneration
		if strings.Contains(r.URL.Path, "retire") || strings.HasPrefix(r.URL.Path, "/v1/rev") {
			generation = plan.ExpectedGeneration
		}
		response := boundResponse(request, generation)
		switch r.URL.Path {
		case "/v1/issue", "/v1/issue/status":
			if string(request.CSR) != string(csr) {
				t.Error("CSR changed")
			}
			response.Certificate = chain
		case "/v1/register", "/v1/registration", "/v1/activate", "/v1/activation", "/v1/activated", "/v1/activation-status":
			if request.Handle == nil || *request.Handle != target.Handle || string(request.Certificate) != string(chain) {
				t.Error("target handle or certificate lost")
			}
			if r.TLS.PeerCertificates[0].Subject.CommonName != device.Subject(plan.DeviceID, 2) {
				t.Error("target actual TLS signer missing")
			}
			if r.URL.Path == "/v1/activate" || r.URL.Path == "/v1/activation" {
				nonce, _ := device.RandomID()
				response.Activation = &device.Activation{OperationID: plan.OperationID, PlanDigest: plan.Digest, DeviceID: plan.DeviceID, ApplicationID: "application-a", Generation: plan.TargetGeneration, CertificateFingerprint: fingerprint, Probe: device.Probe{OperationID: plan.OperationID, DeviceID: plan.DeviceID, Generation: plan.TargetGeneration, Endpoint: "tls://lab.known-device.invalid:8883", Nonce: nonce, Deadline: profile.Now.Add(30 * time.Second)}}
			} else if (r.URL.Path == "/v1/activated" || r.URL.Path == "/v1/activation-status") && request.Activation == nil {
				t.Error("control CAS lacks application acknowledgment")
			}
		case "/v1/retire", "/v1/retirement":
			if request.Handle == nil || *request.Handle != previous.Handle {
				t.Error("retirement lost the previous handle")
			}
			if r.TLS.PeerCertificates[0].Subject.CommonName != device.Subject(plan.DeviceID, plan.TargetGeneration) {
				t.Error("old signer authenticated its own retirement")
			}
			response.Retirement = &device.Retirement{OperationID: plan.OperationID, PlanDigest: plan.Digest, Generation: plan.ExpectedGeneration, PolicyDurable: true, SessionsTerminated: true}
		case "/v1/revoke", "/v1/revocation":
			if request.Handle == nil || *request.Handle != previous.Handle || r.TLS.PeerCertificates[0].Subject.CommonName != device.Subject(plan.DeviceID, plan.TargetGeneration) {
				t.Error("CA retirement lost artifact or current signer scope")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	client, err := New(Options{ControlURL: "https://lab.known-device.invalid", ApplicationURL: "https://lab.known-device.invalid", ControlRoots: profile.Roots, ApplicationRoots: profile.Roots, ApplicationID: "application-a", ProbeEndpoint: "tls://lab.known-device.invalid:8883", Timeout: time.Second, Now: func() time.Time { return profile.Now }, dialContext: server.DialContext, ProbeTransport: probeFunc(func(_ context.Context, request device.Probe, credential device.Credential) (device.Probe, error) {
		if credential.Handle == previous.Handle {
			if request.OperationID != previous.Handle.Binding.OperationID || request.Generation != 1 || request.Nonce == "" {
				t.Error("old access proof lost its scope")
			}
			return device.Probe{}, fmt.Errorf("explicit broker denial: %w: %w", device.ErrDenied, mqttprobe.ErrACL)
		}
		if credential.Handle != target.Handle {
			t.Error("probe did not receive the actual target")
		}
		return request, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Authorize(context.Background(), plan, &previous); err != nil {
		t.Fatal(err)
	}
	issue := device.IssueRequest{Plan: plan, CSR: csr, Credential: &previous}
	if _, err := client.Issue(context.Background(), issue); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Lookup(context.Background(), issue); err != nil {
		t.Fatal(err)
	}
	if err := client.Register(context.Background(), plan, target); err != nil {
		t.Fatal(err)
	}
	if err := client.Registration(context.Background(), plan, target); err != nil {
		t.Fatal(err)
	}
	probe := device.Probe{OperationID: plan.OperationID, DeviceID: plan.DeviceID, Generation: 2, Endpoint: "tls://lab.known-device.invalid:8883", Nonce: "cccccccccccccccccccccccccccccccc", Deadline: profile.Now.Add(30 * time.Second)}
	if _, err := client.Probe(context.Background(), probe, target); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Activate(context.Background(), plan, target); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ActivationStatus(context.Background(), plan, target); err != nil {
		t.Fatal(err)
	}
	retirement, err := client.Retire(context.Background(), plan, previous, target)
	if err != nil || !retirement.ApplicationAccessDenied || retirement.TLSObservation != "accepted" {
		t.Fatalf("retirement = %+v, %v", retirement, err)
	}
	if _, err := client.RetirementStatus(context.Background(), plan, previous, target); err != nil {
		t.Fatal(err)
	}
	if err := client.Revoke(context.Background(), plan, previous, target); err != nil {
		t.Fatal(err)
	}
	if err := client.RevocationStatus(context.Background(), plan, previous, target); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/v1/authorize", "/v1/issue", "/v1/issue/status", "/v1/register", "/v1/registration", "/v1/activate", "/v1/activation", "/v1/activated", "/v1/activation-status", "/v1/retire", "/v1/retirement", "/v1/revoke", "/v1/revocation"} {
		if paths[path] != 1 {
			t.Errorf("%s calls = %d", path, paths[path])
		}
	}
}

func TestStatusBindingAndSafeUnknown(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     string
		badBinding bool
		want       error
	}{
		{name: "not found", status: "not-found", want: device.ErrNotFound},
		{name: "unknown", status: "unknown", want: device.ErrUnknown},
		{name: "denied", status: "denied", want: device.ErrDenied},
		{name: "unsupported", status: "unsupported", want: device.ErrUnsupported},
		{name: "conflict", status: "conflict", want: device.ErrConflict},
		{name: "stale response", status: "ok", badBinding: true, want: device.ErrUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := testtls.New(t)
			plan := testtls.Plan(t, profile.Now)
			target := profile.Credential(t, plan.Binding())
			server := testtls.HTTP(t, profile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request Request
				_ = json.NewDecoder(r.Body).Decode(&request)
				response := boundResponse(request, plan.TargetGeneration)
				response.Status = test.status
				if test.badBinding {
					response.OperationID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(response)
			}))
			client, err := New(Options{ControlURL: "https://lab.known-device.invalid", ApplicationURL: "https://lab.known-device.invalid", ControlRoots: profile.Roots, ApplicationRoots: profile.Roots, ApplicationID: "application-a", ProbeEndpoint: "tls://lab.known-device.invalid:8883", Timeout: time.Second, Now: func() time.Time { return profile.Now.Add(10 * time.Minute) }, dialContext: server.DialContext})
			if err != nil {
				t.Fatal(err)
			}
			err = client.Registration(context.Background(), plan, target)
			if !errors.Is(err, test.want) {
				t.Fatalf("status = %v, want %v", err, test.want)
			}
			if err := client.Register(context.Background(), plan, target); err == nil {
				t.Fatal("expired mutation accepted")
			}
		})
	}
}

func TestRecoveryAndUnsupportedProbeScope(t *testing.T) {
	profile := testtls.New(t)
	plan := testtls.Plan(t, profile.Now)
	client, err := New(Options{ControlURL: "https://lab.known-device.invalid", ApplicationURL: "https://lab.known-device.invalid", ControlRoots: profile.Roots, ApplicationRoots: profile.Roots, ApplicationID: "application-a", ProbeEndpoint: "tls://lab.known-device.invalid:8883", Timeout: time.Second, Now: func() time.Time { return profile.Now }})
	if err != nil {
		t.Fatal(err)
	}
	recovery := profile.Recovery(t, plan.DeviceID)
	if err := client.Authorize(context.Background(), plan, &recovery); !errors.Is(err, device.ErrDenied) {
		t.Fatalf("recovery rotate scope = %v", err)
	}
	if _, err := client.Activate(context.Background(), plan, recovery); !errors.Is(err, device.ErrDenied) {
		t.Fatalf("recovery activation scope = %v", err)
	}
	if _, err := client.Probe(context.Background(), device.Probe{}, profile.Credential(t, plan.Binding())); !errors.Is(err, device.ErrUnsupported) {
		t.Fatalf("absent transport = %v", err)
	}
}

func TestRetirementRequiresExplicitApplicationDenial(t *testing.T) {
	profile := testtls.New(t)
	plan := testtls.Plan(t, profile.Now)
	previous := profile.Credential(t, device.Binding{DeviceID: plan.DeviceID, OperationID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Generation: 1, Slot: "A"})
	current := profile.Credential(t, plan.Binding())
	server := testtls.HTTP(t, profile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := boundResponse(Request{Plan: plan}, 1)
		response.Retirement = &device.Retirement{OperationID: plan.OperationID, PlanDigest: plan.Digest, Generation: 1, PolicyDurable: true, SessionsTerminated: true, ApplicationAccessDenied: true, TLSObservation: "denied"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	for _, failure := range []error{device.ErrUnknown, device.ErrDenied, nil} {
		client, err := New(Options{ControlURL: "https://lab.known-device.invalid", ApplicationURL: "https://lab.known-device.invalid", ControlRoots: profile.Roots, ApplicationRoots: profile.Roots, ApplicationID: "application-a", ProbeEndpoint: "tls://lab.known-device.invalid:8883", Timeout: time.Second, Now: func() time.Time { return profile.Now }, dialContext: server.DialContext, ProbeTransport: probeFunc(func(_ context.Context, request device.Probe, _ device.Credential) (device.Probe, error) {
			return request, failure
		})})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Retire(context.Background(), plan, previous, current); !errors.Is(err, device.ErrUnknown) {
			t.Fatalf("retirement with %v = %v", failure, err)
		}
	}
}

func TestImportValidatesPublicChainAndRecoveryScope(t *testing.T) {
	profile := testtls.New(t)
	plan := testtls.Plan(t, profile.Now)
	plan.Mode = "recover"
	plan.Digest, _ = plan.CalculateDigest()
	key := testtls.Key(t)
	csr := testtls.CSR(t, device.Subject(plan.DeviceID, plan.TargetGeneration), key)
	_, chain := profile.Sign(t, device.Subject(plan.DeviceID, plan.TargetGeneration), key.Public(), nil)
	recovery := profile.Recovery(t, plan.DeviceID)
	var calls int
	server := testtls.HTTP(t, profile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var request Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if r.URL.Path != "/v1/issue/import" || request.Plan != plan || string(request.CSR) != string(csr) || string(request.Certificate) != string(chain) || r.TLS.PeerCertificates[0].Subject.CommonName != device.RecoverySubject(plan.DeviceID) {
			t.Error("import scope, chain or authentication mismatch")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(boundResponse(request, plan.TargetGeneration))
	}))
	client, err := New(Options{ControlURL: "https://lab.known-device.invalid", ApplicationURL: "https://lab.known-device.invalid", ControlRoots: profile.Roots, ApplicationRoots: profile.Roots, ApplicationID: "application-a", ProbeEndpoint: "tls://lab.known-device.invalid:8883", Timeout: time.Second, Now: func() time.Time { return profile.Now }, dialContext: server.DialContext})
	if err != nil {
		t.Fatal(err)
	}
	request := device.IssueRequest{Plan: plan, CSR: csr, Credential: &recovery}
	if err := client.Import(context.Background(), request, chain); err != nil {
		t.Fatal(err)
	}
	_, wrong := profile.Sign(t, device.Subject(plan.DeviceID, plan.TargetGeneration), testtls.Key(t).Public(), nil)
	if err := client.Import(context.Background(), request, wrong); err == nil {
		t.Fatal("wrong public key reached import")
	}
	if calls != 1 {
		t.Fatal("invalid import made a remote request")
	}
}

func TestApplicationReplayAndControlAbsence(t *testing.T) {
	profile := testtls.New(t)
	plan := testtls.Plan(t, profile.Now)
	target := profile.Credential(t, plan.Binding())
	chain, _ := credentials.PublicChain(target)
	fingerprint, _ := credentials.CertificateFingerprint(chain)
	var controlReads int
	server := testtls.HTTP(t, profile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := boundResponse(Request{Plan: plan}, plan.TargetGeneration)
		if r.URL.Path == "/v1/activate" || r.URL.Path == "/v1/activation" {
			response.Activation = &device.Activation{OperationID: plan.OperationID, PlanDigest: plan.Digest, DeviceID: plan.DeviceID, ApplicationID: "application-a", Generation: plan.TargetGeneration, CertificateFingerprint: fingerprint, Probe: device.Probe{OperationID: plan.OperationID, DeviceID: plan.DeviceID, Generation: plan.TargetGeneration, Endpoint: "tls://lab.known-device.invalid:8883", Nonce: "dddddddddddddddddddddddddddddddd", Deadline: profile.Now.Add(30 * time.Second)}}
		} else if r.URL.Path == "/v1/activation-status" {
			controlReads++
			response.Status = "not-found"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	client, err := New(Options{ControlURL: "https://lab.known-device.invalid", ApplicationURL: "https://lab.known-device.invalid", ControlRoots: profile.Roots, ApplicationRoots: profile.Roots, ApplicationID: "application-a", ProbeEndpoint: "tls://lab.known-device.invalid:8883", Timeout: time.Second, Now: func() time.Time { return profile.Now }, dialContext: server.DialContext})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ActivationStatus(context.Background(), plan, target); !errors.Is(err, device.ErrNotFound) {
		t.Fatalf("missing control activation = %v", err)
	}
	if _, err := client.Activate(context.Background(), plan, target); !errors.Is(err, device.ErrDenied) {
		t.Fatalf("replayed application nonce = %v", err)
	}
	if controlReads != 1 {
		t.Fatal("replay reached a control CAS")
	}
}
