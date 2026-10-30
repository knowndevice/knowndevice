// SPDX-License-Identifier: Apache-2.0

package stepca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/adapters/internal/testtls"
	"github.com/knowndevice/knowndevice/sdk/device"
)

func TestSignAndRevokeActualPayloads(t *testing.T) {
	profile := testtls.New(t)
	plan := testtls.Plan(t, profile.Now)
	key := testtls.Key(t)
	csr := testtls.CSR(t, device.Subject(plan.DeviceID, plan.TargetGeneration), key)
	credential := profile.Credential(t, device.Binding{DeviceID: plan.DeviceID, OperationID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Generation: plan.ExpectedGeneration, Slot: "A"})
	current := profile.Credential(t, plan.Binding())
	leaf, chain := profile.Sign(t, device.Subject(plan.DeviceID, plan.TargetGeneration), key.Public(), nil)
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: profile.Root.Raw}))
	var signs, revokes atomic.Int32
	server := testtls.HTTP(t, profile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/sign":
			signs.Add(1)
			var input signRequest
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.CSR != string(csr) || input.OTT != "scoped-in-memory-token" {
				t.Error("incorrect /sign payload")
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(signResponse{Certificate: leafPEM, CA: caPEM, Chain: []string{leafPEM, caPEM}})
		case "/revoke":
			revokes.Add(1)
			var input struct {
				Serial     string `json:"serial"`
				OTT        string `json:"ott"`
				ReasonCode int    `json:"reasonCode"`
				Reason     string `json:"reason"`
				Passive    bool   `json:"passive"`
			}
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&input); err != nil {
				t.Error(err)
			}
			previous, _ := x509.ParseCertificate(credential.TLS.Certificate[0])
			if input.Serial != previous.SerialNumber.String() || input.OTT != "scoped-in-memory-token" || !input.Passive || input.ReasonCode != 4 {
				t.Error("incorrect /revoke payload")
			}
			fmt.Fprint(w, "{\"status\":\"ok\"}")
		default:
			t.Error("unexpected endpoint")
			w.WriteHeader(404)
		}
	}))
	client, err := New(Options{URL: "https://lab.known-device.invalid", Roots: profile.Roots, Timeout: time.Second, Now: func() time.Time { return profile.Now }, dialContext: server.DialContext, TokenProvider: func(_ context.Context, scope TokenRequest) (string, error) {
		if scope.Plan != plan {
			t.Error("token scope lost the plan")
		}
		if scope.Purpose == "sign" && string(scope.CSR) != string(csr) {
			t.Error("token scope lost the CSR")
		}
		if scope.Purpose == "revoke" && scope.Serial == "" {
			t.Error("token scope lost the serial")
		}
		return "scoped-in-memory-token", nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Issue(context.Background(), device.IssueRequest{Plan: plan, CSR: csr, Credential: &credential})
	if err != nil || string(result) != string(chain) {
		t.Fatalf("issue error = %v", err)
	}
	if err := client.Revoke(context.Background(), plan, credential, current); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Lookup(context.Background(), device.IssueRequest{Plan: plan, CSR: csr}); !errors.Is(err, device.ErrUnknown) {
		t.Fatalf("lookup = %v", err)
	}
	if err := client.RevocationStatus(context.Background(), plan, credential, current); !errors.Is(err, device.ErrUnknown) {
		t.Fatalf("revocation status = %v", err)
	}
	if signs.Load() != 1 || revokes.Load() != 1 {
		t.Fatal("status lookup made an unsupported CA call")
	}
}

func TestLostIssuanceAndRemoteErrorsStayUnknown(t *testing.T) {
	for _, behavior := range []string{"lost", "malformed", "oversized", "server-error", "issued-forbidden", "wrong-chain"} {
		t.Run(behavior, func(t *testing.T) {
			profile := testtls.New(t)
			plan := testtls.Plan(t, profile.Now)
			plan.Mode = "recover"
			plan.Digest, _ = plan.CalculateDigest()
			credential := profile.Recovery(t, plan.DeviceID)
			key := testtls.Key(t)
			csr := testtls.CSR(t, device.Subject(plan.DeviceID, plan.TargetGeneration), key)
			var calls atomic.Int32
			var issued atomic.Bool
			server := testtls.HTTP(t, profile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch behavior {
				case "lost":
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					connection.Close()
				case "malformed":
					fmt.Fprint(w, "private-key-secret-token")
				case "oversized":
					fmt.Fprint(w, strings.Repeat("private-key-secret-token", 20000))
				case "server-error":
					w.WriteHeader(500)
					fmt.Fprint(w, "private-key-secret-token")
				case "issued-forbidden":
					profile.Sign(t, device.Subject(plan.DeviceID, plan.TargetGeneration), key.Public(), nil)
					issued.Store(true)
					w.WriteHeader(403)
					fmt.Fprint(w, "private-key-secret-token")
				case "wrong-chain":
					_, chain := profile.Sign(t, device.Subject(plan.DeviceID, 1), key.Public(), nil)
					_ = json.NewEncoder(w).Encode(signResponse{Certificate: string(chain)})
				}
			}))
			client, err := New(Options{URL: "https://lab.known-device.invalid", Roots: profile.Roots, Timeout: time.Second, Now: func() time.Time { return profile.Now }, dialContext: server.DialContext, TokenProvider: func(context.Context, TokenRequest) (string, error) { return "private-key-secret-token", nil }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Issue(context.Background(), device.IssueRequest{Plan: plan, CSR: csr, Credential: &credential})
			if !errors.Is(err, device.ErrUnknown) {
				t.Fatalf("uncertain issue = %v", err)
			}
			if strings.Contains(err.Error(), "private-key-secret-token") {
				t.Fatal("token or raw response leaked")
			}
			if calls.Load() != 1 {
				t.Fatal("uncertain issuance was retried")
			}
			if behavior == "issued-forbidden" && !issued.Load() {
				t.Fatal("regression peer did not issue before refusing the response")
			}
		})
	}
}

func TestTokenProviderErrorRedactionAndBadCSR(t *testing.T) {
	profile := testtls.New(t)
	plan := testtls.Plan(t, profile.Now)
	client, err := New(Options{URL: "https://lab.known-device.invalid", Roots: profile.Roots, Timeout: time.Second, Now: func() time.Time { return profile.Now }, TokenProvider: func(context.Context, TokenRequest) (string, error) {
		return "", fmt.Errorf("secret OTT: %w", device.ErrDenied)
	}})
	if err != nil {
		t.Fatal(err)
	}
	csr := testtls.CSR(t, device.Subject(plan.DeviceID, plan.TargetGeneration), testtls.Key(t))
	_, err = client.Issue(context.Background(), device.IssueRequest{Plan: plan, CSR: csr})
	if !errors.Is(err, device.ErrDenied) || strings.Contains(err.Error(), "secret OTT") {
		t.Fatalf("token provider error = %v", err)
	}
	_, err = client.Issue(context.Background(), device.IssueRequest{Plan: plan, CSR: []byte("invalid")})
	if err == nil {
		t.Fatal("invalid CSR reached token issuance")
	}
}

func TestPublicRevokeUsesScopedTokenWithoutDeviceSigner(t *testing.T) {
	profile := testtls.New(t)
	plan := testtls.Plan(t, profile.Now)
	leaf, chain := profile.Sign(t, device.Subject(plan.DeviceID, plan.ExpectedGeneration), testtls.Key(t).Public(), func(c *x509.Certificate) {
		c.NotBefore = profile.Now.Add(-5 * time.Minute)
		c.NotAfter = profile.Now.Add(-4 * time.Minute)
	})
	var calls atomic.Int32
	server := testtls.HTTPWithClientAuth(t, profile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if len(r.TLS.PeerCertificates) != 0 {
			t.Error("control service invented a device signer")
		}
		var input struct {
			Serial     string `json:"serial"`
			OTT        string `json:"ott"`
			ReasonCode int    `json:"reasonCode"`
			Reason     string `json:"reason"`
			Passive    bool   `json:"passive"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		if r.URL.Path != "/revoke" || input.Serial != leaf.SerialNumber.String() || input.OTT != "scope-token" || !input.Passive {
			t.Error("public revocation payload mismatch")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{\"status\":\"ok\"}")
	}), tls.VerifyClientCertIfGiven)
	client, err := New(Options{URL: "https://lab.known-device.invalid", Roots: profile.Roots, Timeout: time.Second, Now: func() time.Time { return profile.Now }, dialContext: server.DialContext, TokenProvider: func(_ context.Context, request TokenRequest) (string, error) {
		if request.Purpose != "revoke" || request.Plan != plan || request.Serial != leaf.SerialNumber.String() {
			t.Error("public revocation token scope mismatch")
		}
		return "scope-token", nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RevokeCertificate(context.Background(), plan, chain); err != nil {
		t.Fatal(err)
	}
	_, wrong := profile.Sign(t, device.Subject(plan.DeviceID, 2), testtls.Key(t).Public(), nil)
	if err := client.RevokeCertificate(context.Background(), plan, wrong); !errors.Is(err, device.ErrDenied) {
		t.Fatalf("wrong public generation = %v", err)
	}
	_, foreign := testtls.New(t).Sign(t, device.Subject(plan.DeviceID, 1), testtls.Key(t).Public(), nil)
	if err := client.RevokeCertificate(context.Background(), plan, foreign); !errors.Is(err, device.ErrDenied) {
		t.Fatalf("foreign public issuer = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("invalid public revocation reached the CA")
	}
}
