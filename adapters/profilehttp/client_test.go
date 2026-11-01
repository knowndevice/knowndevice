// SPDX-License-Identifier: Apache-2.0

package profilehttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/adapters/internal/testtls"
	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
	"github.com/knowndevice/knowndevice/sdk/device"
)

func clientFixture(t *testing.T) (*Client, device.Plan, device.Credential, *testtls.Profile) {
	t.Helper()
	policy, _ := credentialprofile.Find(credentialprofile.StableID, 1)
	s := &device.PublicSnapshot{APIVersion: device.V2, EncodingVersion: 2, DeploymentID: "test-deployment", DeviceID: "gateway", Profile: policy, Composition: device.Composition{ID: "local-http-lab", Version: 1, AuthorityTemplateDigest: device.Hash([]byte("template")), ApplicationID: "worker", SessionPolicy: "new-connection-no-state-transfer", ObservationRoute: "authenticated-application-callback", WithdrawalScope: "whole-service-lab"}, Limits: device.DefaultLimits(), RequestTimeoutSeconds: 1, PlanTTLSeconds: 600, ClockTrust: "trusted-system-clock", RecoveryIdentity: device.RecoverySubject("gateway")}
	caps := map[string]string{"application": "durable-activation-and-fresh-observation", "authority": "bounded-unknown-issuance", "clock": "bounded-interval", "entitlement": "current-entitlement", "platform": "exact-peer-binding", "transport": "explicit-access-observation", "withdrawal": "durable-deny-and-session-inventory"}
	for role, cap := range caps {
		s.Composition.Adapters = append(s.Composition.Adapters, device.AdapterSpec{Role: role, ID: "local-http-lab-" + role, Version: "1", ArtifactDigest: device.Hash([]byte("artifact")), Capabilities: []string{cap}})
	}
	sort.Slice(s.Composition.Adapters, func(i, j int) bool { return s.Composition.Adapters[i].Role < s.Composition.Adapters[j].Role })
	var recovery device.Credential
	var server *testtls.Profile
	for _, role := range []string{"application", "authority-transport", "control", "issuance", "observer", "operational", "recovery", "transport"} {
		p := testtls.New(t)
		r := device.RoleSnapshot{Role: role, Anchors: [][]byte{p.Root.Raw}, LeafPins: []string{}, SPKIPins: []string{}, AllowedIssuers: []string{}}
		switch role {
		case "recovery":
			recovery = p.Recovery(t, "gateway")
			s.RecoveryLeafPin = device.Hash(recovery.TLS.Certificate[0])
			s.RecoverySPKIPin = device.Hash(recovery.TLS.Leaf.RawSubjectPublicKeyInfo)
		case "operational":
			r.AllowedIssuers = []string{device.Hash(p.Root.Raw)}
		default:
			r.Endpoint = "https://lab.known-device.invalid"
			r.PeerName = "lab.known-device.invalid"
			r.LeafPins = []string{device.Hash(p.Server.Certificate[0])}
			r.SPKIPins = []string{device.Hash(p.Server.Leaf.RawSubjectPublicKeyInfo)}
			if role == "control" {
				server = p
			}
			if role == "observer" {
				r.Endpoint = ""
			}
			if role == "issuance" {
				r.CallerLeafPins = []string{device.Hash([]byte("authority leaf"))}
				r.CallerSPKIPins = []string{device.Hash([]byte("authority key"))}
			}
		}
		s.Trust = append(s.Trust, r)
	}
	c, e := New(s)
	if e != nil {
		t.Fatal(e)
	}
	p := device.Plan{APIVersion: device.V2, DigestEncodingVersion: 2, DeploymentID: s.DeploymentID, DeviceID: s.DeviceID, OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Mode: "enroll", TargetGeneration: 1, TargetSlot: "A", ConfigDigest: s.Digest(), SnapshotDigest: s.Digest(), ProfileID: s.Profile.ID, ProfileVersion: s.Profile.Version, ProfileDigest: s.Profile.PolicyDigest, CompositionDigest: s.Composition.Digest(), ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	for _, x := range []struct {
		role  string
		value *string
	}{{"control", &p.ControlTrustDigest}, {"application", &p.ApplicationTrustDigest}, {"issuance", &p.IssuanceTrustDigest}, {"recovery", &p.RecoveryTrustDigest}, {"transport", &p.TransportTrustDigest}} {
		r, _ := s.Role(x.role)
		*x.value = r.Digest()
	}
	p.Digest, _ = p.CalculateDigest()
	if e = p.Validate(time.Now()); e != nil {
		t.Fatal(e)
	}
	return c, p, recovery, server
}

type shiftedClock struct{ offset atomic.Int64 }

func (c *shiftedClock) Assess(context.Context, time.Time) (device.ClockAssessment, error) {
	now := time.Now()
	sample := now.Add(time.Duration(c.offset.Load()))
	return device.ClockAssessment{Earliest: sample.Add(-time.Second), Latest: sample.Add(time.Second), AssessedAt: now, MaximumAge: 10 * time.Second, Trusted: true, Source: "trusted-system-clock"}, nil
}

func TestP17FreshIntervalAtTLSHandshakeAndAfterResponse(t *testing.T) {
	for _, phase := range []string{"dial", "response"} {
		t.Run(phase, func(t *testing.T) {
			c, p, k, server := clientFixture(t)
			clock := &shiftedClock{}
			c.clock = clock
			key := testtls.Key(t)
			leaf, _ := server.Sign(t, "lab.known-device.invalid", key.Public(), func(cert *x509.Certificate) {
				cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				cert.NotAfter = time.Now().Add(10 * time.Second)
			})
			server.Server = tls.Certificate{Certificate: [][]byte{leaf.Raw, server.Root.Raw}, PrivateKey: key, Leaf: leaf}
			for i := range c.snapshot.Trust {
				if c.snapshot.Trust[i].Role == "control" {
					c.snapshot.Trust[i].LeafPins = []string{device.Hash(leaf.Raw)}
					c.snapshot.Trust[i].SPKIPins = []string{device.Hash(leaf.RawSubjectPublicKeyInfo)}
					p.SnapshotDigest = c.snapshot.Digest()
					p.ConfigDigest = p.SnapshotDigest
					p.ControlTrustDigest = c.snapshot.Trust[i].Digest()
				}
			}
			p.Digest, _ = p.CalculateDigest()
			var requests atomic.Int64
			listener := testtls.HTTPWithClientAuth(t, server, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				var in device.RoleRequest
				_ = json.NewDecoder(r.Body).Decode(&in)
				if phase == "response" {
					clock.offset.Store(int64(9400 * time.Millisecond))
				}
				v := device.Evidence{APIVersion: device.V2, Role: "entitlement", Action: "entitlement", RequestID: in.RequestID, Plan: in.Plan, Revision: 1, Reference: in.Plan.OperationID, Source: device.Hash(leaf.Raw), ObservedAt: time.Now().UTC(), Deadline: in.Plan.ExpiresAt, Status: "authorized"}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(device.RoleResponse{Status: "authorized", Evidence: &v})
			}), tls.NoClientCert)
			c.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				if phase == "dial" {
					clock.offset.Store(int64(9400 * time.Millisecond))
				}
				return listener.DialContext(ctx, network, address)
			}
			_, e := c.post(context.Background(), "control", "/entitlement", &k, device.RoleRequest{Plan: p}, false)
			if !errors.Is(e, device.ErrUnknown) {
				t.Fatalf("expired assessed server interval at %s accepted: %v", phase, e)
			}
			want := int64(0)
			if phase == "response" {
				want = 1
			}
			if requests.Load() != want {
				t.Fatalf("requests=%d, want %d; no retry or pre-validation send", requests.Load(), want)
			}
		})
	}
}

func TestP7P8DelayedImportRequiresOriginalAuthenticatedIssuanceInterval(t *testing.T) {
	for _, variant := range []string{"valid-delayed", "wrong-original-time", "unbounded-original-time", "wrong-CSR-binding"} {
		t.Run(variant, func(t *testing.T) {
			c, p, auth, server := clientFixture(t)
			issuer := testtls.New(t)
			for i := range c.snapshot.Trust {
				if c.snapshot.Trust[i].Role == "operational" {
					c.snapshot.Trust[i].Anchors = [][]byte{issuer.Root.Raw}
					c.snapshot.Trust[i].AllowedIssuers = []string{device.Hash(issuer.Root.Raw)}
				}
			}
			p.SnapshotDigest, p.ConfigDigest = c.snapshot.Digest(), c.snapshot.Digest()
			p.Digest, _ = p.CalculateDigest()
			key := testtls.Key(t)
			csr, err := c.snapshot.Profile.CreateCSR(key, p.DeviceID, p.TargetGeneration)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := c.snapshot.Profile.ValidateCSR(csr, p.DeviceID, p.TargetGeneration)
			if err != nil {
				t.Fatal(err)
			}
			issued := time.Now().UTC().Add(-time.Minute)
			leaf, chain := issuer.Sign(t, p.DeviceID, key.Public(), func(cert *x509.Certificate) {
				cert.DNSNames = nil
				cert.NotBefore, cert.NotAfter = issued.Add(-30*time.Second), issued.Add(1170*time.Second)
			})
			binding := device.CredentialBinding{DeploymentID: p.DeploymentID, DeviceID: p.DeviceID, OperationID: p.OperationID, PlanDigest: p.Digest, ConfigDigest: p.ConfigDigest, SnapshotDigest: p.SnapshotDigest, ProfileID: p.ProfileID, ProfileVersion: p.ProfileVersion, ProfileDigest: p.ProfileDigest, Generation: p.TargetGeneration, PublicKeyDigest: device.Hash(parsed.RawSubjectPublicKeyInfo), CertificateFingerprint: device.Hash(leaf.Raw), CSRDigest: device.Hash(parsed.Raw)}
			var requests atomic.Int64
			listener := testtls.HTTPWithClientAuth(t, server, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/import" {
					t.Error("import requested another issuance action")
				}
				var in device.RoleRequest
				_ = json.NewDecoder(r.Body).Decode(&in)
				role, _ := c.snapshot.Role("control")
				v := device.Evidence{APIVersion: device.V2, Role: "authority", Action: "import", RequestID: in.RequestID, Plan: in.Plan, Subject: binding, Revision: 1, Reference: in.Plan.OperationID, Source: role.LeafPins[0], ObservedAt: time.Now().UTC(), Deadline: in.Plan.ExpiresAt, Status: "ok", IssuanceEarliest: issued.Add(-time.Second), IssuanceLatest: issued.Add(time.Second)}
				switch variant {
				case "wrong-original-time":
					v.IssuanceEarliest, v.IssuanceLatest = time.Now().Add(-time.Second), time.Now().Add(time.Second)
				case "unbounded-original-time":
					v.IssuanceEarliest = issued.Add(-time.Minute)
				case "wrong-CSR-binding":
					v.Subject.CSRDigest = device.Hash([]byte("another CSR"))
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(device.RoleResponse{Status: "ok", Certificate: chain, Evidence: &v})
			}), tls.NoClientCert)
			c.dial = listener.DialContext
			err = c.Import(context.Background(), device.IssueRequest{Plan: p, CSR: csr, Credential: &auth}, chain)
			if variant == "valid-delayed" && err != nil {
				t.Fatalf("valid original issuance interval rejected after delay: %v", err)
			}
			if variant != "valid-delayed" && !errors.Is(err, device.ErrUnknown) {
				t.Fatalf("unbound issuance evidence accepted: %v", err)
			}
			if requests.Load() != 1 {
				t.Fatalf("requests=%d, want one import and no issuance retry", requests.Load())
			}
		})
	}
}

func TestP4PinnedRolesCannotIgnoreApprovedIssuer(t *testing.T) {
	for _, role := range []string{"control", "recovery"} {
		t.Run(role, func(t *testing.T) {
			c, p, k, server := clientFixture(t)
			for i := range c.snapshot.Trust {
				if c.snapshot.Trust[i].Role == role {
					c.snapshot.Trust[i].AllowedIssuers = []string{device.Hash([]byte("another issuer"))}
					if role == "control" {
						p.ControlTrustDigest = c.snapshot.Trust[i].Digest()
					} else {
						p.RecoveryTrustDigest = c.snapshot.Trust[i].Digest()
					}
				}
			}
			p.SnapshotDigest, p.ConfigDigest = c.snapshot.Digest(), c.snapshot.Digest()
			p.Digest, _ = p.CalculateDigest()
			var requests atomic.Int64
			listener := testtls.HTTPWithClientAuth(t, server, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
			}), tls.NoClientCert)
			c.dial = listener.DialContext
			_, err := c.post(context.Background(), "control", "/entitlement", &k, device.RoleRequest{Plan: p}, false)
			want := device.ErrUnknown
			if role == "recovery" {
				want = device.ErrDenied
			}
			if !errors.Is(err, want) || requests.Load() != 0 {
				t.Fatalf("approved issuer was ignored for pinned %s role: %v; requests=%d", role, err, requests.Load())
			}
		})
	}
}
func TestP16GenericDenialAndSocketLossRemainUnknown(t *testing.T) {
	for _, name := range []string{"generic-denial", "closed-socket", "blackhole", "wrong-role-server", "wrong-source", "valid-bound-decision"} {
		t.Run(name, func(t *testing.T) {
			c, p, k, server := clientFixture(t)
			switch name {
			case "closed-socket":
				c.dial = func(context.Context, string, string) (net.Conn, error) {
					a, b := net.Pipe()
					_ = b.Close()
					return a, nil
				}
			case "blackhole":
				c.dial = func(context.Context, string, string) (net.Conn, error) {
					a, b := net.Pipe()
					t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
					return a, nil
				}
			default:
				if name == "wrong-role-server" {
					server = testtls.New(t)
				}
				listener := testtls.HTTPWithClientAuth(t, server, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var in device.RoleRequest
					_ = json.NewDecoder(r.Body).Decode(&in)
					response := device.RoleResponse{Status: "denied"}
					if name == "valid-bound-decision" || name == "wrong-source" {
						role, _ := c.snapshot.Role("control")
						source := role.LeafPins[0]
						if name == "wrong-source" {
							source = device.Hash([]byte("device self ACK"))
						}
						response.Evidence = &device.Evidence{APIVersion: device.V2, Role: "entitlement", Action: "entitlement", RequestID: in.RequestID, Plan: in.Plan, Revision: 1, Reference: in.Plan.OperationID, Source: source, ObservedAt: time.Now().UTC(), Deadline: in.Plan.ExpiresAt, Status: "denied"}
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(response)
				}), tls.NoClientCert)
				c.dial = listener.DialContext
			}
			_, e := c.post(context.Background(), "control", "/entitlement", &k, device.RoleRequest{Plan: p}, false)
			want := device.ErrUnknown
			if name == "valid-bound-decision" {
				want = device.ErrDenied
			}
			if !errors.Is(e, want) {
				t.Fatalf("%s result=%v, want %v", name, e, want)
			}
		})
	}
}

func TestLocalProfileRefusalsAreDeniedBeforeNetwork(t *testing.T) {
	for _, name := range []string{"wrong-issuer", "wrong-credential-profile", "wrong-csr", "wrong-import-csr"} {
		t.Run(name, func(t *testing.T) {
			c, p, recovery, _ := clientFixture(t)
			var dials atomic.Int64
			c.dial = func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("network must not be reached")
			}
			var err error
			if name == "wrong-issuer" || name == "wrong-credential-profile" {
				issuer := testtls.New(t)
				key := testtls.Key(t)
				subject := p.DeviceID
				if name == "wrong-credential-profile" {
					subject = device.Subject(p.DeviceID, p.TargetGeneration)
				}
				leaf, _ := issuer.Sign(t, subject, key.Public(), func(cert *x509.Certificate) {
					if name == "wrong-issuer" {
						cert.DNSNames = nil
					}
					cert.NotBefore = time.Now().Add(-30 * time.Second)
					cert.NotAfter = time.Now().Add(1170 * time.Second)
				})
				credential := device.Credential{Handle: device.Handle{Binding: p.Binding(), PublicKeyDigest: device.Hash(leaf.RawSubjectPublicKeyInfo)}, TLS: tls.Certificate{Certificate: [][]byte{leaf.Raw, issuer.Root.Raw}, PrivateKey: key, Leaf: leaf}}
				err = c.Register(context.Background(), p, credential)
			} else {
				other, _ := credentialprofile.Find(credentialprofile.ReferenceID, 1)
				csr, createErr := other.CreateCSR(testtls.Key(t), p.DeviceID, p.TargetGeneration)
				if createErr != nil {
					t.Fatal(createErr)
				}
				request := device.IssueRequest{Plan: p, CSR: csr, Credential: &recovery}
				if name == "wrong-csr" {
					_, err = c.Issue(context.Background(), request)
				} else {
					err = c.Import(context.Background(), request, []byte("invalid public chain"))
				}
			}
			if !errors.Is(err, device.ErrDenied) || dials.Load() != 0 || err.Error() != device.ErrDenied.Error() {
				t.Fatalf("policy refusal=%v; outbound dials=%d", err, dials.Load())
			}
		})
	}
}

func pipeRoleResponse(t *testing.T, c *Client, certificate tls.Certificate, reply func(device.RoleRequest) device.RoleResponse) *atomic.Int64 {
	t.Helper()
	requests := &atomic.Int64{}
	roots, err := c.snapshot.Roots("recovery")
	if err != nil {
		t.Fatal(err)
	}
	c.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		client, peer := net.Pipe()
		deadline := time.Now().Add(2 * time.Second)
		if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
			deadline = bound
		}
		_ = client.SetDeadline(deadline)
		_ = peer.SetDeadline(deadline)
		t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
		go func() {
			server := tls.Server(peer, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, SessionTicketsDisabled: true})
			defer server.Close()
			if server.HandshakeContext(ctx) != nil {
				return
			}
			req, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			defer req.Body.Close()
			var in device.RoleRequest
			if device.DecodeStrict(req.Body, &in) != nil {
				return
			}
			requests.Add(1)
			data, err := json.Marshal(reply(in))
			if err != nil {
				return
			}
			response := &http.Response{StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": []string{"application/json"}}, ContentLength: int64(len(data)), Body: io.NopCloser(bytes.NewReader(data)), Close: true}
			_ = response.Write(server)
		}()
		return client, nil
	}
	return requests
}

func TestAuthenticatedRoleResponsesRequireMatchingDecisions(t *testing.T) {
	cases := []struct {
		name, path, role, status, evidenceStatus string
		want                                     error
	}{
		{"native-entitlement", "/entitlement", "entitlement", "ok", "ok", nil},
		{"fixture-entitlement", "/entitlement", "entitlement", "authorized", "authorized", nil},
		{"wrong-entitlement-role", "/entitlement", "authority", "authorized", "authorized", device.ErrUnknown},
		{"denied-entitlement-proof", "/entitlement", "entitlement", "authorized", "denied", device.ErrUnknown},
		{"unrelated-entitlement-success", "/entitlement", "entitlement", "issued", "issued", device.ErrUnknown},
		{"native-issuance", "/issue", "authority", "ok", "ok", nil},
		{"fixture-issuance", "/issue", "authority", "issued", "issued", nil},
		{"mutation-cannot-prove-absence", "/issue", "authority", "not-started", "not-started", device.ErrUnknown},
		{"exact-lookup-absence", "/lookup", "authority", "not-started", "not-started", device.ErrNotFound},
		{"wrong-lookup-role", "/lookup", "platform", "not-started", "not-started", device.ErrUnknown},
		{"issued-lookup-proof", "/lookup", "authority", "not-started", "issued", device.ErrUnknown},
		{"unbound-lookup-not-found", "/lookup", "authority", "not-found", "not-found", device.ErrUnknown},
		{"native-registration", "/registration", "platform", "ok", "ok", nil},
		{"fixture-registration", "/registration", "platform", "registered", "registered", nil},
		{"wrong-registration-role", "/registration", "authority", "registered", "registered", device.ErrUnknown},
		{"contradictory-registration", "/registration", "platform", "registered", "denied", device.ErrUnknown},
		{"native-application-switch", "/activate", "application", "ok", "completed", nil},
		{"native-control-activation", "/activate", "application", "ok", "ok", nil},
		{"fixture-activation", "/activate", "application", "activated", "activated", nil},
		{"native-withdrawal", "/withdrawal-status", "withdrawal", "ok", "ok", nil},
		{"fixture-withdrawal", "/withdrawal-status", "withdrawal", "withdrawn", "withdrawn", nil},
		{"native-revocation", "/revocation-status", "authority", "ok", "ok", nil},
		{"fixture-revocation", "/revocation-status", "authority", "revoked", "revoked", nil},
		{"native-access", "/challenge", "transport", "ok", "accepted", nil},
		{"fixture-access", "/challenge", "transport", "completed", "completed", nil},
		{"wrong-access-role", "/challenge", "application", "ok", "accepted", device.ErrUnknown},
		{"denied-access-proof", "/challenge", "transport", "ok", "denied", device.ErrUnknown},
		{"unrelated-access-success", "/challenge", "transport", "revoked", "revoked", device.ErrUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p, k, server := clientFixture(t)
			requests := pipeRoleResponse(t, c, server.Server, func(in device.RoleRequest) device.RoleResponse {
				role, _ := c.snapshot.Role("control")
				v := device.Evidence{APIVersion: device.V2, Role: tc.role, Action: tc.path[1:], RequestID: in.RequestID, Plan: in.Plan, Revision: 1, Reference: in.Plan.OperationID, Source: role.LeafPins[0], ObservedAt: time.Now().UTC(), Deadline: in.Plan.ExpiresAt, Status: tc.evidenceStatus}
				return device.RoleResponse{Status: tc.status, Evidence: &v}
			})
			var err error
			switch tc.path {
			case "/entitlement":
				err = c.Authorize(context.Background(), p, &k)
			case "/lookup":
				csr, createErr := c.snapshot.Profile.CreateCSR(testtls.Key(t), p.DeviceID, p.TargetGeneration)
				if createErr != nil {
					t.Fatal(createErr)
				}
				_, err = c.Lookup(context.Background(), device.IssueRequest{Plan: p, Credential: &k, CSR: csr})
			default:
				_, err = c.post(context.Background(), "control", tc.path, &k, device.RoleRequest{Plan: p}, false)
			}
			if !errors.Is(err, tc.want) || requests.Load() != 1 {
				t.Fatalf("decision=%v, want=%v; authenticated requests=%d", err, tc.want, requests.Load())
			}
		})
	}
}
