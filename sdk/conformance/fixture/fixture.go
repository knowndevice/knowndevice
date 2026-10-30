// SPDX-License-Identifier: Apache-2.0

// Package fixture supplies generated-data mTLS services for adapter conformance.
// Its registry and counters live in memory. Adapter restart preserves that one
// running backend; no service persistence, real CA integration or hardware claim
// follows from this harness.
package fixture

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/knowndevice/knowndevice/adapters/profilehttp"
	"github.com/knowndevice/knowndevice/sdk/conformance"
	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
	"github.com/knowndevice/knowndevice/sdk/device"
)

// Factory creates a new loopback PKI, identity and in-memory backend per case.
// A process connector must supply its exact ProcessArtifactDigest. An empty
// digest selects the existing native composition. The fixture does not alter
// protocol negotiation, permissions, validation or process confinement.
type Factory struct {
	Connect               conformance.Connector
	ProcessArtifactDigest string
}

// Builtin uses exactly the public HTTP adapter and reviewed system clock.
func Builtin(_ context.Context, snapshot *device.PublicSnapshot) (device.Adapters, func() error, error) {
	c, err := profilehttp.New(snapshot)
	if err != nil {
		return device.Adapters{}, nil, err
	}
	r := c.Roles()
	a := device.Adapters{Entitlement: c, Authority: c, Platform: c, Transport: c, Application: c, Clock: r.Clock, Withdrawal: c}
	return a, func() error { return nil }, a.Validate()
}

type backend struct {
	mu                sync.Mutex
	snapshot          *device.PublicSnapshot
	plan              device.Plan
	previous          device.Credential
	target            device.Credential
	issuers           map[string]*issuer
	servers           []*http.Server
	observation       conformance.Observation
	fault             conformance.Fault
	issueObserved     chan struct{}
	lateObserved      chan struct{}
	release           chan struct{}
	issueOnce         sync.Once
	lateOnce          sync.Once
	releaseOnce       sync.Once
	closeOnce         sync.Once
	issuedAt          time.Time
	registered        bool
	candidateVerified bool
	selected          bool
	activationRev     uint64
	withdrawn         bool
	denial            device.AccessObservation
	instanceID        string
	sessionID         string
	connectionMu      sync.Mutex
	connectionClose   func() error
	connect           conformance.Connector
}

func (f Factory) Open(ctx context.Context, request conformance.Request) (*conformance.Harness, error) {
	policy, err := credentialprofile.Find(request.ProfileID, 1)
	if err != nil {
		return nil, device.ErrUnsupported
	}
	validCase := false
	for _, name := range conformance.Cases() {
		validCase = validCase || name == request.Case
	}
	if !validCase || ctx.Err() != nil {
		return nil, device.ErrUnsupported
	}
	b := &backend{issuers: map[string]*issuer{}, fault: conformance.NoFault, issueObserved: make(chan struct{}), lateObserved: make(chan struct{}), release: make(chan struct{}), connect: f.Connect}
	if b.connect == nil {
		b.connect = Builtin
	}
	ok := false
	defer func() {
		if !ok {
			_ = b.close()
		}
	}()
	identity, err := device.RandomID()
	if err != nil {
		return nil, device.ErrUnknown
	}
	s := &device.PublicSnapshot{APIVersion: device.V2, EncodingVersion: 2, DeviceID: "device-" + identity, DeploymentID: "fixture-" + identity, Profile: policy, Composition: device.Composition{ID: "local-http-lab", Version: 1, AuthorityTemplateDigest: device.Hash([]byte("conformance-in-memory-authority/1")), ApplicationID: "fixture-worker", SessionPolicy: "new-connection-no-state-transfer", ObservationRoute: "authenticated-application-callback", WithdrawalScope: "whole-service-lab"}, Limits: device.DefaultLimits(), RequestTimeoutSeconds: 3, PlanTTLSeconds: 600, ClockTrust: "trusted-system-clock"}
	if f.ProcessArtifactDigest != "" {
		s.Composition.ID = "local-http-process-lab"
		s.Composition.AuthorityLifetimeSeconds = 1200
		s.Composition.ProcessArtifactDigest = f.ProcessArtifactDigest
	}
	for _, role := range []string{"application", "authority", "clock", "entitlement", "platform", "transport", "withdrawal"} {
		capability, _ := device.RequiredCapability(role)
		s.Composition.Adapters = append(s.Composition.Adapters, device.AdapterSpec{Role: role, ID: "local-http-lab-" + role, Version: "1", ArtifactDigest: device.Hash([]byte("conformance-in-memory-backend/1")), Capabilities: []string{capability}})
	}
	for _, role := range []string{"application", "authority-transport", "control", "issuance", "observer", "operational", "recovery", "transport"} {
		i, e := newIssuer(role)
		if e != nil {
			return nil, e
		}
		b.issuers[role] = i
	}
	recovery, err := b.issuers["recovery"].recovery(s.DeviceID)
	if err != nil {
		return nil, err
	}
	s.RecoveryIdentity = device.RecoverySubject(s.DeviceID)
	s.RecoveryLeafPin = device.Hash(recovery.TLS.Certificate[0])
	s.RecoverySPKIPin = device.Hash(recovery.TLS.Leaf.RawSubjectPublicKeyInfo)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(b.issuers["operational"].root)
	clientRoots.AddCert(b.issuers["recovery"].root)
	for _, role := range []string{"application", "authority-transport", "control", "issuance", "observer", "operational", "recovery", "transport"} {
		i := b.issuers[role]
		r := device.RoleSnapshot{Role: role, Anchors: [][]byte{i.root.Raw}, LeafPins: []string{}, SPKIPins: []string{}, AllowedIssuers: []string{}}
		if role == "operational" {
			r.AllowedIssuers = []string{device.Hash(i.root.Raw)}
		} else if role != "recovery" {
			certificate, e := i.server()
			if e != nil {
				return nil, e
			}
			r.LeafPins = []string{device.Hash(certificate.Certificate[0])}
			r.SPKIPins = []string{device.Hash(certificate.Leaf.RawSubjectPublicKeyInfo)}
			r.PeerName = "127.0.0.1"
			if role != "observer" {
				listener, e := net.Listen("tcp4", "127.0.0.1:0")
				if e != nil {
					return nil, device.ErrUnknown
				}
				r.Endpoint = "https://" + listener.Addr().String()
				config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots, SessionTicketsDisabled: true}
				serviceRole := role
				server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { b.serve(serviceRole, w, req) }), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
				b.servers = append(b.servers, server)
				go func() { _ = server.Serve(tls.NewListener(listener, config)) }()
			}
			if role == "issuance" {
				r.CallerLeafPins = []string{device.Hash([]byte("fixture-authority-caller-leaf"))}
				r.CallerSPKIPins = []string{device.Hash([]byte("fixture-authority-caller-spki"))}
			}
		}
		s.Trust = append(s.Trust, r)
	}
	sort.Slice(s.Composition.Adapters, func(i, j int) bool { return s.Composition.Adapters[i].Role < s.Composition.Adapters[j].Role })
	immutable, err := device.DecodeSnapshot(s.Bytes())
	if err != nil {
		return nil, device.ErrUnsupported
	}
	b.snapshot = immutable
	b.plan, err = newPlan(immutable, "rotate", 1, 2, "B")
	if err != nil {
		return nil, err
	}
	previousPlan, err := newPlan(immutable, "enroll", 0, 1, "A")
	if err != nil {
		return nil, err
	}
	b.previous, err = targetVector(previousPlan, policy)
	if err != nil {
		return nil, err
	}
	b.previous.TLS.Certificate, b.previous.TLS.Leaf, err = b.issuers["operational"].issue(policy, previousPlan, b.previous.CSR)
	if err != nil {
		return nil, err
	}
	previous := b.previous
	b.previous.TLS.PrivateKey = nil
	target, err := targetVector(b.plan, policy)
	if err != nil {
		return nil, err
	}
	// The backend receives only the public CSR/handle. The connector keeps the
	// target signer in the host and brokers it to a process per RFC 0006.
	b.target = device.Credential{Handle: target.Handle, CSR: append([]byte(nil), target.CSR...)}
	wrongPolicy := credentialprofile.StableID
	if policy.ID == wrongPolicy {
		wrongPolicy = credentialprofile.ReferenceID
	}
	otherPolicy, _ := credentialprofile.Find(wrongPolicy, 1)
	wrongProfile, err := targetVector(b.plan, otherPolicy)
	if err != nil {
		return nil, err
	}
	wrongProfile.TLS.Certificate, wrongProfile.TLS.Leaf, err = b.issuers["operational"].issue(otherPolicy, b.plan, wrongProfile.CSR)
	if err != nil {
		return nil, err
	}
	wrongTrust, err := targetVector(b.plan, policy)
	if err != nil {
		return nil, err
	}
	wrongIssuer, err := newIssuer("untrusted-operational")
	if err != nil {
		return nil, err
	}
	wrongTrust.TLS.Certificate, wrongTrust.TLS.Leaf, err = wrongIssuer.issue(policy, b.plan, wrongTrust.CSR)
	if err != nil {
		return nil, err
	}
	b.instanceID, err = device.RandomID()
	if err != nil {
		return nil, err
	}
	b.sessionID, err = device.RandomID()
	if err != nil {
		return nil, err
	}
	b.observation.ActiveGeneration = 1
	a, err := b.restart(ctx)
	if err != nil {
		return nil, err
	}
	h := &conformance.Harness{Scope: "in-memory-model", Snapshot: immutable, Plan: b.plan, Previous: previous, Target: target, WrongProfile: wrongProfile, WrongTrust: wrongTrust, Adapters: a, Arm: b.arm, Await: b.await, Release: b.releaseReply, Observe: b.observe, Restart: b.restart, Close: b.close}
	ok = true
	return h, nil
}

func newPlan(s *device.PublicSnapshot, mode string, expected, target uint64, slot string) (device.Plan, error) {
	id, err := device.RandomID()
	if err != nil {
		return device.Plan{}, device.ErrUnknown
	}
	p := device.Plan{APIVersion: device.V2, DigestEncodingVersion: 2, OperationID: id, DeviceID: s.DeviceID, Mode: mode, ExpectedGeneration: expected, TargetGeneration: target, TargetSlot: slot, ConfigDigest: s.Digest(), ExpiresAt: time.Now().UTC().Add(5 * time.Minute), DeploymentID: s.DeploymentID, ProfileID: s.Profile.ID, ProfileVersion: s.Profile.Version, ProfileDigest: s.Profile.PolicyDigest, CompositionDigest: s.Composition.Digest(), SnapshotDigest: s.Digest()}
	for _, field := range []struct {
		role string
		out  *string
	}{{"control", &p.ControlTrustDigest}, {"application", &p.ApplicationTrustDigest}, {"issuance", &p.IssuanceTrustDigest}, {"recovery", &p.RecoveryTrustDigest}, {"transport", &p.TransportTrustDigest}} {
		r, _ := s.Role(field.role)
		*field.out = r.Digest()
	}
	p.Digest, err = p.CalculateDigest()
	if err != nil || p.Validate(time.Now().UTC()) != nil || s.ValidatePlan(p) != nil {
		return device.Plan{}, device.ErrConflict
	}
	return p, nil
}

func (b *backend) arm(fault conformance.Fault) error {
	switch fault {
	case conformance.NoFault, conformance.LostIssueResponse, conformance.LateIssueResponse, conformance.DeniedScope, conformance.StaleGeneration, conformance.LookupUnavailable, conformance.CandidateOnly, conformance.MissingActivationRevision, conformance.MissingFreshObservation, conformance.TLSOnlyRetirement, conformance.MissingSessions, conformance.StaleRetirementTarget:
		b.mu.Lock()
		b.fault = fault
		b.mu.Unlock()
		return nil
	default:
		return device.ErrUnsupported
	}
}

func (b *backend) await(ctx context.Context, effect conformance.Effect) error {
	var ready <-chan struct{}
	switch effect {
	case conformance.IssueEffect:
		ready = b.issueObserved
	case conformance.LateReply:
		ready = b.lateObserved
	default:
		return device.ErrUnsupported
	}
	select {
	case <-ready:
		return nil
	case <-ctx.Done():
		return device.ErrUnknown
	}
}

func (b *backend) releaseReply() error {
	b.releaseOnce.Do(func() { close(b.release) })
	return nil
}

func (b *backend) observe() conformance.Observation {
	b.mu.Lock()
	defer b.mu.Unlock()
	o := b.observation
	o.DeniedGenerations = append([]uint64(nil), o.DeniedGenerations...)
	return o
}

func (b *backend) restart(ctx context.Context) (device.Adapters, error) {
	b.connectionMu.Lock()
	defer b.connectionMu.Unlock()
	if b.connectionClose != nil {
		if err := b.connectionClose(); err != nil {
			return device.Adapters{}, device.ErrUnknown
		}
		b.connectionClose = nil
	}
	snapshot, err := device.DecodeSnapshot(b.snapshot.Bytes())
	if err != nil {
		return device.Adapters{}, device.ErrConflict
	}
	a, closeSession, err := b.connect(ctx, snapshot)
	if err != nil || closeSession == nil || a.Validate() != nil {
		if closeSession != nil {
			_ = closeSession()
		}
		return device.Adapters{}, device.ErrUnsupported
	}
	b.connectionClose = closeSession
	return a, nil
}

func (b *backend) close() error {
	var result error
	b.closeOnce.Do(func() {
		_ = b.releaseReply()
		b.connectionMu.Lock()
		if b.connectionClose != nil {
			result = b.connectionClose()
		}
		b.connectionMu.Unlock()
		for _, server := range b.servers {
			_ = server.Close()
		}
	})
	return result
}
