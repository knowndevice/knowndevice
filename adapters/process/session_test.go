// SPDX-License-Identifier: Apache-2.0

package process

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"knowndevice.local/knowndevice/adapters/internal/testtls"
	"knowndevice.local/knowndevice/sdk/credentialprofile"
	"knowndevice.local/knowndevice/sdk/device"
)

func fixture(t *testing.T, pin, profile string) (*device.PublicSnapshot, device.Plan, device.Credential, device.Credential) {
	s, p, recovery, target, _ := fixtureWithIssuer(t, pin, profile)
	return s, p, recovery, target
}

func fixtureWithIssuer(t *testing.T, pin, profile string) (*device.PublicSnapshot, device.Plan, device.Credential, device.Credential, *testtls.Profile) {
	t.Helper()
	policy, err := credentialprofile.Find(profile, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := &device.PublicSnapshot{APIVersion: device.V2, EncodingVersion: 2, DeploymentID: "fixture-deployment", DeviceID: "gateway", Profile: policy, Composition: device.Composition{ID: "local-http-process-lab", Version: 1, AuthorityTemplateDigest: device.Hash([]byte("fixture-template")), AuthorityLifetimeSeconds: 1200, ProcessArtifactDigest: pin, ApplicationID: "fixture-worker", SessionPolicy: "new-connection-no-state-transfer", ObservationRoute: "authenticated-application-callback", WithdrawalScope: "whole-service-lab"}, Limits: device.DefaultLimits(), RequestTimeoutSeconds: 1, PlanTTLSeconds: 600, ClockTrust: "trusted-system-clock", RecoveryIdentity: device.RecoverySubject("gateway")}
	for _, role := range []string{"application", "authority", "clock", "entitlement", "platform", "transport", "withdrawal"} {
		capability, _ := device.RequiredCapability(role)
		s.Composition.Adapters = append(s.Composition.Adapters, device.AdapterSpec{Role: role, ID: "local-http-lab-" + role, Version: "1", ArtifactDigest: device.Hash([]byte("fixture-backend")), Capabilities: []string{capability}})
	}
	var recovery device.Credential
	var operational *testtls.Profile
	for _, name := range []string{"application", "authority-transport", "control", "issuance", "observer", "operational", "recovery", "transport"} {
		p := testtls.New(t)
		r := device.RoleSnapshot{Role: name, Anchors: [][]byte{p.Root.Raw}, LeafPins: []string{}, SPKIPins: []string{}, AllowedIssuers: []string{}}
		switch name {
		case "operational":
			r.AllowedIssuers = []string{device.Hash(p.Root.Raw)}
			operational = p
		case "recovery":
			recovery = p.Recovery(t, s.DeviceID)
			s.RecoveryLeafPin = device.Hash(recovery.TLS.Certificate[0])
			s.RecoverySPKIPin = device.Hash(recovery.TLS.Leaf.RawSubjectPublicKeyInfo)
		default:
			r.Endpoint = "https://fixture.known-device.invalid"
			r.PeerName = "fixture.known-device.invalid"
			r.LeafPins = []string{device.Hash(p.Server.Certificate[0])}
			r.SPKIPins = []string{device.Hash(p.Server.Leaf.RawSubjectPublicKeyInfo)}
			if name == "observer" {
				r.Endpoint = ""
			}
			if name == "issuance" {
				r.CallerLeafPins = []string{device.Hash([]byte("fixture-issuer-leaf"))}
			}
		}
		s.Trust = append(s.Trust, r)
	}
	if s.Validate() != nil {
		t.Fatal("invalid fixture snapshot")
	}
	p := device.Plan{APIVersion: device.V2, DigestEncodingVersion: 2, DeploymentID: s.DeploymentID, DeviceID: s.DeviceID, OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Mode: "enroll", TargetGeneration: 1, TargetSlot: "A", ConfigDigest: s.Digest(), SnapshotDigest: s.Digest(), ProfileID: s.Profile.ID, ProfileVersion: s.Profile.Version, ProfileDigest: s.Profile.PolicyDigest, CompositionDigest: s.Composition.Digest(), ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	for _, field := range []struct {
		role   string
		digest *string
	}{{"control", &p.ControlTrustDigest}, {"application", &p.ApplicationTrustDigest}, {"issuance", &p.IssuanceTrustDigest}, {"recovery", &p.RecoveryTrustDigest}, {"transport", &p.TransportTrustDigest}} {
		r, _ := s.Role(field.role)
		*field.digest = r.Digest()
	}
	p.Digest, _ = p.CalculateDigest()
	if err = p.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	key := testtls.Key(t)
	csr, err := policy.CreateCSR(key, p.DeviceID, p.TargetGeneration)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := operational.Sign(t, policy.Subject(p.DeviceID, p.TargetGeneration), key.Public(), func(cert *x509.Certificate) {
		cert.NotBefore = time.Now().Add(-30 * time.Second)
		cert.NotAfter = time.Now().Add(1170 * time.Second)
		if profile == credentialprofile.StableID {
			cert.DNSNames = nil
		}
	})
	target := device.Credential{Handle: device.Handle{Binding: p.Binding(), PublicKeyDigest: device.Hash(leaf.RawSubjectPublicKeyInfo)}, TLS: recovery.TLS, CSR: csr}
	target.TLS.Certificate = [][]byte{leaf.Raw, operational.Root.Raw}
	target.TLS.PrivateKey = key
	target.TLS.Leaf = leaf
	target.Recovery = false
	target.DeviceID = ""
	return s, p, recovery, target, operational
}

func rotateFixture(t *testing.T, pin, profile string) (*device.PublicSnapshot, device.Plan, device.Credential, device.Credential) {
	s, p, _, old, issuer := fixtureWithIssuer(t, pin, profile)
	p.Mode = "rotate"
	p.OperationID = strings.Repeat("b", 32)
	p.ExpectedGeneration = 1
	p.TargetGeneration = 2
	p.TargetSlot = "B"
	p.Digest, _ = p.CalculateDigest()
	key := testtls.Key(t)
	csr, err := s.Profile.CreateCSR(key, p.DeviceID, p.TargetGeneration)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := issuer.Sign(t, s.Profile.Subject(p.DeviceID, p.TargetGeneration), key.Public(), func(cert *x509.Certificate) {
		cert.NotBefore = time.Now().Add(-30 * time.Second)
		cert.NotAfter = time.Now().Add(1170 * time.Second)
		if profile == credentialprofile.StableID {
			cert.DNSNames = nil
		}
	})
	target := old
	target.Handle = device.Handle{Binding: p.Binding(), PublicKeyDigest: device.Hash(leaf.RawSubjectPublicKeyInfo)}
	target.CSR = csr
	target.TLS.Certificate = [][]byte{leaf.Raw, issuer.Root.Raw}
	target.TLS.PrivateKey = key
	target.TLS.Leaf = leaf
	return s, p, old, target
}

type fixtureBackend struct {
	mode       string
	effects    atomic.Int64
	sent       atomic.Bool
	recordPath string
}

func (b *fixtureBackend) proof(k *device.Credential) error {
	if b.mode == "plain" {
		return nil
	}
	digest := sha256.Sum256([]byte("bounded fixture signature"))
	signer, ok := k.TLS.PrivateKey.(crypto.Signer)
	if !ok {
		return device.ErrDenied
	}
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	key, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(key, digest[:], signature) {
		return device.ErrDenied
	}
	return nil
}
func (b *fixtureBackend) Authorize(ctx context.Context, p device.Plan, k *device.Credential) error {
	if err := b.proof(k); err != nil {
		return err
	}
	b.effects.Add(1)
	switch b.mode {
	case "late":
		time.Sleep(700 * time.Millisecond)
	case "lost":
		os.Exit(0)
	case "hostile":
		fmtHostile()
	}
	return nil
}
func fmtHostile() {
	_, _ = os.Stdout.WriteString(`{"jsonrpc":"2.0","id":"s-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","method":"key.destroy","params":{}}` + "\n")
}
func (b *fixtureBackend) Issue(ctx context.Context, r device.IssueRequest) ([]byte, error) {
	if b.recordPath != "" {
		if prior, err := loadFixtureIntent(b.recordPath); err == nil {
			if prior.matches(r) {
				return nil, device.ErrUnknown
			}
			return nil, device.ErrConflict
		} else if !os.IsNotExist(err) {
			return nil, device.ErrUnknown
		}
	}
	if err := b.proof(r.Credential); err != nil {
		return nil, err
	}
	b.effects.Add(1)
	b.sent.Store(true)
	if b.recordPath != "" {
		csr, err := credentialprofile.Resolve(r.Plan.ProfileID, r.Plan.ProfileVersion, r.Plan.ProfileDigest)
		if err != nil {
			return nil, device.ErrDenied
		}
		request, err := csr.ValidateCSR(r.CSR, r.Plan.DeviceID, r.Plan.TargetGeneration)
		if err != nil {
			return nil, device.ErrDenied
		}
		intent := fixtureIntent{Plan: r.Plan, CSR: r.CSR, SPKI: device.Hash(request.RawSubjectPublicKeyInfo), Counter: r.Plan.TargetGeneration, IssueSends: 1, Sent: true}
		if saveFixtureIntent(b.recordPath, intent) != nil {
			return nil, device.ErrUnknown
		}
	}
	return nil, device.ErrUnknown
}
func (b *fixtureBackend) Lookup(_ context.Context, r device.IssueRequest) ([]byte, error) {
	if b.recordPath != "" {
		intent, err := loadFixtureIntent(b.recordPath)
		if os.IsNotExist(err) {
			return nil, device.ErrNotFound
		}
		if err != nil {
			return nil, device.ErrUnknown
		}
		if !intent.matches(r) {
			return nil, device.ErrConflict
		}
		return nil, device.ErrUnknown
	}
	if b.sent.Load() {
		return nil, device.ErrUnknown
	}
	return nil, device.ErrNotFound
}

// This argv-selected fixture models a separate authority's durable send budget.
// It is outside the shipped HTTP wrapper and supplies no CA or isolation evidence.
type fixtureIntent struct {
	Plan       device.Plan `json:"plan"`
	CSR        []byte      `json:"csr"`
	SPKI       string      `json:"spki"`
	Counter    uint64      `json:"counter"`
	IssueSends int         `json:"issueSends"`
	Sent       bool        `json:"sent"`
}

func (i fixtureIntent) matches(r device.IssueRequest) bool {
	return i.Plan == r.Plan && bytes.Equal(i.CSR, r.CSR) && i.Counter == r.Plan.TargetGeneration && i.IssueSends == 1 && i.Sent
}
func loadFixtureIntent(file string) (fixtureIntent, error) {
	var intent fixtureIntent
	data, err := os.ReadFile(file)
	if err != nil {
		return intent, err
	}
	err = json.Unmarshal(data, &intent)
	return intent, err
}
func saveFixtureIntent(file string, intent fixtureIntent) error {
	data, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	temporary := file + ".new"
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temporary, file); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(file))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func (b *fixtureBackend) Revoke(ctx context.Context, p device.Plan, old, target device.Credential) error {
	if b.mode == "revoke-hostile" {
		proxy := target.TLS.PrivateKey.(*remoteSigner)
		ref := ""
		if oldProxy, ok := old.TLS.PrivateKey.(*remoteSigner); ok {
			ref = oldProxy.ref
		}
		digest := sha256.Sum256([]byte("forbidden old-key signing"))
		m, _ := request("s-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "signer.sign", SignParams{proxy.parent, ref, proxy.scope, "SHA256", digest[:]})
		_ = (&protocolWriter{out: os.Stdout}).write(m)
		time.Sleep(200 * time.Millisecond)
		return nil
	}
	if err := b.proof(&target); err != nil {
		return err
	}
	return device.ErrUnknown
}
func (b *fixtureBackend) RevocationStatus(context.Context, device.Plan, device.Credential, device.Credential) error {
	return device.ErrNotFound
}
func (b *fixtureBackend) Register(context.Context, device.Plan, device.Credential) error {
	b.effects.Add(1)
	return nil
}
func (b *fixtureBackend) Registration(context.Context, device.Plan, device.Credential) error {
	return device.ErrNotFound
}
func (b *fixtureBackend) Probe(_ context.Context, p device.Probe, _ device.Credential) (device.Probe, error) {
	return p, nil
}
func (b *fixtureBackend) Activate(context.Context, device.Plan, device.Credential) (device.Activation, error) {
	return device.Activation{}, nil
}
func (b *fixtureBackend) ActivationStatus(context.Context, device.Plan, device.Credential) (device.Activation, error) {
	return device.Activation{}, nil
}
func (b *fixtureBackend) Retire(context.Context, device.Plan, device.Credential, device.Credential) (device.Retirement, error) {
	return device.Retirement{}, device.ErrUnknown
}
func (b *fixtureBackend) RetirementStatus(context.Context, device.Plan, device.Credential, device.Credential) (device.Retirement, error) {
	return device.Retirement{}, device.ErrUnknown
}
func backendAdapters(s *device.PublicSnapshot, b *fixtureBackend) device.Adapters {
	return device.Adapters{Entitlement: b, Authority: b, Platform: b, Transport: b, Application: b, Withdrawal: b, Clock: device.SystemClock{Uncertainty: time.Second, MaximumAge: time.Duration(s.Limits.MaximumAssessmentAgeSeconds) * time.Second, DriftPPM: float64(s.Limits.DriftPPM)}}
}

type peer struct {
	in    *io.PipeWriter
	out   *bufio.Reader
	close func()
}

func newPeer(t *testing.T, s *device.PublicSnapshot, b *fixtureBackend) peer {
	t.Helper()
	childIn, hostIn := io.Pipe()
	hostOut, childOut := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan struct{})
	go func() {
		_ = Serve(ctx, childIn, childOut, ServerOptions{Snapshot: s, Adapters: backendAdapters(s, b), ArtifactDigest: s.Composition.ProcessArtifactDigest})
		close(done)
	}()
	p := peer{hostIn, bufio.NewReader(hostOut), func() {
		cancel()
		_ = hostIn.Close()
		_ = hostOut.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("server teardown exceeded bound")
		}
	}}
	t.Cleanup(p.close)
	return p
}
func (p peer) call(t *testing.T, id, method string, params any) message {
	t.Helper()
	m, err := request(id, method, params)
	if err != nil {
		t.Fatal(err)
	}
	if (&protocolWriter{out: p.in}).write(m) != nil {
		t.Fatal("peer write failed")
	}
	line, err := readLine(p.out, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	response, err := decodeMessage(line, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func initializeFixture(s *device.PublicSnapshot) InitializeParams {
	permissions, _ := ExpectedPermissions(s)
	return InitializeParams{[]string{ProtocolVersion}, []string{ErrorVersion}, []SchemaIdentity{Schema()}, s.Composition.ProcessArtifactDigest, s.Digest(), s.Composition.Digest(), s.Profile, s.Bytes(), defaultRequired(s), permissions, DefaultLimits()}
}

func TestInitializationRefusesMismatchBeforeDomainEffects(t *testing.T) {
	s, p, recovery, _ := fixture(t, strings.Repeat("b", 64), credentialprofile.StableID)
	for _, variant := range []string{"protocol", "schema", "profile", "permission", "limits", "capability", "snapshot", "domain-first"} {
		t.Run(variant, func(t *testing.T) {
			b := &fixtureBackend{mode: "plain"}
			peer := newPeer(t, s, b)
			init := initializeFixture(s)
			switch variant {
			case "protocol":
				init.ProtocolVersions = []string{"unsupported"}
			case "schema":
				init.Schemas[0].SHA256 = strings.Repeat("c", 64)
			case "profile":
				init.Profile.PolicyDigest = strings.Repeat("c", 64)
			case "permission":
				init.Permissions.FilesystemWrite = []string{"unsafe"}
			case "limits":
				init.Limits.MaxLineBytes++
			case "capability":
				init.RequiredCapabilities = []string{"unsupported-capability"}
			case "snapshot":
				init.Snapshot = append(init.Snapshot, ' ')
			}
			var response message
			if variant == "domain-first" {
				w, _, _ := wirePublic(recovery, strings.Repeat("c", 32))
				response = peer.call(t, testID, "entitlement.authorize", AuthorizeParams{scopeFor(p, time.Now().Add(time.Second)), p, &w})
			} else {
				response = peer.call(t, testID, "plugin.initialize", init)
			}
			if response.Error == nil || b.effects.Load() != 0 {
				t.Fatal("initialization gap allowed domain effects")
			}
		})
	}
}

func TestScopeRoleGenerationAndStagingRefusal(t *testing.T) {
	for _, profile := range []string{credentialprofile.ReferenceID, credentialprofile.StableID} {
		t.Run(profile, func(t *testing.T) {
			s, p, recovery, target := fixture(t, strings.Repeat("b", 64), profile)
			b := &fixtureBackend{mode: "plain"}
			peer := newPeer(t, s, b)
			if peer.call(t, testID, "plugin.initialize", initializeFixture(s)).Error != nil {
				t.Fatal("valid initialize refused")
			}
			w, _, err := wirePublic(recovery, strings.Repeat("c", 32))
			if err != nil {
				t.Fatal(err)
			}
			scope := scopeFor(p, time.Now().Add(800*time.Millisecond))
			for i, variant := range []string{"stale-generation", "wrong-profile", "wrong-role"} {
				params := AuthorizeParams{scope, p, &w}
				if variant == "stale-generation" {
					params.Scope.TargetGeneration++
				}
				if variant == "wrong-profile" {
					params.Scope.ProfileID = "unknown"
				}
				if variant == "wrong-role" {
					operational, _, _ := wirePublic(target, strings.Repeat("d", 32))
					params.Credential = &operational
				}
				id := "h-" + strings.Repeat("d", 31) + string('1'+rune(i))
				response := peer.call(t, id, "entitlement.authorize", params)
				if response.Error == nil || b.effects.Load() != 0 {
					t.Fatal("scope or role mismatch caused effects")
				}
			}
			wt, _, _ := wirePublic(target, strings.Repeat("e", 32))
			response := peer.call(t, "h-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "application.activate", CredentialParams{scope, p, wt})
			if response.Error == nil || response.Error.Data.Kind != "unknown" {
				t.Fatal("incomplete activation was accepted")
			}
		})
	}
}

type trackedSigner struct {
	crypto.Signer
	calls  atomic.Int64
	called chan struct{}
	once   sync.Once
}

func (s *trackedSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls.Add(1)
	s.once.Do(func() { close(s.called) })
	return s.Signer.Sign(r, digest, opts)
}

type lockedLog struct {
	mu sync.Mutex
	bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Buffer.Write(p)
}
func (l *lockedLog) text() string { l.mu.Lock(); defer l.mu.Unlock(); return l.Buffer.String() }

func TestHelperProcess(t *testing.T) {
	mode := ""
	recordPath := ""
	for i, arg := range os.Args {
		if arg == "process-fixture" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
			if i+2 < len(os.Args) {
				recordPath = os.Args[i+2]
			}
		}
	}
	if mode == "" {
		return
	}
	exe, _ := os.Executable()
	pin, err := ExecutableDigest(exe)
	if err != nil {
		os.Exit(2)
	}
	_, _ = os.Stderr.WriteString("Bearer fixture-secret\n-----BEGIN PRIVATE KEY-----\nfixture-payload\n")
	err = Serve(context.Background(), os.Stdin, os.Stdout, ServerOptions{ArtifactDigest: pin, Factory: func(s *device.PublicSnapshot) (device.Adapters, error) {
		return backendAdapters(s, &fixtureBackend{mode: mode, recordPath: recordPath}), nil
	}})
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func startFixtureProcess(t *testing.T, mode string) (*Client, device.Plan, device.Credential, device.Credential, *trackedSigner, *lockedLog) {
	return startConfiguredFixtureProcess(t, mode, false)
}

func startConfiguredFixtureProcess(t *testing.T, mode string, rotation bool) (*Client, device.Plan, device.Credential, device.Credential, *trackedSigner, *lockedLog) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := ExecutableDigest(exe)
	if err != nil {
		t.Fatal(err)
	}
	s, p, recovery, target := fixture(t, pin, credentialprofile.StableID)
	if rotation {
		s, p, recovery, target = rotateFixture(t, pin, credentialprofile.StableID)
	}
	tracker := &trackedSigner{Signer: recovery.TLS.PrivateKey.(crypto.Signer), called: make(chan struct{})}
	recovery.TLS.PrivateKey = tracker
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := &lockedLog{}
	client, err := Start(context.Background(), Options{Executable: exe, ArtifactDigest: pin, Args: []string{"-test.run=^TestHelperProcess$", "process-fixture", mode}, WorkDir: root, Snapshot: s, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, p, recovery, target, tracker, log
}

func TestRevokePreviousIsPublicOnlyAndCannotUseBroker(t *testing.T) {
	for _, mode := range []string{"sign", "revoke-hostile"} {
		t.Run(mode, func(t *testing.T) {
			c, p, old, target, oldSigner, _ := startConfiguredFixtureProcess(t, mode, true)
			targetSigner := &trackedSigner{Signer: target.TLS.PrivateKey.(crypto.Signer), called: make(chan struct{})}
			target.TLS.PrivateKey = targetSigner
			if err := c.Revoke(context.Background(), p, old, target); !errors.Is(err, device.ErrUnknown) {
				t.Fatal("unexpected revoke result", err)
			}
			if oldSigner.calls.Load() != 0 {
				t.Fatal("previous artifact received a revoke signing grant")
			}
			if mode == "sign" && targetSigner.calls.Load() != 1 {
				t.Fatal("current target signer was not used")
			}
			if mode == "revoke-hostile" && c.Health(context.Background()) != device.ErrUnknown {
				t.Fatal("unsolicited previous signing did not terminate session")
			}
		})
	}
}

func TestRealSubprocessSignerLookupAndRedaction(t *testing.T) {
	c, p, recovery, target, tracker, log := startFixtureProcess(t, "sign")
	if err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Assess(context.Background(), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Authorize(context.Background(), p, &recovery); err != nil {
		t.Fatal(err)
	}
	r := device.IssueRequest{Plan: p, CSR: target.CSR, Credential: &recovery}
	if _, err := c.Lookup(context.Background(), r); !errors.Is(err, device.ErrNotFound) {
		t.Fatal("fresh bound fixture absence refused", err)
	}
	if _, err := c.Issue(context.Background(), r); !errors.Is(err, device.ErrUnknown) {
		t.Fatal("unknown issuance was changed", err)
	}
	if tracker.calls.Load() != 2 {
		t.Fatal("unexpected signing/retry count")
	}
	if _, err := c.Lookup(context.Background(), r); !errors.Is(err, device.ErrUnknown) {
		t.Fatal("sent unknown issuance became absence", err)
	}
	if tracker.calls.Load() != 2 {
		t.Fatal("lookup resent issue/sign")
	}
	if err := c.Register(context.Background(), p, target); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Activate(context.Background(), p, target); !errors.Is(err, device.ErrUnknown) {
		t.Fatal("staged/incomplete application result accepted", err)
	}
	_ = c.Close()
	time.Sleep(20 * time.Millisecond)
	for _, marker := range []string{"fixture-secret", "PRIVATE KEY", "fixture-payload"} {
		if strings.Contains(log.text(), marker) {
			t.Fatal("raw stderr leaked")
		}
	}
	if !strings.Contains(log.text(), "adapter stderr bytes=") {
		t.Fatal("missing fixed stderr count")
	}
}

func TestActualProcessRestartReconcilesOriginalDurableIntentWithoutReissue(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := ExecutableDigest(exe)
	if err != nil {
		t.Fatal(err)
	}
	s, p, recovery, target := fixture(t, pin, credentialprofile.StableID)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "authority-fixture.json")
	tracker := &trackedSigner{Signer: recovery.TLS.PrivateKey.(crypto.Signer), called: make(chan struct{})}
	recovery.TLS.PrivateKey = tracker
	opts := Options{Executable: exe, ArtifactDigest: pin, Args: []string{"-test.run=^TestHelperProcess$", "process-fixture", "persistent", file}, WorkDir: root, Snapshot: s}
	first, err := Start(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := device.IssueRequest{Plan: p, CSR: target.CSR, Credential: &recovery}
	if _, err = first.Lookup(context.Background(), r); !errors.Is(err, device.ErrNotFound) {
		t.Fatal("fresh fixture absence refused", err)
	}
	if _, err = first.Issue(context.Background(), r); !errors.Is(err, device.ErrUnknown) {
		t.Fatal("fixture send not unknown", err)
	}
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	second, err := Start(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err = second.Lookup(context.Background(), r); !errors.Is(err, device.ErrUnknown) {
		t.Fatal("restart changed sent intent into absence", err)
	}
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("reconciliation modified original intent")
	}
	intent, err := loadFixtureIntent(file)
	if err != nil || !intent.matches(r) || intent.SPKI != target.Handle.PublicKeyDigest || intent.Counter != 1 || intent.IssueSends != 1 || tracker.calls.Load() != 1 {
		t.Fatal("restart lost original CSR/SPKI/counter/send budget")
	}
}

func TestCancelLostLateAndUnsolicitedResponseRequireNewSession(t *testing.T) {
	for _, mode := range []string{"late", "lost", "hostile"} {
		t.Run(mode, func(t *testing.T) {
			c, p, recovery, _, tracker, _ := startFixtureProcess(t, mode)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- c.Authorize(ctx, p, &recovery) }()
			select {
			case <-tracker.called:
			case <-time.After(time.Second):
				t.Fatal("process did not request bounded signing")
			}
			if mode == "late" {
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, device.ErrUnknown) {
					t.Fatal("lost effect was not unknown", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("host exceeded execution bound")
			}
			if err := c.Health(context.Background()); !errors.Is(err, device.ErrUnknown) {
				t.Fatal("terminal session reused", err)
			}
			if tracker.calls.Load() != 1 {
				t.Fatal("uncertain call retried signing")
			}
			started := time.Now()
			_ = c.Close()
			if time.Since(started) > 2*time.Second {
				t.Fatal("teardown exceeded bound")
			}
		})
	}
}

func TestErrorCombinationsNeverCreateAbsenceFromMutation(t *testing.T) {
	s, p, _, _ := fixture(t, strings.Repeat("b", 64), credentialprofile.StableID)
	_ = s
	scope := scopeFor(p, time.Now().Add(time.Second))
	known := rpcError("not-started", &scope)
	if mapError(known, "authority.lookup", &scope) != device.ErrNotFound || mapError(known, "authority.issue", &scope) != device.ErrUnknown {
		t.Fatal("absence escaped lookup scope")
	}
	for _, variant := range []string{"code", "message", "outcome", "retry", "scope"} {
		data, _ := json.Marshal(known)
		var bad RPCError
		_ = json.Unmarshal(data, &bad)
		switch variant {
		case "code":
			bad.Code = -32013
		case "message":
			bad.Message = "remote token secret"
		case "outcome":
			bad.Data.Outcome = "unknown"
		case "retry":
			bad.Data.Retryable = true
		case "scope":
			bad.Data.Scope.TargetGeneration++
		}
		if validError(&bad, "authority.lookup", &scope) || mapError(&bad, "authority.lookup", &scope) != device.ErrUnknown {
			t.Fatal("contradictory error accepted")
		}
	}
}

func TestBlockedServerOutputRespectsContext(t *testing.T) {
	s, _, _, _ := fixture(t, strings.Repeat("b", 64), credentialprofile.StableID)
	m, _ := request(testID, "plugin.initialize", initializeFixture(s))
	input, _ := json.Marshal(m)
	input = append(input, '\n')
	reader, writer := io.Pipe()
	defer reader.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, bytes.NewReader(input), writer, ServerOptions{Snapshot: s, Adapters: backendAdapters(s, &fixtureBackend{mode: "plain"}), ArtifactDigest: s.Composition.ProcessArtifactDigest})
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked stdout prevented context teardown")
	}
}

func TestCapabilityListsAreSorted(t *testing.T) {
	s, _, _, _ := fixture(t, strings.Repeat("b", 64), credentialprofile.StableID)
	caps, err := capabilities(s, backendAdapters(s, &fixtureBackend{mode: "plain"}))
	if err != nil || !sort.StringsAreSorted(caps) || len(caps) > 32 {
		t.Fatal("invalid capability declaration")
	}
}

func TestDuplicateIDsAndNotificationsDoNotRedispatch(t *testing.T) {
	s, p, recovery, target := fixture(t, strings.Repeat("b", 64), credentialprofile.StableID)
	b := &fixtureBackend{mode: "plain"}
	peer := newPeer(t, s, b)
	if peer.call(t, testID, "plugin.initialize", initializeFixture(s)).Error != nil {
		t.Fatal("initialize refused")
	}
	scope := scopeFor(p, time.Now().Add(900*time.Millisecond))
	recoveryWire, _, _ := wirePublic(recovery, strings.Repeat("c", 32))
	notification, _ := request("", "entitlement.authorize", AuthorizeParams{scope, p, &recoveryWire})
	notification.ID = nil
	if (&protocolWriter{out: peer.in}).write(notification) != nil {
		t.Fatal("notification failed")
	}
	unknown := peer.call(t, "h-dddddddddddddddddddddddddddddddd", "operation.status", Empty{})
	if unknown.Error == nil || unknown.Error.Code != -32601 || b.effects.Load() != 0 {
		t.Fatal("unknown method or notification triggered effects")
	}
	wire, _, _ := wirePublic(target, strings.Repeat("e", 32))
	id := "h-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	params := CredentialParams{scope, p, wire}
	if peer.call(t, id, "platform.register", params).Error != nil || b.effects.Load() != 1 {
		t.Fatal("fixture registration failed")
	}
	if response := peer.call(t, id, "platform.register", params); response.Error == nil || response.Error.Code != -32600 || b.effects.Load() != 1 {
		t.Fatal("duplicate request redispatched")
	}
}

func TestMalformedServerInputReturnsSafeNullID(t *testing.T) {
	for _, input := range []string{`{"jsonrpc":"2.0",`, `{"jsonrpc":"2.0","jsonrpc":"2.0","method":"plugin.health","params":{}}`} {
		t.Run(input, func(t *testing.T) {
			s, _, _, _ := fixture(t, strings.Repeat("b", 64), credentialprofile.StableID)
			b := &fixtureBackend{mode: "plain"}
			peer := newPeer(t, s, b)
			if _, err := peer.in.Write([]byte(input + "\n")); err != nil {
				t.Fatal(err)
			}
			line, err := readLine(peer.out, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if validateDefinition("response", line) != nil {
				t.Fatal("invalid error response schema")
			}
			response, err := decodeMessage(line, DefaultLimits())
			if err != nil || response.ID != nil || response.Error == nil || b.effects.Load() != 0 {
				t.Fatal("malformed input was not safely refused")
			}
			expected := -32600
			if !json.Valid([]byte(input)) {
				expected = -32700
			}
			if response.Error.Code != expected {
				t.Fatal("wrong standard JSON-RPC error code")
			}
		})
	}
}
