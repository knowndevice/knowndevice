// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"knowndevice.local/knowndevice/adapters/credentials"
	"knowndevice.local/knowndevice/internal/credentialprofile"
	"knowndevice.local/knowndevice/internal/device"
)

type control struct {
	mu              sync.Mutex
	caMu            sync.Mutex
	dir             string
	config          servicesConfig
	snapshot        *device.PublicSnapshot
	store           *store
	observer        tls.Certificate
	authorityCaller tls.Certificate
	connections     *connections
}

type caCounts struct {
	Sign         uint64 `json:"sign"`
	SignAttempts uint64 `json:"signAttempts"`
}

type countingCATransport struct {
	control *control
	next    http.RoundTripper
}

func (t *countingCATransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/sign" {
		if err := t.control.countCASign(true); err != nil {
			return nil, err
		}
	}
	return t.next.RoundTrip(req)
}

// Attempt counts are durable before transport dispatch, including a lost reply.
// A count does not establish that the CA received or completed an issuance.
func (s *control) countCASign(attempt bool) error {
	s.caMu.Lock()
	defer s.caMu.Unlock()
	path := filepath.Join(s.dir, "control", "ca-counts.json")
	var stored struct {
		Sign         *uint64 `json:"sign"`
		SignAttempts *uint64 `json:"signAttempts"`
	}
	if err := readJSON(path, &stored); err != nil || stored.Sign == nil || stored.SignAttempts == nil {
		return device.ErrUnknown
	}
	counts := caCounts{Sign: *stored.Sign, SignAttempts: *stored.SignAttempts}
	count := &counts.Sign
	if attempt {
		count = &counts.SignAttempts
	}
	if *count == ^uint64(0) {
		return device.ErrUnknown
	}
	(*count)++
	if err := writeJSON(path, counts); err != nil {
		return device.ErrUnknown
	}
	return nil
}

func openControl(dir string) (*control, error) {
	cfg, snapshot, e := loadServices(dir)
	if e != nil {
		return nil, e
	}
	s, e := openStore(filepath.Join(dir, "control"), registry{DeploymentID: snapshot.DeploymentID, DeviceID: snapshot.DeviceID, Status: "authorized", Revision: 1, RecoveryFingerprint: cfg.RecoveryFingerprint, RecoveryPublicKeyDigest: cfg.RecoveryPublicKeyDigest, SnapshotDigest: snapshot.Digest()})
	if e != nil {
		return nil, e
	}
	observer, e := credentialAt(dir, "observer")
	if e != nil {
		s.close()
		return nil, e
	}
	authorityCaller, e := credentialAt(dir, "authority-caller")
	if e != nil {
		s.close()
		return nil, e
	}
	return &control{dir: dir, config: cfg, snapshot: snapshot, store: s, observer: observer, authorityCaller: authorityCaller, connections: newConnections()}, nil
}

func action(path string) (role, name string, status bool) {
	switch path {
	case "/entitlement":
		return "entitlement", "entitlement", false
	case "/issue":
		return "authority", "issue", false
	case "/lookup":
		return "authority", "lookup", true
	case "/import":
		return "authority", "import", false
	case "/register":
		return "platform", "register", false
	case "/registration":
		return "platform", "registration", true
	case "/activate":
		return "application", "activate", false
	case "/activation-status":
		return "application", "activation-status", true
	case "/withdraw":
		return "withdrawal", "withdraw", false
	case "/withdrawal-status":
		return "withdrawal", "withdrawal-status", true
	case "/revoke":
		return "authority", "revoke", false
	case "/revocation-status":
		return "authority", "revocation-status", true
	}
	return "", "", false
}

func (s *control) request(w http.ResponseWriter, req *http.Request) {
	in, e := decodeRequest(w, req)
	if e != nil {
		reply(w, device.RoleResponse{}, e)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	response, e := s.handle(req, in)
	reply(w, response, e)
}

func (s *control) plan(ctx context.Context, p device.Plan, status bool) error {
	now := time.Now().UTC()
	at := now.Add(time.Second)
	if status {
		at = p.ExpiresAt.Add(-time.Nanosecond)
	}
	if e := p.Validate(at); e != nil {
		return device.ErrDenied
	}
	if e := s.snapshot.ValidatePlan(p); e != nil || p.ConfigDigest != s.config.ConfigDigest {
		return device.ErrDenied
	}
	if !status {
		if !now.Add(time.Second).Before(p.ExpiresAt) {
			return device.ErrPlanExpired
		}
		template, e := os.ReadFile(filepath.Join(s.dir, "ca", "profile.tpl"))
		if e != nil || len(template) > 16<<10 || device.Hash(template) != s.config.TemplateDigest {
			return device.ErrDenied
		}
		cfg, e := device.LoadConfig(s.config.DeviceConfig)
		if e != nil {
			return device.ErrDenied
		}
		digest, e := cfg.Digest()
		if e != nil || digest != p.ConfigDigest {
			return device.ErrDenied
		}
		if e := s.store.clock(ctx, now.Add(-time.Second)); e != nil {
			return e
		}
	}
	_, e := checkEntitlement(s.dir, p)
	return e
}

func (s *control) authorize(req *http.Request, p device.Plan, r *reservation, issuance, status bool) error {
	c := peer(req)
	if c == nil {
		return device.ErrDenied
	}
	reg, e := s.store.registry(req.Context())
	if e != nil {
		return e
	}
	if reg.Status != "authorized" {
		return device.ErrDenied
	}
	if issuance {
		if r == nil && (p.TargetGeneration <= reg.Counter || p.Mode == "enroll" && reg.Counter > 0) {
			return device.ErrConflict
		}
		if p.Mode == "enroll" || p.Mode == "recover" {
			if verifyPeerRole(req, s.snapshot, "recovery") != nil || credentials.ValidateIdentity(c, device.RecoverySubject(p.DeviceID)) != nil || device.Hash(c.Raw) != reg.RecoveryFingerprint || device.Hash(c.RawSubjectPublicKeyInfo) != reg.RecoveryPublicKeyDigest {
				return device.ErrDenied
			}
		} else if p.Mode == "rotate" {
			if verifyPeerRole(req, s.snapshot, "operational") != nil || reg.Active == nil || reg.Active.Generation != p.ExpectedGeneration || !matches(c, *reg.Active) {
				return device.ErrDenied
			}
			current, e := s.store.generation(req.Context(), reg.Active.Generation)
			if e != nil || current.Candidate != *reg.Active {
				return device.ErrDenied
			}
			certs, e := credentialprofile.ParseChain(current.Certificate)
			if e != nil || !bytes.Equal(c.Raw, certs[0].Raw) || !bytes.Equal(c.RawSubjectPublicKeyInfo, current.SPKI) || s.snapshot.Profile.ValidateLeaf(c, p.DeviceID, reg.Active.Generation) != nil {
				return device.ErrDenied
			}
		} else {
			return device.ErrDenied
		}
		if (reg.Active == nil && p.ExpectedGeneration != 0) || (reg.Active != nil && reg.Active.Generation != p.ExpectedGeneration) {
			return device.ErrConflict
		}
		return nil
	}
	if r == nil {
		return device.ErrNotFound
	}
	if verifyPeerRole(req, s.snapshot, "operational") != nil || !matches(c, r.Candidate) || len(r.Certificate) == 0 {
		return device.ErrDenied
	}
	certs, e := credentialprofile.ParseChain(r.Certificate)
	if e != nil || !bytes.Equal(c.Raw, certs[0].Raw) || !bytes.Equal(c.RawSubjectPublicKeyInfo, r.SPKI) || s.snapshot.Profile.ValidateLeaf(c, p.DeviceID, p.TargetGeneration) != nil {
		return device.ErrDenied
	}
	if !status && validateInstalled(s.snapshot, r, false, false) != nil {
		return device.ErrDenied
	}
	return nil
}

func (s *control) handle(req *http.Request, in device.RoleRequest) (device.RoleResponse, error) {
	ctx := req.Context()
	p := in.Plan
	role, name, status := action(req.URL.Path)
	if role == "" {
		return device.RoleResponse{}, device.ErrDenied
	}
	if e := s.plan(ctx, p, status); e != nil {
		return device.RoleResponse{}, e
	}
	r, e := s.store.operation(ctx, p)
	if e != nil {
		return device.RoleResponse{}, e
	}
	issuance := req.URL.Path == "/entitlement" || req.URL.Path == "/issue" || req.URL.Path == "/lookup" || req.URL.Path == "/import"
	if e = s.authorize(req, p, r, issuance, status); e != nil {
		return device.RoleResponse{}, e
	}
	response := device.RoleResponse{Status: "ok"}
	subject := device.CredentialBinding{DeploymentID: p.DeploymentID, DeviceID: p.DeviceID, Generation: p.TargetGeneration, OperationID: p.OperationID, PlanDigest: p.Digest, ConfigDigest: p.ConfigDigest, SnapshotDigest: p.SnapshotDigest, ProfileID: p.ProfileID, ProfileVersion: p.ProfileVersion, ProfileDigest: p.ProfileDigest}
	revision := uint64(1)
	if r != nil {
		subject = r.Candidate
		revision = r.Revision
	}
	initial := evidence(p, subject, role, name, in.RequestID, revision, source(s.snapshot, "control"), "ok")
	response.Evidence = &initial
	if req.URL.Path == "/entitlement" {
		reg, e := s.store.registry(ctx)
		if e != nil {
			return response, e
		}
		subject.Generation = p.ExpectedGeneration
		revision = reg.Revision
		if reg.Active != nil {
			subject = *reg.Active
		}
	} else if issuance {
		csr, e := s.snapshot.Profile.ValidateCSR(in.CSR, p.DeviceID, p.TargetGeneration)
		if e != nil {
			return response, device.ErrDenied
		}
		if r == nil {
			if req.URL.Path == "/lookup" {
				return response, device.ErrNotFound
			}
			if req.URL.Path != "/issue" {
				return response, device.ErrConflict
			}
			r, e = s.store.reserve(ctx, reservation{Plan: p, CSR: append([]byte(nil), in.CSR...), SPKI: append([]byte(nil), csr.RawSubjectPublicKeyInfo...), Candidate: bound(p, csr)})
			if e != nil {
				return response, e
			}
			chain, e := s.sign(ctx, r)
			if e != nil {
				return response, device.ErrUnknown
			}
			var fixture policy
			if e = readJSON(filepath.Join(s.dir, "fixtures", "policy.json"), &fixture); e != nil {
				return response, device.ErrUnknown
			}
			if fixture.LoseCAResult {
				if e = writeAtomic(filepath.Join(s.dir, "control", "recovered-"+p.OperationID+".pem"), chain); e != nil {
					return response, device.ErrUnknown
				}
				return response, device.ErrUnknown
			}
			if e = s.install(ctx, r, chain); e != nil {
				return response, device.ErrUnknown
			}
		} else if !bytes.Equal(r.CSR, in.CSR) || !bytes.Equal(r.SPKI, csr.RawSubjectPublicKeyInfo) {
			return response, device.ErrConflict
		}
		if req.URL.Path == "/import" {
			if len(r.Certificate) != 0 {
				if !bytes.Equal(r.Certificate, in.Certificate) {
					return response, device.ErrConflict
				}
			} else if e = s.install(ctx, r, in.Certificate); e != nil {
				return response, device.ErrDenied
			}
		}
		if len(r.Certificate) == 0 {
			return response, device.ErrUnknown
		}
		response.Certificate = append([]byte(nil), r.Certificate...)
		subject = r.Candidate
		revision = r.Revision
	} else {
		if len(in.Certificate) > 0 && !bytes.Equal(in.Certificate, r.Certificate) {
			return response, device.ErrDenied
		}
		switch req.URL.Path {
		case "/register":
			reg, e := s.store.registry(ctx)
			if e != nil {
				return response, e
			}
			if !sameExpected(reg, r) && !(r.Activated && reg.Active != nil && *reg.Active == r.Candidate) {
				return response, device.ErrConflict
			}
			if !r.Registered {
				r.Registered = true
				if e = s.store.save(ctx, r); e != nil {
					return response, e
				}
			}
		case "/registration":
			if !r.Registered {
				return response, device.ErrNotFound
			}
		case "/activate", "/activation-status":
			if !r.Registered {
				return response, device.ErrDenied
			}
			if e = s.plan(ctx, p, false); e != nil {
				return response, e
			}
			app, e := s.application(ctx, r, req.URL.Path == "/activate")
			if e != nil {
				return response, e
			}
			if e = s.plan(ctx, p, false); e != nil {
				return response, e
			}
			if e = s.authorize(req, p, r, false, false); e != nil {
				return response, e
			}
			if validateInstalled(s.snapshot, r, true, false) != nil {
				return response, device.ErrDenied
			}
			if e = s.store.activate(ctx, r, app); e != nil {
				return response, e
			}
			if e = labCheckpoint(ctx, s.dir, "control", "activation-committed", p); e != nil {
				return response, e
			}
			if e = s.plan(ctx, p, false); e != nil {
				return response, e
			}
			response.Application = &app
		case "/withdraw", "/withdrawal-status":
			if e = s.plan(ctx, p, false); e != nil {
				return response, e
			}
			withdrawal, e := s.withdraw(ctx, in, r, req.URL.Path == "/withdraw")
			if e != nil {
				return response, e
			}
			response.Withdrawal = &withdrawal
			subject = withdrawal.Previous
		case "/revoke", "/revocation-status":
			if r.Withdrawal == nil || !r.Withdrawal.SessionsTerminated || r.Withdrawal.Denial.Kind != "denied" {
				return response, device.ErrDenied
			}
			old, e := s.previous(ctx, in, r)
			if e != nil {
				return response, e
			}
			subject = old.Candidate
			if !r.Revoked {
				if r.RevocationSent {
					return response, device.ErrUnknown
				}
				if req.URL.Path == "/revocation-status" {
					absent := evidence(p, old.Candidate, role, name, in.RequestID, r.Revision, source(s.snapshot, "control"), "not-started")
					response.Evidence = &absent
					return response, device.ErrNotFound
				}
				r.RevocationSent = true
				if e = s.store.save(ctx, r); e != nil {
					return response, e
				}
				if e = s.revoke(ctx, r, old); e != nil {
					return response, device.ErrUnknown
				}
				r.Revoked = true
				r.Finished = true
				if e = s.store.save(ctx, r); e != nil {
					return response, e
				}
			}
		}
		revision = r.Revision
	}
	entry := evidence(p, subject, role, name, in.RequestID, revision, source(s.snapshot, "control"), "ok")
	if r != nil && issuance {
		entry.IssuanceEarliest = r.IssueEarliest
		entry.IssuanceLatest = r.IssueLatest
	}
	response.Evidence = &entry
	return response, nil
}

func sameExpected(reg registry, r *reservation) bool {
	return (reg.Active == nil && r.Expected == nil) || (reg.Active != nil && r.Expected != nil && *reg.Active == *r.Expected)
}

func (s *control) install(ctx context.Context, r *reservation, chain []byte) error {
	if len(r.Certificate) != 0 {
		return device.ErrConflict
	}
	candidate := *r
	candidate.Certificate = append([]byte(nil), chain...)
	if e := validateInstalled(s.snapshot, &candidate, false, false); e != nil {
		return device.ErrDenied
	}
	certs, e := credentialprofile.ParseChain(chain)
	if e != nil {
		return device.ErrDenied
	}
	for _, cert := range certs[1:] {
		if !cert.IsCA {
			return device.ErrDenied
		}
	}
	c := certs[0]
	if r.IssueEarliest.IsZero() || r.IssueLatest.Before(r.IssueEarliest) || c.NotBefore.Before(r.IssueEarliest.Add(-time.Duration(s.snapshot.Limits.MaxBackdateSeconds)*time.Second)) {
		return device.ErrDenied
	}
	candidate.Candidate.CertificateFingerprint = device.Hash(c.Raw)
	candidate.Issuer = device.Hash(c.RawIssuer)
	candidate.Serial = c.SerialNumber.String()
	candidate.NotBefore = c.NotBefore
	candidate.NotAfter = c.NotAfter
	if e = s.store.save(ctx, &candidate); e != nil {
		return e
	}
	*r = candidate
	return nil
}

func (s *control) token(p device.Plan, purpose, serial string, csr []byte) (string, error) {
	if s.snapshot.ValidatePlan(p) != nil || p.Validate(time.Now().Add(time.Second)) != nil {
		return "", device.ErrPlanExpired
	}
	b, e := os.ReadFile(filepath.Join(s.dir, "control", "provisioner.key"))
	if e != nil {
		return "", e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return "", device.ErrDenied
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return "", device.ErrDenied
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", device.ErrDenied
	}
	var meta struct {
		Kid string `json:"kid"`
	}
	if e = readJSON(filepath.Join(s.dir, "control", "provisioner.json"), &meta); e != nil {
		return "", e
	}
	id, e := device.RandomID()
	if e != nil {
		return "", e
	}
	subject := s.snapshot.Profile.Subject(p.DeviceID, p.TargetGeneration)
	if purpose == "revoke" {
		subject = serial
	}
	now := time.Now()
	if !now.Add(time.Second).Before(p.ExpiresAt) {
		return "", device.ErrPlanExpired
	}
	latestToken := now.Add(30 * time.Second)
	if p.ExpiresAt.Add(-time.Second).Before(latestToken) {
		latestToken = p.ExpiresAt.Add(-time.Second)
	}
	claims := map[string]any{"iss": "known-device-profile-lab", "sub": subject, "aud": s.config.CAURL + "/1.0/" + purpose, "iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "exp": latestToken.Unix(), "jti": id}
	if purpose == "sign" {
		request, e := s.snapshot.Profile.ValidateCSR(csr, p.DeviceID, p.TargetGeneration)
		if e != nil {
			return "", device.ErrDenied
		}
		sum := sha256.Sum256(request.Raw)
		claims["cnf"] = map[string]string{"x5rt#S256": base64.RawURLEncoding.EncodeToString(sum[:])}
		if s.snapshot.Profile.ID == credentialprofile.ReferenceID {
			claims["sans"] = []string{subject}
		}
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": meta.Kid})
	body, _ := json.Marshal(claims)
	encoded := b64(header) + "." + b64(body)
	sum := sha256.Sum256([]byte(encoded))
	a, z, e := ecdsa.Sign(rand.Reader, key, sum[:])
	if e != nil {
		return "", e
	}
	signature := make([]byte, 64)
	a.FillBytes(signature[:32])
	z.FillBytes(signature[32:])
	return encoded + "." + b64(signature), nil
}

func (s *control) sign(ctx context.Context, r *reservation) ([]byte, error) {
	ctx, cancel, e := authorityContext(ctx, r.Plan)
	if e != nil {
		return nil, e
	}
	defer cancel()
	if !r.IssueSent || len(r.Certificate) != 0 {
		return nil, device.ErrDenied
	}
	if _, e := s.snapshot.Profile.ValidateCSR(r.CSR, r.Plan.DeviceID, r.Plan.TargetGeneration); e != nil {
		return nil, device.ErrDenied
	}
	if _, e := checkEntitlement(s.dir, r.Plan); e != nil {
		return nil, e
	}
	token, e := s.token(r.Plan, "sign", "", r.CSR)
	if e != nil {
		return nil, e
	}
	issuedAt := time.Now().UTC()
	input := struct {
		CSR       string `json:"csr"`
		OTT       string `json:"ott"`
		NotBefore string `json:"notBefore"`
		NotAfter  string `json:"notAfter"`
	}{CSR: string(r.CSR), OTT: token, NotBefore: issuedAt.Add(-30 * time.Second).Format(time.RFC3339), NotAfter: issuedAt.Add(s.snapshot.Composition.AuthorityLifetime() - 30*time.Second).Format(time.RFC3339)}
	var out struct {
		CRT        string          `json:"crt"`
		CA         string          `json:"ca"`
		Chain      []string        `json:"certChain"`
		TLSOptions json.RawMessage `json:"tlsOptions,omitempty"`
	}
	if e = post(ctx, s.snapshot, "issuance", "/sign", &s.authorityCaller, input, &out); e != nil {
		return nil, device.ErrUnknown
	}
	if len(out.Chain) > 8 {
		return nil, device.ErrUnknown
	}
	var chain []byte
	if len(out.Chain) > 0 {
		if out.CRT != out.Chain[0] || len(out.Chain) > 1 && out.CA != out.Chain[1] {
			return nil, device.ErrUnknown
		}
		for _, cert := range out.Chain {
			chain = append(chain, cert...)
		}
	} else {
		chain = []byte(out.CRT + out.CA)
	}
	return chain, nil
}

func (s *control) revoke(ctx context.Context, r, old *reservation) error {
	ctx, cancel, e := authorityContext(ctx, r.Plan)
	if e != nil {
		return e
	}
	defer cancel()
	token, e := s.token(r.Plan, "revoke", old.Serial, nil)
	if e != nil {
		return e
	}
	input := map[string]any{"serial": old.Serial, "ott": token, "reason": "credential generation superseded", "reasonCode": 4, "passive": true}
	var out struct {
		Status string `json:"status"`
	}
	if e = post(ctx, s.snapshot, "issuance", "/revoke", &s.authorityCaller, input, &out); e != nil || out.Status != "ok" {
		return device.ErrUnknown
	}
	return nil
}

func authorityContext(ctx context.Context, p device.Plan) (context.Context, context.CancelFunc, error) {
	deadline := p.ExpiresAt.Add(-time.Second)
	if ctx.Err() != nil || !time.Now().Before(deadline) || p.Validate(time.Now().Add(time.Second)) != nil {
		return nil, nil, device.ErrPlanExpired
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	return bounded, cancel, nil
}

func (s *control) caProxy() (*httputil.ReverseProxy, error) {
	u, e := url.Parse(s.config.CAURL)
	if e != nil {
		return nil, e
	}
	policy, e := s.snapshot.Role("authority-transport")
	if e != nil || policy.Endpoint != s.config.CAURL {
		return nil, device.ErrDenied
	}
	roots, e := s.snapshot.Roots("authority-transport")
	if e != nil {
		return nil, e
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: policy.PeerName, MinVersion: tls.VersionTLS12}
	tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return device.ErrDenied
		}
		leaf := cs.PeerCertificates[0]
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		now := time.Now()
		early, late := now.Add(-time.Second), now.Add(time.Second)
		var paths [][]*x509.Certificate
		for _, at := range []time.Time{early, late} {
			verified, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: policy.PeerName, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if e != nil {
				return device.ErrDenied
			}
			if paths == nil {
				paths = verified
			}
		}
		if policy.ValidateVerifiedInterval(paths, early, late) != nil {
			return device.ErrDenied
		}
		if len(policy.LeafPins) > 0 && !contains(policy.LeafPins, device.Hash(leaf.Raw)) {
			return device.ErrDenied
		}
		if len(policy.SPKIPins) > 0 && !contains(policy.SPKIPins, device.Hash(leaf.RawSubjectPublicKeyInfo)) {
			return device.ErrDenied
		}
		return nil
	}
	proxy.Transport = &countingCATransport{control: s, next: &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return freshTLSDial(ctx, network, address, tlsConfig, func() error {
			if ctx.Err() != nil {
				return device.ErrUnknown
			}
			if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
				return device.ErrUnknown
			}
			return nil
		})
	}}}
	original := proxy.Director
	proxy.Director = func(r *http.Request) {
		original(r)
		r.Host = u.Host
		r.GetBody = nil
		r.Header.Del("Idempotency-Key")
		r.Header.Del("X-Idempotency-Key")
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.TLS == nil || tlsConfig.VerifyConnection(*response.TLS) != nil {
			return device.ErrUnknown
		}
		if response.Request.URL.Path == "/sign" {
			return s.countCASign(false)
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "authority unavailable", http.StatusBadGateway)
	}
	return proxy, nil
}

func runControl(dir string) error {
	s, e := openControl(dir)
	if e != nil {
		return e
	}
	defer s.store.close()
	controlTLS, e := serviceTLS(dir, "control", s.snapshot, []string{"operational", "recovery", "observer"})
	if e != nil {
		return e
	}
	transportTLS, e := serviceTLS(dir, "transport", s.snapshot, []string{"operational"})
	if e != nil {
		return e
	}
	issuanceTLS, e := serviceTLS(dir, "issuance", s.snapshot, []string{"control"})
	if e != nil {
		return e
	}
	proxy, e := s.caProxy()
	if e != nil {
		return e
	}
	errch := make(chan error, 3)
	go func() {
		server := newServer(s.config.TransportAddress, http.HandlerFunc(s.challenge), transportTLS)
		server.ConnContext = s.connections.context
		server.ConnState = s.connections.state
		errch <- server.ListenAndServeTLS("", "")
	}()
	go func() {
		server := newServer(s.config.IssuanceAddress, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := peer(r)
			validInterval := r.TLS != nil && len(r.TLS.VerifiedChains) > 0
			if validInterval {
				callerRole, e := s.snapshot.Role("control")
				early, late := time.Now().Add(-time.Second), time.Now().Add(time.Second)
				validInterval = e == nil && callerRole.ValidateVerifiedInterval(r.TLS.VerifiedChains, early, late) == nil
			}
			if r.Method != "POST" || (r.URL.Path != "/sign" && r.URL.Path != "/revoke") || c == nil || device.Hash(c.Raw) != s.config.AuthorityCallerFingerprint || device.Hash(c.RawSubjectPublicKeyInfo) != s.config.AuthorityCallerPublicKeyDigest || !validInterval {
				http.Error(w, "authority action denied", http.StatusForbidden)
				return
			}
			proxy.ServeHTTP(w, r)
		}), issuanceTLS)
		errch <- server.ListenAndServeTLS("", "")
	}()
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/session-inventory", s.inventory)
		mux.HandleFunc("/", s.request)
		errch <- newServer(s.config.ControlAddress, mux, controlTLS).ListenAndServeTLS("", "")
	}()
	return <-errch
}

func newServer(address string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{Addr: address, Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 8192, ErrorLog: nil}
}
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
