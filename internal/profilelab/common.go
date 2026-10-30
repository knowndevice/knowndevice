// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
	"github.com/knowndevice/knowndevice/internal/keystore"
)

type servicesConfig struct {
	SchemaVersion                  int    `json:"schemaVersion"`
	DeviceConfig                   string `json:"deviceConfig"`
	Snapshot                       []byte `json:"snapshot"`
	ConfigDigest                   string `json:"configDigest"`
	CAURL                          string `json:"caURL"`
	ControlAddress                 string `json:"controlAddress"`
	ApplicationAddress             string `json:"applicationAddress"`
	TransportAddress               string `json:"transportAddress"`
	IssuanceAddress                string `json:"issuanceAddress"`
	RecoveryFingerprint            string `json:"recoveryFingerprint"`
	RecoveryPublicKeyDigest        string `json:"recoveryPublicKeyDigest"`
	ObserverFingerprint            string `json:"observerFingerprint"`
	ObserverPublicKeyDigest        string `json:"observerPublicKeyDigest"`
	AuthorityCallerFingerprint     string `json:"authorityCallerFingerprint"`
	AuthorityCallerPublicKeyDigest string `json:"authorityCallerPublicKeyDigest"`
	TemplateDigest                 string `json:"templateDigest"`
}

type entitlement struct {
	DeploymentID string    `json:"deploymentId"`
	DeviceID     string    `json:"deviceId"`
	Status       string    `json:"status"`
	Revision     uint64    `json:"revision"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type policy struct {
	LoseCAResult              bool   `json:"loseCAResult"`
	DenyGeneration            uint64 `json:"denyGeneration"`
	FailActivationPersistence bool   `json:"failActivationPersistence"`
	StagedStatusOnly          bool   `json:"stagedStatusOnly"`
	WrongObservationRevision  bool   `json:"wrongObservationRevision"`
	PauseAt                   string `json:"pauseAt,omitempty"`
}

// Only the generated lab selects these explicit failure checkpoints. Its
// immutable marker names the operation; a real process kill remains external.
func labCheckpoint(ctx context.Context, dir, role, phase string, p device.Plan) error {
	label := role + ":" + phase
	var fixture policy
	if e := readJSON(filepath.Join(dir, "fixtures", "policy.json"), &fixture); e != nil {
		return device.ErrUnknown
	}
	if fixture.PauseAt != label {
		return nil
	}
	marker := filepath.Join(dir, role, "checkpoint-"+p.OperationID+"-"+phase+".json")
	if e := writeJSON(marker, map[string]string{"role": role, "phase": phase, "operationId": p.OperationID, "planDigest": p.Digest}); e != nil {
		return device.ErrUnknown
	}
	for {
		if ctx.Err() != nil || !time.Now().Add(time.Second).Before(p.ExpiresAt) {
			return device.ErrUnknown
		}
		if e := readJSON(filepath.Join(dir, "fixtures", "policy.json"), &fixture); e != nil {
			return device.ErrUnknown
		}
		if fixture.PauseAt != label {
			return nil
		}
		select {
		case <-ctx.Done():
			return device.ErrUnknown
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func readJSON(path string, v any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return device.DecodeStrict(f, v)
}
func writeAtomic(path string, b []byte) error {
	f, e := os.OpenFile(path+".pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(e) {
		info, statErr := os.Lstat(path + ".pending")
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return device.ErrConflict
		}
		existing, readErr := os.ReadFile(path + ".pending")
		if readErr != nil || !bytes.Equal(existing, b) {
			return device.ErrConflict
		}
		f, e = os.Open(path + ".pending")
		if e != nil {
			return e
		}
		e = f.Sync()
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		if e = os.Rename(path+".pending", path); e != nil {
			return e
		}
		d, e := os.Open(filepath.Dir(path))
		if e != nil {
			return e
		}
		defer d.Close()
		return d.Sync()
	}
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(path+".pending", path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return writeAtomic(path, append(b, '\n'))
}

func loadServices(dir string) (servicesConfig, *device.PublicSnapshot, error) {
	var cfg servicesConfig
	if e := readJSON(filepath.Join(dir, "services.json"), &cfg); e != nil {
		return cfg, nil, e
	}
	if cfg.SchemaVersion != 2 {
		return cfg, nil, fmt.Errorf("profile service configuration version refused")
	}
	snapshot, e := device.DecodeSnapshot(cfg.Snapshot)
	if e != nil {
		return cfg, nil, e
	}
	if cfg.ConfigDigest != snapshot.Digest() {
		return cfg, nil, fmt.Errorf("allowed service configuration differs from immutable snapshot")
	}
	if snapshot.Composition.AuthorityTemplateDigest != cfg.TemplateDigest {
		return cfg, nil, fmt.Errorf("authority template composition binding mismatch")
	}
	if cfg.RecoveryFingerprint != snapshot.RecoveryLeafPin || cfg.RecoveryPublicKeyDigest != snapshot.RecoverySPKIPin {
		return cfg, nil, fmt.Errorf("recovery registry pins differ from immutable snapshot")
	}
	observer, e := snapshot.Role("observer")
	if e != nil || !contains(observer.LeafPins, cfg.ObserverFingerprint) || !contains(observer.SPKIPins, cfg.ObserverPublicKeyDigest) {
		return cfg, nil, fmt.Errorf("observer caller differs from immutable snapshot")
	}
	executable, e := os.Executable()
	if e != nil {
		return cfg, nil, e
	}
	artifact, e := os.ReadFile(executable)
	if e != nil {
		return cfg, nil, e
	}
	artifactDigest := device.Hash(artifact)
	for _, adapter := range snapshot.Composition.Adapters {
		if adapter.Role != "clock" && adapter.Role != "transport" && adapter.ArtifactDigest != artifactDigest {
			return cfg, nil, fmt.Errorf("service artifact differs from immutable composition")
		}
	}
	issuer, e := snapshot.Role("issuance")
	if e != nil || !contains(issuer.CallerLeafPins, cfg.AuthorityCallerFingerprint) || !contains(issuer.CallerSPKIPins, cfg.AuthorityCallerPublicKeyDigest) {
		return cfg, nil, fmt.Errorf("authority caller differs from immutable issuance trust")
	}
	backend, e := snapshot.Role("authority-transport")
	if e != nil || backend.Endpoint != cfg.CAURL {
		return cfg, nil, fmt.Errorf("authority transport differs from immutable snapshot")
	}
	b, e := os.ReadFile(filepath.Join(dir, "ca", "profile.tpl"))
	if e != nil || device.Hash(b) != cfg.TemplateDigest {
		return cfg, nil, fmt.Errorf("authority template differs from immutable snapshot")
	}
	return cfg, snapshot, nil
}

func credentialAt(dir, role string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, role, "cert.pem"), filepath.Join(dir, role, "key.pem")
	if role == "recovery" {
		return keystore.LoadCredential(certPath, keyPath)
	}
	purpose := x509.ExtKeyUsageClientAuth
	if role == "control" || role == "application" || role == "transport" || role == "issuance" {
		purpose = x509.ExtKeyUsageServerAuth
	}
	return keystore.LoadServiceCredential(certPath, keyPath, purpose)
}
func leaf(c tls.Certificate) *x509.Certificate {
	if c.Leaf != nil {
		return c.Leaf
	}
	if len(c.Certificate) == 0 {
		return nil
	}
	v, _ := x509.ParseCertificate(c.Certificate[0])
	return v
}
func peer(req *http.Request) *x509.Certificate {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return nil
	}
	return req.TLS.PeerCertificates[0]
}
func matches(c *x509.Certificate, b device.CredentialBinding) bool {
	return c != nil && device.Hash(c.Raw) == b.CertificateFingerprint && device.Hash(c.RawSubjectPublicKeyInfo) == b.PublicKeyDigest
}
func bound(p device.Plan, csr *x509.CertificateRequest) device.CredentialBinding {
	return device.CredentialBinding{DeploymentID: p.DeploymentID, DeviceID: p.DeviceID, OperationID: p.OperationID, PlanDigest: p.Digest, ConfigDigest: p.ConfigDigest, SnapshotDigest: p.SnapshotDigest, ProfileID: p.ProfileID, ProfileVersion: p.ProfileVersion, ProfileDigest: p.ProfileDigest, Generation: p.TargetGeneration, PublicKeyDigest: device.Hash(csr.RawSubjectPublicKeyInfo), CSRDigest: device.Hash(csr.Raw)}
}

func evidence(p device.Plan, subject device.CredentialBinding, role, action, requestID string, revision uint64, source, status string) device.Evidence {
	return device.Evidence{APIVersion: "knowndevice/v1alpha2", Role: role, Action: action, RequestID: requestID, Plan: p, Subject: subject, Revision: revision, Reference: p.OperationID, Source: source, ObservedAt: time.Now().UTC(), Deadline: p.ExpiresAt, Status: status}
}

func serviceTLS(dir, role string, snapshot *device.PublicSnapshot, clients []string) (*tls.Config, error) {
	c, e := credentialAt(dir, role)
	if e != nil {
		return nil, e
	}
	rs, e := snapshot.Role(role)
	if e != nil {
		return nil, e
	}
	serverLeaf := leaf(c)
	if serverLeaf == nil || len(rs.LeafPins) > 0 && !contains(rs.LeafPins, device.Hash(serverLeaf.Raw)) || len(rs.SPKIPins) > 0 && !contains(rs.SPKIPins, device.Hash(serverLeaf.RawSubjectPublicKeyInfo)) {
		return nil, device.ErrDenied
	}
	roots, e := snapshot.Roots(role)
	if e != nil {
		return nil, e
	}
	intermediates := x509.NewCertPool()
	for _, der := range c.Certificate[1:] {
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, e
		}
		intermediates.AddCert(cert)
	}
	now := time.Now()
	early, late := now.Add(-time.Second), now.Add(time.Second)
	for _, at := range []time.Time{early, late} {
		paths, e := serverLeaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: rs.PeerName, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if e != nil {
			return nil, device.ErrDenied
		}
		if rs.ValidateVerifiedInterval(paths, early, late) != nil {
			return nil, device.ErrDenied
		}
	}
	config := &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	if len(clients) > 0 {
		roots := x509.NewCertPool()
		for _, r := range clients {
			for _, rs := range snapshot.Trust {
				if rs.Role == r {
					for _, der := range rs.Anchors {
						cert, e := x509.ParseCertificate(der)
						if e != nil {
							return nil, e
						}
						roots.AddCert(cert)
					}
				}
			}
		}
		if len(roots.Subjects()) == 0 {
			return nil, fmt.Errorf("explicit service client trust required")
		}
		config.ClientCAs = roots
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return config, nil
}

func verifyPeerRole(req *http.Request, snapshot *device.PublicSnapshot, role string) error {
	c := peer(req)
	if c == nil || c.IsCA || len(c.UnhandledCriticalExtensions) != 0 {
		return device.ErrDenied
	}
	roots, e := snapshot.Roots(role)
	if e != nil {
		return device.ErrDenied
	}
	rs, e := snapshot.Role(role)
	if e != nil {
		return device.ErrDenied
	}
	intermediates := x509.NewCertPool()
	for _, cert := range req.TLS.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	now := time.Now()
	early, late := now.Add(-time.Second), now.Add(time.Second)
	for _, at := range []time.Time{early, late} {
		paths, e := c.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		if e != nil {
			return device.ErrDenied
		}
		if rs.ValidateVerifiedInterval(paths, early, late) != nil {
			return device.ErrDenied
		}
	}
	for _, rs := range snapshot.Trust {
		if rs.Role == role {
			if rs.PeerName != "" && role == "observer" && c.VerifyHostname(rs.PeerName) != nil {
				return device.ErrDenied
			}
			if len(rs.LeafPins) > 0 {
				ok := false
				for _, pin := range rs.LeafPins {
					ok = ok || pin == device.Hash(c.Raw)
				}
				if !ok {
					return device.ErrDenied
				}
			}
			if len(rs.SPKIPins) > 0 {
				ok := false
				for _, pin := range rs.SPKIPins {
					ok = ok || pin == device.Hash(c.RawSubjectPublicKeyInfo)
				}
				if !ok {
					return device.ErrDenied
				}
			}
			return nil
		}
	}
	return device.ErrDenied
}

// Requests use the already resolved public DER. No ambient roots or proxies enter a dial.
func post(ctx context.Context, snapshot *device.PublicSnapshot, role, path string, credential *tls.Certificate, input, output any) error {
	var rs *device.RoleSnapshot
	for i := range snapshot.Trust {
		if snapshot.Trust[i].Role == role {
			rs = &snapshot.Trust[i]
			break
		}
	}
	if rs == nil {
		return device.ErrUnsupported
	}
	checkRequest := func() error {
		if ctx.Err() != nil {
			return device.ErrUnknown
		}
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return device.ErrUnknown
		}
		if in, ok := input.(device.RoleRequest); ok {
			if snapshot.ValidatePlan(in.Plan) != nil {
				return device.ErrDenied
			}
			latest := time.Now().Add(time.Second)
			when := latest
			if path == "/status" || path == "/lookup" || path == "/registration" || path == "/revocation-status" {
				when = in.Plan.ExpiresAt.Add(-time.Nanosecond)
			}
			if in.Plan.Validate(when) != nil || in.Probe.Nonce != "" && device.MatchProbe(in.Probe, in.Probe, latest) != nil {
				return device.ErrDenied
			}
		}
		return validateCallerInterval(snapshot, credential)
	}
	if e := checkRequest(); e != nil {
		return e
	}
	u, e := url.Parse(rs.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" {
		return device.ErrDenied
	}
	roots, e := snapshot.Roots(role)
	if e != nil {
		return e
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: rs.PeerName, SessionTicketsDisabled: true}
	if credential != nil {
		tlsConfig.Certificates = []tls.Certificate{*credential}
	}
	tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if e := checkRequest(); e != nil {
			return e
		}
		if len(cs.PeerCertificates) == 0 {
			return device.ErrDenied
		}
		c := cs.PeerCertificates[0]
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		now := time.Now()
		early, late := now.Add(-time.Second), now.Add(time.Second)
		for _, at := range []time.Time{early, late} {
			paths, e := c.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: rs.PeerName, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if e != nil {
				return device.ErrDenied
			}
			if rs.ValidateVerifiedInterval(paths, early, late) != nil {
				return device.ErrDenied
			}
		}
		if len(rs.LeafPins) > 0 {
			ok := false
			for _, p := range rs.LeafPins {
				ok = ok || p == device.Hash(c.Raw)
			}
			if !ok {
				return device.ErrDenied
			}
		}
		if len(rs.SPKIPins) > 0 {
			ok := false
			for _, p := range rs.SPKIPins {
				ok = ok || p == device.Hash(c.RawSubjectPublicKeyInfo)
			}
			if !ok {
				return device.ErrDenied
			}
		}
		return nil
	}
	t := &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true, Proxy: nil, ForceAttemptHTTP2: false, DialTLSContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
		return freshTLSDial(dialCtx, network, address, tlsConfig, checkRequest)
	}}
	defer t.CloseIdleConnections()
	client := &http.Client{Transport: t, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return device.ErrDenied }}
	b, e := json.Marshal(input)
	if e != nil {
		return e
	}
	u.Path = path
	request, e := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(b))
	if e != nil {
		return e
	}
	request.Header.Set("Content-Type", "application/json")
	request.GetBody = nil
	response, e := client.Do(request)
	if e != nil {
		return device.ErrUnknown
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && !(role == "issuance" && path == "/sign" && response.StatusCode == http.StatusCreated) {
		return device.ErrUnknown
	}
	if response.TLS == nil || tlsConfig.VerifyConnection(*response.TLS) != nil {
		return device.ErrUnknown
	}
	responseBytes, e := io.ReadAll(io.LimitReader(response.Body, (128<<10)+1))
	if e != nil || len(responseBytes) > 128<<10 {
		return device.ErrUnknown
	}
	if e = device.DecodeStrict(bytes.NewReader(responseBytes), output); e != nil {
		return e
	}
	if tlsConfig.VerifyConnection(*response.TLS) != nil || checkRequest() != nil {
		return device.ErrUnknown
	}
	return nil
}

func freshTLSDial(ctx context.Context, network, address string, config *tls.Config, current func() error) (net.Conn, error) {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: config}
	connection, e := dialer.DialContext(ctx, network, address)
	if e != nil {
		return nil, e
	}
	state := connection.(*tls.Conn).ConnectionState()
	if e = current(); e == nil && config.VerifyConnection != nil {
		e = config.VerifyConnection(state)
	}
	if e != nil {
		_ = connection.Close()
		return nil, e
	}
	return connection, nil
}

func validateCallerInterval(snapshot *device.PublicSnapshot, credential *tls.Certificate) error {
	if credential == nil {
		return nil
	}
	c := leaf(*credential)
	if c == nil || c.IsCA || len(c.UnhandledCriticalExtensions) != 0 {
		return device.ErrDenied
	}
	role := "operational"
	fingerprint, spki := device.Hash(c.Raw), device.Hash(c.RawSubjectPublicKeyInfo)
	observer, e := snapshot.Role("observer")
	if e != nil {
		return e
	}
	issuance, e := snapshot.Role("issuance")
	if e != nil {
		return e
	}
	switch {
	case fingerprint == snapshot.RecoveryLeafPin && spki == snapshot.RecoverySPKIPin:
		role = "recovery"
	case contains(observer.LeafPins, fingerprint) && contains(observer.SPKIPins, spki):
		role = "observer"
	case contains(issuance.CallerLeafPins, fingerprint) && contains(issuance.CallerSPKIPins, spki):
		role = "control"
	}
	rs, e := snapshot.Role(role)
	if e != nil {
		return e
	}
	roots, e := snapshot.Roots(role)
	if e != nil {
		return e
	}
	intermediates := x509.NewCertPool()
	for _, der := range credential.Certificate[1:] {
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return device.ErrDenied
		}
		intermediates.AddCert(cert)
	}
	now := time.Now()
	early, late := now.Add(-time.Second), now.Add(time.Second)
	for _, at := range []time.Time{early, late} {
		paths, e := c.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		if e != nil || rs.ValidateVerifiedInterval(paths, early, late) != nil {
			return device.ErrDenied
		}
	}
	return nil
}

func reply(w http.ResponseWriter, response device.RoleResponse, err error) {
	if err != nil {
		response.Status = "unknown"
		for _, entry := range []struct {
			err    error
			status string
		}{{device.ErrDenied, "denied"}, {device.ErrConflict, "conflict"}, {device.ErrNotFound, "not-started"}, {device.ErrUnsupported, "unsupported"}, {device.ErrPlanExpired, "intervention-required"}} {
			if errors.Is(err, entry.err) {
				response.Status = entry.status
				break
			}
		}
		if response.Evidence != nil {
			response.Evidence.Status = response.Status
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func contains(pins []string, want string) bool {
	for _, pin := range pins {
		if pin == want {
			return true
		}
	}
	return false
}
func decodeRequest(w http.ResponseWriter, req *http.Request) (device.RoleRequest, error) {
	var input device.RoleRequest
	if req.Method != "POST" {
		return input, device.ErrDenied
	}
	e := device.DecodeStrict(http.MaxBytesReader(w, req.Body, 128<<10), &input)
	if e != nil {
		return input, device.ErrDenied
	}
	if len(input.RequestID) != 32 {
		return input, device.ErrDenied
	}
	return input, nil
}
func checkEntitlement(dir string, p device.Plan) (entitlement, error) {
	var ent entitlement
	if e := readJSON(filepath.Join(dir, "fixtures", "entitlement.json"), &ent); e != nil || ent.DeploymentID != p.DeploymentID || ent.DeviceID != p.DeviceID || ent.Status != "authorized" || ent.Revision == 0 || !time.Now().Add(time.Second).Before(ent.ExpiresAt) {
		return ent, device.ErrDenied
	}
	return ent, nil
}

func certificateValidation(snapshot *device.PublicSnapshot, activation, issuance bool) (credentialprofile.Validation, error) {
	now := time.Now().UTC()
	v, e := snapshot.Validation(now.Add(-time.Second), now.Add(time.Second), activation, false)
	if issuance {
		v.MaxBackdate = time.Duration(snapshot.Limits.MaxBackdateSeconds) * time.Second
	}
	return v, e
}
func validateInstalled(snapshot *device.PublicSnapshot, r *reservation, activation, issuance bool) error {
	v, e := certificateValidation(snapshot, activation, issuance)
	if e != nil {
		return e
	}
	return snapshot.Profile.ValidateChain(r.Certificate, r.CSR, r.Candidate.PublicKeyDigest, r.Plan.DeviceID, r.Plan.TargetGeneration, v)
}
