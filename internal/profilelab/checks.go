// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"bufio"
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
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/knowndevice/knowndevice/internal/controller"
	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
	"github.com/knowndevice/knowndevice/internal/journal"
	"github.com/knowndevice/knowndevice/internal/keystore"
)

type checkReport struct {
	Scope              string   `json:"scope"`
	Architecture       string   `json:"architecture"`
	RuntimeEnvironment string   `json:"runtimeEnvironment"`
	Profile            string   `json:"profile"`
	Composition        string   `json:"composition"`
	AdapterExecution   string   `json:"adapterExecution"`
	TemplateDigest     string   `json:"templateDigest"`
	SnapshotDigest     string   `json:"snapshotDigest"`
	Passed             []string `json:"passed"`
	Skipped            []string `json:"skipped"`
	Hardware           string   `json:"hardware"`
	KD029              string   `json:"kd029"`
	KD030              string   `json:"kd030"`
}
type checks struct {
	dir, cliPath string
	config       device.Config
	snapshot     *device.PublicSnapshot
	services     servicesConfig
	report       checkReport
}

func (c *checks) cli(args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	args = append(args, "--config", filepath.Join(c.dir, "device.json"))
	cmd := exec.CommandContext(ctx, c.cliPath, args...)
	cmd.Env = append(os.Environ(), "KNOWNDEVICE_PROCESS_TIMING=1")
	var out, errout bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	err := cmd.Run()
	code := 0
	if err != nil {
		var e *exec.ExitError
		if errors.As(err, &e) {
			code = e.ExitCode()
		} else {
			return nil, -1, err
		}
	}
	if bytes.Contains(out.Bytes(), []byte("PRIVATE KEY")) || bytes.Contains(errout.Bytes(), []byte("PRIVATE KEY")) || bytes.Contains(out.Bytes(), []byte("\"ott\"")) || bytes.Contains(errout.Bytes(), []byte("\"ott\"")) {
		return nil, code, fmt.Errorf("private material in CLI output")
	}
	if errout.Len() > 0 && code != 0 {
		fmt.Printf("CLI exit %d: %s\n", code, errout.String())
	}
	return out.Bytes(), code, nil
}
func (c *checks) state() (device.State, error) {
	return journal.ReadV2(context.Background(), filepath.Join(c.config.StateDir, "journal.db"), c.snapshot.DeploymentID, c.snapshot.DeviceID, c.snapshot.Profile.ID, c.snapshot.Profile.Version, c.snapshot.Profile.PolicyDigest)
}
func (c *checks) plan(mode string) (device.Plan, error) {
	b, code, e := c.cli("plan", "--mode", mode)
	if e != nil || code != 0 {
		return device.Plan{}, fmt.Errorf("profile plan failed, exit %d", code)
	}
	var p device.Plan
	if e = json.Unmarshal(b, &p); e != nil {
		return p, e
	}
	e = writeJSON(filepath.Join(c.config.StateDir, "plan.json"), p)
	return p, e
}
func (c *checks) apply() (controller.Receipt, error) {
	b, code, e := c.cli("apply", "--plan", filepath.Join(c.config.StateDir, "plan.json"))
	var receipt controller.Receipt
	if e != nil {
		return receipt, e
	}
	if e = json.Unmarshal(b, &receipt); e != nil {
		return receipt, fmt.Errorf("invalid profile receipt, exit %d", code)
	}
	return receipt, nil
}
func (c *checks) finish() error {
	for i := 0; i < 3; i++ {
		b, code, e := c.cli("reconcile")
		if e != nil {
			return e
		}
		var receipt controller.Receipt
		if e = json.Unmarshal(b, &receipt); e != nil {
			return e
		}
		if code == 0 && receipt.Outcome == "succeeded" {
			return nil
		}
		if receipt.Outcome != "unknown" {
			return fmt.Errorf("profile reconcile %s at %s: %s", receipt.Outcome, receipt.Phase, receipt.Reason)
		}
	}
	return device.ErrUnknown
}
func (c *checks) pass(name string) error {
	fmt.Println("PASS", name)
	c.report.Passed = append(c.report.Passed, name)
	return writeJSON(filepath.Join(c.dir, "profile-check-report.json"), c.report)
}
func (c *checks) credential(h device.Handle) (tls.Certificate, []byte, error) {
	store, e := keystore.OpenReadOnlyV2(filepath.Join(c.config.StateDir, "slots"), c.snapshot.DeploymentID, c.snapshot.DeviceID, c.snapshot.Profile.ID, c.snapshot.Profile.Version, c.snapshot.Profile.PolicyDigest)
	if e != nil {
		return tls.Certificate{}, nil, e
	}
	defer store.Close()
	signer, e := store.Signer(context.Background(), h)
	if e != nil {
		return tls.Certificate{}, nil, e
	}
	chain, e := store.Certificate(context.Background(), h)
	if e != nil {
		return tls.Certificate{}, nil, e
	}
	certs, e := credentialprofile.ParseChain(chain)
	if e != nil {
		return tls.Certificate{}, nil, e
	}
	credential := tls.Certificate{PrivateKey: signer, Leaf: certs[0]}
	for _, cert := range certs {
		credential.Certificate = append(credential.Certificate, cert.Raw)
	}
	return credential, chain, nil
}
func (c *checks) counts() (uint64, error) {
	var n struct {
		Sign         uint64  `json:"sign"`
		SignAttempts *uint64 `json:"signAttempts"`
	}
	e := readJSON(filepath.Join(c.dir, "control", "ca-counts.json"), &n)
	if e != nil {
		return 0, e
	}
	if n.SignAttempts == nil {
		return 0, fmt.Errorf("authority dispatch counter is unavailable")
	}
	return *n.SignAttempts, nil
}
func (c *checks) call(role, path string, credential *tls.Certificate, in device.RoleRequest) (device.RoleResponse, error) {
	if in.RequestID == "" {
		id, e := device.RandomID()
		if e != nil {
			return device.RoleResponse{}, e
		}
		in.RequestID = id
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var response device.RoleResponse
	e := post(ctx, c.snapshot, role, path, credential, in, &response)
	return response, e
}

func runChecks(dir, cliPath string) error {
	cfg, e := device.LoadConfig(filepath.Join(dir, "device.json"))
	if e != nil {
		return e
	}
	services, snapshot, e := loadServices(dir)
	if e != nil {
		return e
	}
	environment := os.Getenv("KNOWNDEVICE_PROFILE_RUNTIME")
	if environment == "" {
		environment = "unknown: caller did not label host architecture or emulation"
	}
	c := &checks{dir: dir, cliPath: cliPath, config: cfg, snapshot: snapshot, services: services, report: checkReport{Scope: "linux-container-step-ca-profile-http", Architecture: runtime.GOARCH, RuntimeEnvironment: environment, Profile: snapshot.Profile.ID + "/1", TemplateDigest: services.TemplateDigest, SnapshotDigest: snapshot.Digest(), Hardware: "not-run: no named hardware", KD029: "not-established: same implementation author and local composition", KD030: "not-established: local generated lab withdrawal scope", Skipped: []string{"hardware-power-cut", "independent-second-profile", "shared-deployment-selective-withdrawal", "durable-application-backlog-transfer: policy explicitly has no state transfer"}}}
	c.report.Composition = fmt.Sprintf("%s/%d", snapshot.Composition.ID, snapshot.Composition.Version)
	c.report.AdapterExecution = "built-in"
	if snapshot.Composition.ID == "local-http-process-lab" {
		c.report.AdapterExecution = "process-stdio"
	}
	if _, code, e := c.cli("init"); e != nil || code != 0 {
		return fmt.Errorf("profile init failed, exit %d", code)
	}
	state, e := c.state()
	if e != nil {
		return e
	}
	if state.Active != nil || state.Operation != nil {
		return fmt.Errorf("profile checks require unused generated device state")
	}
	if _, e = c.plan("enroll"); e != nil {
		return e
	}
	receipt, e := c.apply()
	if e != nil {
		return e
	}
	if receipt.Outcome != "succeeded" {
		if e = c.finish(); e != nil {
			return e
		}
	}
	if e = c.pass("P1-real-profile-enrollment"); e != nil {
		return e
	}
	state, e = c.state()
	if e != nil || state.Active == nil {
		return fmt.Errorf("missing profile active state")
	}
	credential, chain, e := c.credential(*state.Active)
	if e != nil {
		return e
	}
	certs, e := credentialprofile.ParseChain(chain)
	if e != nil {
		return e
	}
	if e = snapshot.Profile.ValidateLeaf(certs[0], cfg.DeviceID, state.Active.Binding.Generation); e != nil {
		return e
	}
	if snapshot.Profile.ID == credentialprofile.StableID && (len(certs[0].DNSNames) != 0 || certs[0].Subject.CommonName != cfg.DeviceID || len(certs[0].ExtKeyUsage) != 1 || certs[0].ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("actual stable CA result violates CN/no-SAN/clientAuth")
	}
	if e = c.pass("P1-exact-step-ca-template-subject-san-clientAuth"); e != nil {
		return e
	}
	if e = c.unreserved(*state.Operation, &credential); e != nil {
		return e
	}
	if e = c.recoveryScope(state.Operation.Plan); e != nil {
		return e
	}
	for _, entry := range []struct {
		name    string
		fixture policy
	}{{"P10-staged-success-activation-persistence-refusal", policy{FailActivationPersistence: true}}, {"P11-candidate-verified-cannot-authorize-CAS", policy{StagedStatusOnly: true}}, {"P11-post-switch-wrong-revision-refusal", policy{WrongObservationRevision: true}}} {
		if e = c.activationFailure(entry.name, entry.fixture); e != nil {
			return e
		}
	}
	if e = c.liveWithdrawal(); e != nil {
		return e
	}
	if e = c.lostIssuance(); e != nil {
		return e
	}
	for _, phase := range []string{"planned", "key-created", "key-ready", "issue-intent", "issued-remote", "issued", "certificate-written", "register-intent", "registered-remote", "registered", "verified", "activate-intent", "activated-remote", "activated", "pointer-written", "committed", "broker-retire-intent", "broker-retired-remote", "broker-retired", "ca-revoke-intent", "ca-revoked-remote", "ca-revoked", "destroy-intent", "key-destroyed", "retired"} {
		if e = c.rotateAt(phase); e != nil {
			return e
		}
		if e = c.pass("P13-cli-SIGKILL-reconcile-" + phase); e != nil {
			return e
		}
	}
	if e = c.fencing(); e != nil {
		return e
	}
	if _, code, e := c.cli("probe"); e != nil || code != 0 {
		return fmt.Errorf("final actual application probe failed, exit %d", code)
	}
	if e = c.pass("fresh-final-target-application"); e != nil {
		return e
	}
	return nil
}

func (c *checks) rotateAt(phase string) error {
	p, e := c.plan("rotate")
	if e != nil {
		return e
	}
	before, e := c.counts()
	if e != nil {
		return e
	}
	marker := filepath.Join(c.config.StateDir, "checkpoint.marker")
	if e = os.Remove(marker); e != nil && !os.IsNotExist(e) {
		return e
	}
	cmd := exec.Command(c.cliPath, "apply", "--config", filepath.Join(c.dir, "device.json"), "--plan", filepath.Join(c.config.StateDir, "plan.json"))
	cmd.Env = append(os.Environ(), "KNOWNDEVICE_REFERENCE_LAB=1", "KNOWNDEVICE_LAB_PAUSE_AT="+phase, "KNOWNDEVICE_PROCESS_TIMING=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(35 * time.Second)
	reached := false
	for time.Now().Before(deadline) {
		if b, e := os.ReadFile(marker); e == nil && string(b) == phase {
			reached = true
			break
		}
		select {
		case <-done:
			return fmt.Errorf("profile controller exited before %s: %s %s", phase, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !reached {
		_ = cmd.Process.Kill()
		<-done
		return fmt.Errorf("profile checkpoint %s not reached: %s", phase, strings.TrimSpace(stderr.String()))
	}
	if e = cmd.Process.Kill(); e != nil {
		return e
	}
	if e = <-done; e == nil {
		return fmt.Errorf("profile SIGKILL unexpectedly succeeded")
	}
	if phase == "issued-remote" {
		fmt.Println("WAIT 45 seconds before known-result issuance reconciliation")
		started := time.Now()
		time.Sleep(45 * time.Second)
		if time.Since(started) < 45*time.Second {
			return fmt.Errorf("issuance restart delay not observed")
		}
	}
	if e = c.finish(); e != nil {
		return fmt.Errorf("profile restart after %s: %w", phase, e)
	}
	state, e := c.state()
	if e != nil || state.Active == nil || state.Active.Binding.Generation != p.TargetGeneration || state.Operation == nil || state.Operation.Phase != device.Retired {
		return fmt.Errorf("profile restart lost exact target after %s", phase)
	}
	after, e := c.counts()
	if e != nil || after != before+1 {
		return fmt.Errorf("profile restart sent duplicate or missing sign at %s", phase)
	}
	return nil
}

func (c *checks) unreserved(op device.Operation, current *tls.Certificate) error {
	key, e := newKey()
	if e != nil {
		return e
	}
	csr, e := c.snapshot.Profile.CreateCSR(key, c.config.DeviceID, op.Plan.TargetGeneration)
	if e != nil {
		return e
	}
	parsed, e := c.snapshot.Profile.ValidateCSR(csr, c.config.DeviceID, op.Plan.TargetGeneration)
	if e != nil {
		return e
	}
	authorityCaller, e := credentialAt(c.dir, "authority-caller")
	if e != nil {
		return e
	}
	server := control{dir: c.dir, config: c.services, snapshot: c.snapshot, authorityCaller: authorityCaller}
	chain, e := server.sign(context.Background(), &reservation{Plan: op.Plan, CSR: csr, Candidate: bound(op.Plan, parsed), IssueSent: true})
	if e != nil {
		return e
	}
	certs, e := credentialprofile.ParseChain(chain)
	if e != nil {
		return e
	}
	rogue := tls.Certificate{PrivateKey: key, Leaf: certs[0]}
	for _, cert := range certs {
		rogue.Certificate = append(rogue.Certificate, cert.Raw)
	}
	nonce, _ := device.RandomID()
	transport, _ := c.snapshot.Role("transport")
	probe := device.Probe{OperationID: op.Plan.OperationID, DeviceID: op.Plan.DeviceID, Generation: op.Plan.TargetGeneration, Endpoint: transport.Endpoint, Nonce: nonce, Deadline: time.Now().UTC().Add(30 * time.Second)}
	response, e := c.call("transport", "/challenge", &rogue, device.RoleRequest{Plan: op.Plan, Probe: probe})
	if e != nil || response.Status != "denied" {
		return fmt.Errorf("unreserved certificate received application access")
	}
	if e = c.pass("P3-real-unreserved-peer-leaf-key-denied"); e != nil {
		return e
	}
	response, e = c.call("control", "/activate", &rogue, device.RoleRequest{Plan: op.Plan, Certificate: chain})
	if e != nil || response.Status != "denied" {
		return fmt.Errorf("unreserved peer authorized activation CAS")
	}
	return c.pass("P3-same-subject-payload-cannot-select-generation")
}
func (c *checks) recoveryScope(p device.Plan) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.checkRecoveryScope(ctx, p, (&net.Dialer{Timeout: 5 * time.Second}).DialContext)
}

func (c *checks) checkRecoveryScope(ctx context.Context, p device.Plan, dial func(context.Context, string, string) (net.Conn, error)) error {
	unknown := fmt.Errorf("authenticated recovery application denial not observed: %w", device.ErrUnknown)
	recovery, e := credentialAt(c.dir, "recovery")
	if e != nil {
		return e
	}
	current := func() error {
		if ctx.Err() != nil || c.snapshot.ValidatePlan(p) != nil || p.Validate(time.Now().Add(time.Second)) != nil {
			return device.ErrUnknown
		}
		if leaf(recovery) == nil || device.Hash(leaf(recovery).Raw) != c.snapshot.RecoveryLeafPin || device.Hash(leaf(recovery).RawSubjectPublicKeyInfo) != c.snapshot.RecoverySPKIPin {
			return device.ErrUnknown
		}
		return validateCallerInterval(c.snapshot, &recovery)
	}
	if current() != nil {
		return unknown
	}
	role, e := c.snapshot.Role("application")
	if e != nil {
		return unknown
	}
	u, e := url.Parse(role.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" {
		return unknown
	}
	roots, e := c.snapshot.Roots("application")
	if e != nil {
		return unknown
	}
	config := &tls.Config{RootCAs: roots, ServerName: role.PeerName, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	offered := false
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if e := current(); e != nil {
			return nil, e
		}
		// Present the exact recovery leaf even when the Application role's CA list
		// excludes it. A missing-certificate alert would not prove its refusal.
		offered = true
		return &recovery, nil
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if current() != nil || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return device.ErrUnknown
		}
		server := state.PeerCertificates[0]
		if len(role.LeafPins) > 0 && !contains(role.LeafPins, device.Hash(server.Raw)) || len(role.SPKIPins) > 0 && !contains(role.SPKIPins, device.Hash(server.RawSubjectPublicKeyInfo)) {
			return device.ErrUnknown
		}
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		now := time.Now()
		early, late := now.Add(-time.Second), now.Add(time.Second)
		for _, at := range []time.Time{early, late} {
			paths, e := server.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: role.PeerName, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if e != nil || role.ValidateVerifiedInterval(paths, early, late) != nil {
				return device.ErrUnknown
			}
		}
		return nil
	}
	raw, e := dial(ctx, "tcp", u.Host)
	if e != nil {
		return unknown
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	deadline, ok := ctx.Deadline()
	if !ok || raw.SetDeadline(deadline) != nil {
		return unknown
	}
	connection := tls.Client(raw, config)
	if connection.HandshakeContext(ctx) != nil {
		return unknown
	}
	state := connection.ConnectionState()
	// VerifyConnection precedes CertificateVerify/Finished. Only a completed
	// TLS 1.3 handshake authenticates a subsequent protected peer alert.
	if !offered || !state.HandshakeComplete || state.Version != tls.VersionTLS13 || config.VerifyConnection(state) != nil {
		return unknown
	}
	id, e := device.RandomID()
	if e != nil {
		return unknown
	}
	body, e := json.Marshal(device.RoleRequest{Plan: p, RequestID: id})
	if e != nil {
		return unknown
	}
	u.Path = "/activate"
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if e != nil {
		return unknown
	}
	request.Header.Set("Content-Type", "application/json")
	// Read concurrently so a protected client-certificate refusal cannot be
	// hidden behind a blocked request write on an unbuffered connection.
	written := make(chan error, 1)
	go func() { written <- request.Write(connection) }()
	response, e := http.ReadResponse(bufio.NewReader(connection), request)
	if e != nil {
		_ = raw.Close()
		<-written
		if recoveryRoleAlert(e) && current() == nil && config.VerifyConnection(state) == nil {
			return c.pass("P4-P9-recovery-cannot-authorize-application")
		}
		return unknown
	}
	defer response.Body.Close()
	if <-written != nil || response.StatusCode != http.StatusOK {
		return unknown
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, (128<<10)+1))
	var result device.RoleResponse
	if e != nil || len(data) > 128<<10 || device.DecodeStrict(bytes.NewReader(data), &result) != nil || current() != nil || config.VerifyConnection(state) != nil {
		return unknown
	}
	v := result.Evidence
	now := time.Now().UTC()
	// Recovery has no operational generation; its denial must not name an
	// operational or other credential subject.
	if result.Status != "denied" || len(result.Certificate) != 0 || result.Application != nil || result.Withdrawal != nil || result.Inventory != nil || v == nil || v.Subject != (device.CredentialBinding{}) || v.APIVersion != device.V2 || v.Status != "denied" || v.Role != "application" || v.Action != "activate" || v.Plan != p || v.RequestID != id || v.Source != source(c.snapshot, "application") || v.Reference != p.OperationID || v.Revision == 0 || v.Deadline != p.ExpiresAt || v.ObservedAt.After(now.Add(time.Second)) || now.Sub(v.ObservedAt) > 5*time.Second {
		return unknown
	}
	return c.pass("P4-P9-recovery-cannot-authorize-application")
}

func recoveryRoleAlert(err error) bool {
	var remote *net.OpError
	if !errors.As(err, &remote) || remote.Op != "remote error" {
		return false
	}
	var alert tls.AlertError
	if errors.As(remote.Err, &alert) {
		return alert == 48 // unknown_ca, after the exact recovery leaf was offered.
	}
	// Go 1.27 TCP uses crypto/tls.alert; AlertError is used by QUIC.
	// Unrecognized representations and textual errors remain unknown.
	value := reflect.ValueOf(remote.Err)
	return value.IsValid() && value.Kind() == reflect.Uint8 && value.Type().PkgPath() == "crypto/tls" && value.Type().Name() == "alert" && value.Uint() == 48
}
func (c *checks) activationFailure(name string, fixture policy) error {
	before, e := c.state()
	if e != nil || before.Active == nil {
		return device.ErrUnknown
	}
	previous := *before.Active
	if e = writeJSON(filepath.Join(c.dir, "fixtures", "policy.json"), fixture); e != nil {
		return e
	}
	if _, e = c.plan("rotate"); e != nil {
		return e
	}
	receipt, e := c.apply()
	if e != nil || receipt.Outcome == "succeeded" {
		return fmt.Errorf("failed candidate activation unexpectedly committed")
	}
	after, e := c.state()
	if e != nil || after.Active == nil || *after.Active != previous {
		return fmt.Errorf("activation failure lost previous pointer")
	}
	if _, _, e = c.credential(previous); e != nil {
		return fmt.Errorf("activation failure lost previous signer")
	}
	if e = writeJSON(filepath.Join(c.dir, "fixtures", "policy.json"), policy{}); e != nil {
		return e
	}
	if e = c.finish(); e != nil {
		return e
	}
	return c.pass(name)
}
func (c *checks) liveWithdrawal() error {
	state, e := c.state()
	if e != nil || state.Active == nil {
		return device.ErrUnknown
	}
	old := *state.Active
	credential, _, e := c.credential(old)
	if e != nil {
		return e
	}
	connection, e := c.liveConnection(state.Operation.Plan, credential)
	if e != nil {
		return e
	}
	defer connection.Close()
	handshakeOnly, e := c.handshakeOnly(credential)
	if e != nil {
		return e
	}
	defer handshakeOnly.Close()
	if _, e = c.plan("rotate"); e != nil {
		return e
	}
	receipt, e := c.apply()
	if e != nil {
		return e
	}
	if receipt.Outcome != "succeeded" {
		if e = c.finish(); e != nil {
			return e
		}
	}
	after, e := c.state()
	if e != nil || after.Operation == nil || after.Operation.Retirement == nil || after.Operation.Retirement.Evidence == nil {
		return fmt.Errorf("missing final withdrawal evidence")
	}
	withdrawal := after.Operation.Retirement.Evidence
	if withdrawal.Previous.Generation != old.Binding.Generation || withdrawal.Denial.Kind != "denied" || !withdrawal.SessionsTerminated || withdrawal.Current.Phase != "activated" || withdrawal.Current.Active.Generation != after.Active.Binding.Generation || withdrawal.Current.ConnectionID == "" {
		return fmt.Errorf("incomplete effective withdrawal evidence")
	}
	if e = closedConnection(connection); e != nil {
		return e
	}
	if e = closedConnection(handshakeOnly); e != nil {
		return e
	}
	return c.pass("P14-P15-durable-exact-deny-old-session-termination-target-fresh")
}

func closedConnection(connection *tls.Conn) error {
	connection.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, e := connection.Read(b[:])
	if errors.Is(e, io.EOF) || errors.Is(e, syscall.ECONNRESET) {
		return nil
	}
	var timeout net.Error
	if errors.As(e, &timeout) && timeout.Timeout() {
		return fmt.Errorf("old connection termination remains unknown: read timeout")
	}
	return fmt.Errorf("old connection termination remains unknown: unsupported close observation")
}
func (c *checks) handshakeOnly(credential tls.Certificate) (*tls.Conn, error) {
	role, e := c.snapshot.Role("transport")
	if e != nil {
		return nil, e
	}
	u, e := url.Parse(role.Endpoint)
	if e != nil {
		return nil, e
	}
	roots, e := c.snapshot.Roots("transport")
	if e != nil {
		return nil, e
	}
	return tls.Dial("tcp", u.Host, &tls.Config{RootCAs: roots, ServerName: role.PeerName, Certificates: []tls.Certificate{credential}, MinVersion: tls.VersionTLS13})
}
func (c *checks) liveConnection(p device.Plan, credential tls.Certificate) (*tls.Conn, error) {
	role, e := c.snapshot.Role("transport")
	if e != nil {
		return nil, e
	}
	u, e := url.Parse(role.Endpoint)
	if e != nil {
		return nil, e
	}
	roots, e := c.snapshot.Roots("transport")
	if e != nil {
		return nil, e
	}
	conn, e := tls.Dial("tcp", u.Host, &tls.Config{RootCAs: roots, ServerName: role.PeerName, Certificates: []tls.Certificate{credential}, MinVersion: tls.VersionTLS13})
	if e != nil {
		return nil, e
	}
	nonce, _ := device.RandomID()
	id, _ := device.RandomID()
	in := device.RoleRequest{Plan: p, RequestID: id, Probe: device.Probe{OperationID: p.OperationID, DeviceID: p.DeviceID, Generation: p.TargetGeneration, Endpoint: role.Endpoint, Nonce: nonce, Deadline: time.Now().UTC().Add(30 * time.Second)}}
	body, _ := json.Marshal(in)
	request, e := http.NewRequest("POST", role.Endpoint+"/challenge", bytes.NewReader(body))
	if e != nil {
		conn.Close()
		return nil, e
	}
	if e = request.Write(conn); e != nil {
		conn.Close()
		return nil, e
	}
	response, e := http.ReadResponse(bufio.NewReader(conn), request)
	if e != nil {
		conn.Close()
		return nil, e
	}
	var result device.RoleResponse
	data, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || json.Unmarshal(data, &result) != nil || result.Status != "ok" {
		conn.Close()
		return nil, fmt.Errorf("old live connection probe failed")
	}
	return conn, nil
}
func (c *checks) lostIssuance() error {
	if e := writeJSON(filepath.Join(c.dir, "fixtures", "policy.json"), policy{LoseCAResult: true}); e != nil {
		return e
	}
	p, e := c.plan("rotate")
	if e != nil {
		return e
	}
	before, e := c.counts()
	if e != nil {
		return e
	}
	receipt, e := c.apply()
	if e != nil || receipt.Outcome != "unknown" {
		return fmt.Errorf("lost authority result did not stay unknown")
	}
	issued, e := c.counts()
	if e != nil || issued != before+1 {
		return fmt.Errorf("authority dispatch count did not record one attempt")
	}
	if e = writeJSON(filepath.Join(c.dir, "fixtures", "policy.json"), policy{}); e != nil {
		return e
	}
	if _, _, e = c.cli("reconcile"); e != nil {
		return e
	}
	after, e := c.counts()
	if e != nil || after != issued {
		return fmt.Errorf("unknown reconciliation resent raw sign")
	}
	state, e := c.state()
	if e != nil || state.Operation == nil || state.Operation.Plan != p {
		return fmt.Errorf("unknown reservation changed")
	}
	savedCSR := append([]byte(nil), state.Operation.CSR...)
	wrong := filepath.Join(c.dir, "control", "recovered-"+p.OperationID+".pem")
	fmt.Println("WAIT 45 seconds before exact unknown-result import")
	importWaitStarted := time.Now()
	time.Sleep(45 * time.Second)
	if time.Since(importWaitStarted) < 45*time.Second {
		return fmt.Errorf("unknown-result import delay not observed")
	}
	b, code, e := c.cli("reconcile", "--certificate", wrong)
	if e != nil {
		return e
	}
	if code != 0 {
		var r controller.Receipt
		_ = json.Unmarshal(b, &r)
		return fmt.Errorf("bounded actual chain import failed: %s %s", r.Phase, r.Reason)
	}
	after, e = c.counts()
	if e != nil || after != issued {
		return fmt.Errorf("import sent another sign request")
	}
	state, e = c.state()
	if e != nil || state.Operation == nil || !bytes.Equal(savedCSR, state.Operation.CSR) {
		return fmt.Errorf("import changed original CSR")
	}
	return c.pass("P7-P8-real-unknown-issuance-no-sign-replay-bounded-exact-import")
}
func (c *checks) fencing() error {
	state, e := c.state()
	if e != nil || state.Active == nil || state.Operation == nil {
		return device.ErrUnknown
	}
	credential, _, e := c.credential(*state.Active)
	if e != nil {
		return e
	}
	p, e := c.plan("rotate")
	if e != nil {
		return e
	}
	key, e := newKey()
	if e != nil {
		return e
	}
	csr, e := c.snapshot.Profile.CreateCSR(key, p.DeviceID, p.TargetGeneration)
	if e != nil {
		return e
	}
	if e = writeJSON(filepath.Join(c.dir, "fixtures", "policy.json"), policy{LoseCAResult: true}); e != nil {
		return e
	}
	response, e := c.call("control", "/issue", &credential, device.RoleRequest{Plan: p, CSR: csr})
	if e != nil || response.Status != "unknown" {
		return fmt.Errorf("direct fencing reservation did not consume unknown budget")
	}
	before, e := c.counts()
	if e != nil {
		return e
	}
	changed := p
	changed.OperationID, _ = device.RandomID()
	changed.TargetGeneration++
	changed.Digest, _ = changed.CalculateDigest()
	newKey, e := newKey()
	if e != nil {
		return e
	}
	otherCSR, e := c.snapshot.Profile.CreateCSR(newKey, changed.DeviceID, changed.TargetGeneration)
	if e != nil {
		return e
	}
	response, e = c.call("control", "/issue", &credential, device.RoleRequest{Plan: changed, CSR: otherCSR})
	if e != nil || response.Status != "conflict" {
		return fmt.Errorf("one unfinished operation fence failed")
	}
	response, e = c.call("control", "/issue", &credential, device.RoleRequest{Plan: p, CSR: otherCSR})
	if e != nil || (response.Status != "conflict" && response.Status != "denied") {
		return fmt.Errorf("immutable original CSR fence failed")
	}
	after, e := c.counts()
	if e != nil || after != before {
		return fmt.Errorf("fencing conflict sent raw sign")
	}
	if e = writeJSON(filepath.Join(c.dir, "fixtures", "policy.json"), policy{}); e != nil {
		return e
	}
	if e = c.pass("P2-P6-one-unfinished-counter-CSR-generation-fence"); e != nil {
		return e
	}
	c.report.Skipped = append(c.report.Skipped, "intentional final unknown reservation retained for intervention; no device apply or generation reuse")
	return writeJSON(filepath.Join(c.dir, "profile-check-report.json"), c.report)
}
