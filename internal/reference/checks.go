// SPDX-License-Identifier: Apache-2.0

package reference

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"knowndevice.local/knowndevice/adapters/controlhttp"
	"knowndevice.local/knowndevice/adapters/credentials"
	"knowndevice.local/knowndevice/adapters/mqttprobe"
	"knowndevice.local/knowndevice/internal/controller"
	"knowndevice.local/knowndevice/internal/device"
	"knowndevice.local/knowndevice/internal/journal"
	"knowndevice.local/knowndevice/internal/keystore"
)

type evidence struct {
	Scope            string   `json:"scope"`
	Architecture     string   `json:"architecture"`
	Tests            []string `json:"passed"`
	HardwarePowerCut string   `json:"hardwarePowerCut"`
}
type checks struct {
	dir      string
	cliPath  string
	config   device.Config
	evidence evidence
}

func referenceClient(cfg device.Config) (*controlhttp.Client, error) {
	roots, err := cfg.Roots()
	if err != nil {
		return nil, err
	}
	probe, err := mqttprobe.New(mqttprobe.Options{Endpoint: cfg.MQTTEndpoint, Roots: roots, Timeout: cfg.Timeout()})
	if err != nil {
		return nil, err
	}
	return controlhttp.New(controlhttp.Options{ControlURL: cfg.ControlURL, ApplicationURL: cfg.ApplicationURL, ControlRoots: roots, ApplicationRoots: roots, CertificateRoots: roots, ApplicationID: cfg.ApplicationID, ProbeEndpoint: cfg.MQTTEndpoint, Timeout: cfg.Timeout(), ProbeTransport: probe})
}

func (c *checks) cli(extraEnv []string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	all := append(args, "--config", filepath.Join(c.dir, "device.json"))
	cmd := exec.CommandContext(ctx, c.cliPath, all...)
	cmd.Env = append(os.Environ(), extraEnv...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code := 0
	if err != nil {
		var exited *exec.ExitError
		if errors.As(err, &exited) {
			code = exited.ExitCode()
		} else {
			return nil, -1, err
		}
	}
	if bytes.Contains(out.Bytes(), []byte("PRIVATE KEY")) || bytes.Contains(out.Bytes(), []byte("\"ott\"")) || bytes.Contains(errOut.Bytes(), []byte("PRIVATE KEY")) || bytes.Contains(errOut.Bytes(), []byte("\"ott\"")) {
		return nil, code, fmt.Errorf("secret material in CLI output")
	}
	return out.Bytes(), code, nil
}
func (c *checks) state() (device.State, error) {
	return journal.Read(context.Background(), filepath.Join(c.config.StateDir, "journal.db"), c.config.DeviceID)
}
func (c *checks) pass(name string) error {
	c.evidence.Tests = append(c.evidence.Tests, name)
	fmt.Println("PASS", name)
	return writeJSON(filepath.Join(c.dir, "check-report.json"), c.evidence)
}
func (c *checks) plan(mode string) (device.Plan, error) {
	b, code, err := c.cli(nil, "plan", "--mode", mode)
	if err != nil || code != 0 {
		return device.Plan{}, fmt.Errorf("plan failed (exit %d)", code)
	}
	var p device.Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if err := writeJSON(filepath.Join(c.config.StateDir, "plan.json"), p); err != nil {
		return p, err
	}
	return p, nil
}
func (c *checks) apply() (controller.Receipt, error) {
	b, code, err := c.cli(nil, "apply", "--plan", filepath.Join(c.config.StateDir, "plan.json"))
	if err != nil {
		return controller.Receipt{}, err
	}
	var r controller.Receipt
	if json.Unmarshal(b, &r) != nil {
		return r, fmt.Errorf("invalid apply report (exit %d)", code)
	}
	return r, nil
}
func (c *checks) finish() (controller.Receipt, error) {
	var r controller.Receipt
	for n := 0; n < 3; n++ {
		b, code, err := c.cli(nil, "reconcile")
		if err != nil {
			return r, err
		}
		if json.Unmarshal(b, &r) != nil {
			return r, fmt.Errorf("invalid reconciliation report (exit %d)", code)
		}
		if code == 0 && r.Outcome == "succeeded" {
			return r, nil
		}
		if r.Outcome != "unknown" {
			return r, fmt.Errorf("reconciliation %s at %s: %s", r.Outcome, r.Phase, r.Reason)
		}
		time.Sleep(300 * time.Millisecond)
	}
	return r, fmt.Errorf("reconciliation still unknown at %s", r.Phase)
}
func (c *checks) activeProbe() error {
	// ACL updates restart this demo broker and its independent responder.
	// Require a fresh successful observation after that bounded reconnect gap.
	for attempt := 0; attempt < 3; attempt++ {
		_, code, err := c.cli(nil, "probe")
		if err != nil {
			return err
		}
		if code == 0 {
			return nil
		}
		fmt.Println("WAIT active MQTT probe after broker restart")
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("active application probe failed after bounded reconnect observations")
}

func runChecks(dir, cli string) error {
	cfg, err := device.LoadConfig(filepath.Join(dir, "device.json"))
	if err != nil {
		return err
	}
	c := &checks{dir: dir, cliPath: cli, config: cfg, evidence: evidence{Scope: "linux-container-step-ca-mosquitto", Architecture: runtime.GOARCH, HardwarePowerCut: "not-run: no named hardware"}}
	if _, code, err := c.cli(nil, "init"); err != nil || code != 0 {
		return fmt.Errorf("lab init failed (exit %d)", code)
	}
	s, err := c.state()
	if err != nil {
		return err
	}
	if s.Operation != nil && s.Operation.Phase != device.Retired {
		return fmt.Errorf("checks require idle or completed state; reconcile existing operation first")
	}
	if s.Active == nil {
		if _, err := c.plan("enroll"); err != nil {
			return err
		}
		r, err := c.apply()
		if err != nil {
			return err
		}
		if r.Outcome != "succeeded" {
			if _, err := c.finish(); err != nil {
				return err
			}
		}
		if err := c.pass("real-enrollment"); err != nil {
			return err
		}
	} else {
		if err := c.pass("existing-enrolled-state-validated"); err != nil {
			return err
		}
	}
	if err := c.activeProbe(); err != nil {
		return err
	}
	if err := c.pass("fresh-external-mqtt-probe"); err != nil {
		return err
	}
	if err := c.denials(); err != nil {
		return err
	}
	if err := c.activationFailure(); err != nil {
		return err
	}
	if err := c.rotateAt("committed", true); err != nil {
		return err
	}
	if err := c.pass("live-session-termination-and-reconnect-acl-denial"); err != nil {
		return err
	}
	if err := c.aclFailure(); err != nil {
		return err
	}
	if err := c.staleFailure(); err != nil {
		return err
	}
	if err := c.lostCA(); err != nil {
		return err
	}
	for _, phase := range []string{"planned", "key-created", "key-ready", "issue-intent", "issued-remote", "issued", "certificate-written", "register-intent", "registered-remote", "registered", "verified", "activate-intent", "activated-remote", "activated", "pointer-written", "broker-retire-intent", "broker-retired-remote", "broker-retired", "ca-revoke-intent", "ca-revoked-remote", "ca-revoked", "destroy-intent", "key-destroyed", "retired"} {
		if err := c.rotateAt(phase, false); err != nil {
			return err
		}
		if err := c.pass("sigkill-restart-" + phase); err != nil {
			return err
		}
	}
	if _, err := c.plan("recover"); err != nil {
		return err
	}
	r, err := c.apply()
	if err != nil {
		return err
	}
	if r.Outcome != "succeeded" {
		if _, err := c.finish(); err != nil {
			return err
		}
	}
	if err := c.pass("separate-server-authorized-recovery"); err != nil {
		return err
	}
	if err := c.expiredRecovery(); err != nil {
		return err
	}
	if err := c.activeProbe(); err != nil {
		return err
	}
	return c.pass("receipt-redaction-and-final-active-probe")
}

func (c *checks) rotateAt(phase string, monitor bool) error {
	p, err := c.plan("rotate")
	if err != nil {
		return err
	}
	marker := filepath.Join(c.config.StateDir, "checkpoint.marker")
	if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
		return err
	}
	cmd := exec.Command(c.cliPath, "apply", "--config", filepath.Join(c.dir, "device.json"), "--plan", filepath.Join(c.config.StateDir, "plan.json"))
	cmd.Env = append(os.Environ(), "KNOWNDEVICE_REFERENCE_LAB=1", "KNOWNDEVICE_LAB_PAUSE_AT="+phase)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(35 * time.Second)
	reached := false
	retries := 0
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(marker); err == nil && string(b) == phase {
			reached = true
			break
		}
		select {
		case <-done:
			var failed controller.Receipt
			if json.Unmarshal(stdout.Bytes(), &failed) == nil && failed.Outcome == "unknown" && retries < 2 {
				retries++
				stdout.Reset()
				stderr.Reset()
				cmd = exec.Command(c.cliPath, "reconcile", "--config", filepath.Join(c.dir, "device.json"))
				cmd.Env = append(os.Environ(), "KNOWNDEVICE_REFERENCE_LAB=1", "KNOWNDEVICE_LAB_PAUSE_AT="+phase)
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				if err := cmd.Start(); err != nil {
					return err
				}
				go func(command *exec.Cmd) { done <- command.Wait() }(cmd)
				continue
			}
			return fmt.Errorf("controller exited before checkpoint %s: %s", phase, strings.TrimSpace(stdout.String()))
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !reached {
		cmd.Process.Kill()
		<-done
		return fmt.Errorf("checkpoint %s not reached", phase)
	}
	var connection *mqttprobe.Connection
	if monitor {
		keys, err := keystore.OpenReadOnly(filepath.Join(c.config.StateDir, "slots"))
		if err != nil {
			return err
		}
		// The writer is paused and holds the journal lock; read the previous public
		// handle from its plan's expected slot instead through the active manifests.
		var previous device.Handle
		slot := "A"
		if p.TargetSlot == "A" {
			slot = "B"
		}
		b, err := os.ReadFile(filepath.Join(c.config.StateDir, "slots", slot, "manifest.json"))
		if err != nil {
			keys.Close()
			return err
		}
		var manifest struct {
			SchemaVersion int           `json:"schemaVersion"`
			Handle        device.Handle `json:"handle"`
		}
		if json.Unmarshal(b, &manifest) != nil {
			keys.Close()
			return fmt.Errorf("previous manifest invalid")
		}
		previous = manifest.Handle
		e := controller.Engine{Config: c.config, Keys: keys}
		cred, err := controller.CredentialFor(context.Background(), &e, previous)
		keys.Close()
		if err != nil {
			return err
		}
		roots, err := c.config.Roots()
		if err != nil {
			return err
		}
		connection, err = mqttprobe.Open(context.Background(), mqttprobe.Options{Endpoint: c.config.MQTTEndpoint, Roots: roots, Timeout: c.config.Timeout()}, cred)
		if err != nil {
			return err
		}
		_, reply, _ := mqttprobe.Topics(c.config.DeviceID, p.ExpectedGeneration)
		if err := connection.Subscribe(context.Background(), reply); err != nil {
			return err
		}
		defer connection.Close(context.Background())
		if _, code, err := c.cli(nil, "apply", "--plan", filepath.Join(c.config.StateDir, "plan.json")); err != nil || code != 4 {
			return fmt.Errorf("second writer not rejected (exit %d)", code)
		}
		if err := c.pass("two-real-controller-processes"); err != nil {
			return err
		}
	}
	if err := cmd.Process.Kill(); err != nil {
		return err
	}
	if err := <-done; err == nil {
		return fmt.Errorf("SIGKILL process unexpectedly succeeded")
	}
	if _, err := c.finish(); err != nil {
		return fmt.Errorf("after %s: %w", phase, err)
	}
	if monitor {
		select {
		case <-connection.Done():
		case <-time.After(5 * time.Second):
			return fmt.Errorf("old live MQTT session survived retirement")
		}
	}
	s, err := c.state()
	if err != nil {
		return err
	}
	if s.Active == nil || s.Active.Binding.Generation != p.TargetGeneration || s.Operation == nil || s.Operation.Phase != device.Retired {
		return fmt.Errorf("restart lost committed target after %s", phase)
	}
	return nil
}

func (c *checks) denials() error {
	path := filepath.Join(c.dir, "fixtures", "entitlement.json")
	var ent entitlement
	if err := readJSON(path, &ent); err != nil {
		return err
	}
	original := ent
	defer writeJSON(path, original)
	for _, status := range []string{"revoked", "retired"} {
		ent.Status = status
		if err := writeJSON(path, ent); err != nil {
			return err
		}
		if _, code, err := c.cli(nil, "recover", "--preflight"); err != nil || code != 3 {
			return fmt.Errorf("%s device recovery was not denied", status)
		}
		if err := c.pass("fresh-registry-" + status + "-recovery-denied"); err != nil {
			return err
		}
	}
	if err := writeJSON(path, original); err != nil {
		return err
	}
	configPath := filepath.Join(c.dir, "device.json")
	var cfg device.Config
	if err := readJSON(configPath, &cfg); err != nil {
		return err
	}
	originalCfg := cfg
	defer writeJSON(configPath, originalCfg)
	cfg.RecoveryCertificate = ""
	cfg.RecoveryKey = ""
	if err := writeJSON(configPath, cfg); err != nil {
		return err
	}
	if _, code, err := c.cli(nil, "recover", "--preflight"); err != nil || code != 3 {
		return fmt.Errorf("missing recovery was not denied")
	}
	if err := writeJSON(configPath, originalCfg); err != nil {
		return err
	}
	if err := c.pass("missing-recovery-denied"); err != nil {
		return err
	}
	if err := c.expiredRecoverySigner(originalCfg, original); err != nil {
		return err
	}
	cfg = originalCfg
	cfg.ClockTrust = "untrusted"
	if err := writeJSON(configPath, cfg); err != nil {
		return err
	}
	if _, code, err := c.cli(nil, "recover", "--preflight"); err != nil || code != 3 {
		return fmt.Errorf("untrusted recovery clock was not denied")
	}
	if err := writeJSON(configPath, originalCfg); err != nil {
		return err
	}
	return c.pass("untrusted-clock-denied")
}

func (c *checks) expiredRecoverySigner(cfg device.Config, ent entitlement) error {
	// Only this trusted generated-data runner can read the demo CA key.
	rootPEM, err := os.ReadFile(filepath.Join(c.dir, "root.crt"))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(c.dir, "ca", "root.key"))
	if err != nil {
		return err
	}
	ca, err := tls.X509KeyPair(rootPEM, keyPEM)
	if err != nil {
		return err
	}
	root, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return err
	}
	recovery, err := keystore.LoadCredential(cfg.RecoveryCertificate, cfg.RecoveryKey)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(recovery.Certificate[0])
	if err != nil {
		return err
	}
	leaf.NotBefore = time.Now().Add(-2 * time.Hour)
	leaf.NotAfter = time.Now().Add(-time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, leaf.PublicKey, ca.PrivateKey)
	if err != nil {
		return err
	}
	expiredPath := filepath.Join(c.dir, "recovery", "expired.pem")
	if err := atomic(expiredPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return err
	}
	configPath := filepath.Join(c.dir, "device.json")
	entPath := filepath.Join(c.dir, "fixtures", "entitlement.json")
	originalCfg, originalEnt := cfg, ent
	defer writeJSON(configPath, originalCfg)
	defer writeJSON(entPath, originalEnt)
	cfg.RecoveryCertificate = expiredPath
	ent.RecoveryFingerprint = device.Hash(der)
	if err := writeJSON(configPath, cfg); err != nil {
		return err
	}
	if err := writeJSON(entPath, ent); err != nil {
		return err
	}
	if _, code, err := c.cli(nil, "recover", "--preflight"); err != nil || code != 3 {
		return fmt.Errorf("expired pinned recovery signer was not denied")
	}
	return c.pass("expired-recovery-signer-denied")
}

func (c *checks) aclFailure() error {
	s, err := c.state()
	if err != nil {
		return err
	}
	p, err := c.plan("rotate")
	if err != nil {
		return err
	}
	path := filepath.Join(c.dir, "fixtures", "policy.json")
	defer writeJSON(path, policy{})
	if err := writeJSON(path, policy{DenyProbe: true, DenyGeneration: p.TargetGeneration}); err != nil {
		return err
	}
	r, err := c.apply()
	if err != nil {
		return err
	}
	if r.Outcome != "blocked" || r.ActiveGeneration != s.Active.Binding.Generation || r.PreviousRetired {
		return fmt.Errorf("MQTT ACL denial committed or retired a generation")
	}
	if err := c.activeProbe(); err != nil {
		return err
	}
	if err := c.pass("real-mqtt-acl-denial-preserves-active"); err != nil {
		return err
	}
	if err := writeJSON(path, policy{}); err != nil {
		return err
	}
	// Reapply the same durable registration through the service; the ACL change
	// is operator fixture configuration, not a change to the approved plan.
	if err := c.reapplyRegistration(p); err != nil {
		return err
	}
	_, err = c.finish()
	return err
}
func (c *checks) reapplyRegistration(p device.Plan) error {
	// Service restart replays its durable desired policy before opening MQTT.
	// The runner cannot restart sibling containers; ask the scoped same-plan
	// registration endpoint to reapply that policy through a target credential.
	keys, err := keystore.OpenReadOnly(filepath.Join(c.config.StateDir, "slots"))
	if err != nil {
		return err
	}
	defer keys.Close()
	s, err := c.state()
	if err != nil || s.Operation == nil || s.Operation.Target == nil {
		return device.ErrConflict
	}
	e := controller.Engine{Config: c.config, Keys: keys}
	cred, err := controller.CredentialFor(context.Background(), &e, *s.Operation.Target)
	if err != nil {
		return err
	}
	client, err := referenceClient(c.config)
	if err != nil {
		return err
	}
	return client.Register(context.Background(), p, cred)
}
func (c *checks) staleFailure() error {
	s, err := c.state()
	if err != nil {
		return err
	}
	if _, err := c.plan("rotate"); err != nil {
		return err
	}
	path := filepath.Join(c.dir, "fixtures", "policy.json")
	defer writeJSON(path, policy{})
	if err := writeJSON(path, policy{StaleReply: true}); err != nil {
		return err
	}
	r, err := c.apply()
	if err != nil {
		return err
	}
	for attempt := 0; r.Outcome == "unknown" && attempt < 2; attempt++ {
		b, _, err := c.cli(nil, "reconcile")
		if err != nil || json.Unmarshal(b, &r) != nil {
			return fmt.Errorf("stale nonce reconciliation unreadable")
		}
	}
	if r.Outcome != "blocked" || r.ActiveGeneration != s.Active.Binding.Generation || r.PreviousRetired {
		return fmt.Errorf("mismatched MQTT nonce committed a generation")
	}
	if err := writeJSON(path, policy{}); err != nil {
		return err
	}
	if err := c.pass("real-wire-stale-nonce-rejected"); err != nil {
		return err
	}
	_, err = c.finish()
	return err
}
func (c *checks) lostCA() error {
	s, err := c.state()
	if err != nil {
		return err
	}
	if _, err := c.plan("rotate"); err != nil {
		return err
	}
	path := filepath.Join(c.dir, "fixtures", "policy.json")
	defer writeJSON(path, policy{})
	if err := writeJSON(path, policy{LoseCAResponse: true}); err != nil {
		return err
	}
	r, err := c.apply()
	if err != nil {
		return err
	}
	if r.Outcome != "unknown" || r.Phase != device.IssueIntent || r.ActiveGeneration != s.Active.Binding.Generation {
		return fmt.Errorf("lost CA response did not preserve unknown/current generation")
	}
	countPath := filepath.Join(c.dir, "control", "ca-sign-count.json")
	beforeCount, err := os.ReadFile(countPath)
	if err != nil {
		return err
	}
	_, code, err := c.cli(nil, "reconcile")
	if err != nil || code != 3 {
		return fmt.Errorf("unknown issuance was blindly retried")
	}
	afterCount, err := os.ReadFile(countPath)
	if err != nil || !bytes.Equal(beforeCount, afterCount) {
		return fmt.Errorf("unknown issuance repeated a real CA request")
	}
	var result struct {
		Certificate string          `json:"crt"`
		CA          string          `json:"ca"`
		Chain       []string        `json:"certChain"`
		TLSOptions  json.RawMessage `json:"tlsOptions"`
	}
	if err := readJSON(filepath.Join(c.dir, "control", "recovered-sign-response.json"), &result); err != nil {
		return err
	}
	var chain []byte
	for _, cert := range result.Chain {
		chain = append(chain, []byte(cert)...)
		chain = append(chain, '\n')
	}
	if len(chain) == 0 {
		chain = []byte(result.Certificate + "\n" + result.CA)
	}
	publicPath := filepath.Join(c.config.StateDir, "recovered.pem")
	if err := atomic(publicPath, chain); err != nil {
		return err
	}
	if err := writeJSON(path, policy{}); err != nil {
		return err
	}
	b, code, err := c.cli(nil, "reconcile", "--certificate", publicPath)
	if err != nil {
		return err
	}
	if code != 0 {
		var r controller.Receipt
		if json.Unmarshal(b, &r) != nil || r.Phase == device.IssueIntent {
			return fmt.Errorf("bounded recovered certificate import failed")
		}
		if _, err := c.finish(); err != nil {
			return err
		}
	}
	return c.pass("real-ca-lost-response-unknown-and-bounded-import")
}

func (c *checks) credential(h device.Handle) (device.Credential, error) {
	keys, err := keystore.OpenReadOnly(filepath.Join(c.config.StateDir, "slots"))
	if err != nil {
		return device.Credential{}, err
	}
	defer keys.Close()
	e := controller.Engine{Config: c.config, Keys: keys}
	return controller.CredentialFor(context.Background(), &e, h)
}

func (c *checks) raw(cert tls.Certificate, base, path string, input controlhttp.Request) (controlhttp.Response, error) {
	roots, err := c.config.Roots()
	if err != nil {
		return controlhttp.Response{}, err
	}
	b, err := json.Marshal(input)
	if err != nil {
		return controlhttp.Response{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	endpoint, err := url.Parse(base)
	if err != nil {
		return controlhttp.Response{}, err
	}
	endpoint.Path = path
	r, err := http.NewRequestWithContext(ctx, "POST", endpoint.String(), bytes.NewReader(b))
	if err != nil {
		return controlhttp.Response{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(r)
	if err != nil {
		return controlhttp.Response{}, err
	}
	defer response.Body.Close()
	var output controlhttp.Response
	if response.StatusCode != 200 || device.DecodeStrict(io.LimitReader(response.Body, 128<<10), &output) != nil {
		return output, fmt.Errorf("raw service request failed")
	}
	return output, nil
}

func (c *checks) activationFailure() error {
	before, err := c.state()
	if err != nil || before.Active == nil {
		return device.ErrConflict
	}
	original := *before.Active
	old, err := c.credential(original)
	if err != nil {
		return err
	}
	recoveryPlan, err := controller.NewPlan(c.config, before, "recover", time.Now().UTC())
	if err != nil {
		return err
	}
	response, err := c.raw(old.TLS, c.config.ControlURL, "/v1/authorize", controlhttp.Request{Plan: recoveryPlan})
	if err != nil || response.Status != "denied" {
		return fmt.Errorf("operational signer acquired recovery authorization")
	}
	if err := c.pass("server-recovery-role-denies-operational-signer"); err != nil {
		return err
	}
	p, err := c.plan("rotate")
	if err != nil {
		return err
	}
	policyPath := filepath.Join(c.dir, "fixtures", "policy.json")
	defer writeJSON(policyPath, policy{})
	if err := writeJSON(policyPath, policy{DenyActivation: true}); err != nil {
		return err
	}
	r, err := c.apply()
	if err != nil {
		return err
	}
	if r.Phase == device.Registered && r.Outcome == "unknown" {
		_, _, err = c.cli(nil, "reconcile")
		if err != nil {
			return err
		}
	}
	state, err := c.state()
	if err != nil || state.Operation == nil || state.Operation.Phase != device.ActivateIntent || state.Active == nil || *state.Active != original {
		return fmt.Errorf("activation failure did not preserve local current generation")
	}
	current, err := c.credential(*state.Operation.Target)
	if err != nil {
		return err
	}
	targetChain, err := credentials.PublicChain(current)
	if err != nil {
		return err
	}
	nonce, _ := device.RandomID()
	fake := device.Activation{OperationID: p.OperationID, PlanDigest: p.Digest, DeviceID: p.DeviceID, ApplicationID: c.config.ApplicationID, Generation: p.TargetGeneration, CertificateFingerprint: device.Hash(current.TLS.Certificate[0]), SessionID: nonce, Probe: device.Probe{OperationID: p.OperationID, DeviceID: p.DeviceID, Generation: p.TargetGeneration, Endpoint: c.config.MQTTEndpoint, Nonce: nonce, Deadline: time.Now().UTC().Add(5 * time.Second)}}
	response, err = c.raw(current.TLS, c.config.ControlURL, "/v1/activated", controlhttp.Request{Plan: p, Handle: state.Operation.Target, Certificate: targetChain, Activation: &fake})
	if err != nil || response.Status != "denied" {
		return fmt.Errorf("self-issued activation receipt advanced server generation")
	}
	if err := c.pass("server-rejects-self-issued-activation-receipt"); err != nil {
		return err
	}
	controlCert, err := keystore.LoadServiceCredential(filepath.Join(c.dir, "control", "cert.pem"), filepath.Join(c.dir, "control", "key.pem"), x509.ExtKeyUsageClientAuth)
	if err != nil {
		return err
	}
	oldChain, err := credentials.PublicChain(old)
	if err != nil {
		return err
	}
	oldInput := controlhttp.Request{Plan: before.Operation.Plan, Handle: &original, Certificate: oldChain}
	oldBefore, err := c.raw(controlCert, c.config.ApplicationURL, "/v1/observed", oldInput)
	if err != nil || oldBefore.Status != "ok" || oldBefore.Activation == nil {
		return fmt.Errorf("old application did not reconnect before failure test")
	}
	if _, code, err := c.cli(nil, "reconcile"); err != nil || code != 3 {
		return fmt.Errorf("activation failure unexpectedly completed")
	}
	oldAfter, err := c.raw(controlCert, c.config.ApplicationURL, "/v1/observed", oldInput)
	if err != nil || oldAfter.Status != "ok" || oldAfter.Activation == nil || oldAfter.Activation.SessionID != oldBefore.Activation.SessionID {
		return fmt.Errorf("failed target activation closed the old application session")
	}
	if err := c.activeProbe(); err != nil {
		return err
	}
	if err := c.pass("failed-activation-preserves-old-app-session-and-pointer"); err != nil {
		return err
	}
	if err := writeJSON(policyPath, policy{}); err != nil {
		return err
	}
	_, err = c.finish()
	return err
}

func (c *checks) expiredRecovery() error {
	path := filepath.Join(c.dir, "fixtures", "policy.json")
	defer writeJSON(path, policy{})
	if err := writeJSON(path, policy{ShortCertificate: true}); err != nil {
		return err
	}
	if _, err := c.plan("rotate"); err != nil {
		return err
	}
	r, err := c.apply()
	if err != nil {
		return err
	}
	if r.Outcome != "succeeded" {
		if _, err := c.finish(); err != nil {
			return err
		}
	}
	if err := writeJSON(path, policy{}); err != nil {
		return err
	}
	state, err := c.state()
	if err != nil || state.Active == nil {
		return device.ErrConflict
	}
	credential, err := c.credential(*state.Active)
	if err != nil {
		return err
	}
	leaf := credential.TLS.Leaf
	if leaf == nil || time.Until(leaf.NotAfter) > 35*time.Second {
		return fmt.Errorf("real short-lived CA certificate not issued")
	}
	fmt.Println("WAIT real certificate expiry; system clock unchanged")
	for time.Now().Before(leaf.NotAfter.Add(time.Second)) {
		time.Sleep(200 * time.Millisecond)
	}
	if _, code, err := c.cli(nil, "probe"); err != nil || code != 3 {
		return fmt.Errorf("expired operational generation remained locally usable")
	}
	if _, err := c.plan("recover"); err != nil {
		return err
	}
	r, err = c.apply()
	if err != nil {
		return err
	}
	if r.Outcome != "succeeded" {
		if _, err := c.finish(); err != nil {
			return err
		}
	}
	return c.pass("real-expiry-recovery-with-current-auth-and-old-tls-denial")
}
