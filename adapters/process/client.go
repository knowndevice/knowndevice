// SPDX-License-Identifier: Apache-2.0

package process

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/knowndevice/knowndevice/sdk/device"
)

type grant struct {
	signer crypto.Signer
	key    *ecdsa.PublicKey
}
type pendingCall struct {
	method    string
	scope     *Scope
	grants    map[string]grant
	signCalls int
	response  chan message
	delivered bool
}

// initializeTimeout bounds adapter start-up and the initialize exchange. Package
// tests raise it because their adapter is the race-enabled test binary.
var initializeTimeout = 5 * time.Second

// Client owns one initialized session. A lost/canceled call makes it terminal.
// Reconciliation starts a fresh session and explicitly invokes the role's lookup.
type Client struct {
	snapshot     *device.PublicSnapshot
	capabilities []string
	cmd          *exec.Cmd
	stdin        io.WriteCloser
	stdout       io.ReadCloser
	stderr       io.ReadCloser
	writer       protocolWriter
	done         chan struct{}
	waited       chan struct{}
	mu           sync.Mutex
	terminal     bool
	pending      map[string]*pendingCall
	ids          map[string]string
	plans        map[string]device.Plan
	domain       chan struct{}
	clock        chan struct{}
	controlGate  chan struct{}
	stageDir     string
	log          io.Writer
	closeOnce    sync.Once
}

func Start(ctx context.Context, opts Options) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot, err := processSnapshot(opts.Snapshot, opts.ArtifactDigest)
	if err != nil {
		return nil, err
	}
	if opts.Limits != (Limits{}) && opts.Limits != DefaultLimits() {
		return nil, device.ErrUnsupported
	}
	if !filepath.IsAbs(opts.WorkDir) || filepath.Clean(opts.WorkDir) != opts.WorkDir || len(opts.Args) > 16 {
		return nil, device.ErrDenied
	}
	argsBytes := 0
	for _, arg := range opts.Args {
		argsBytes += len(arg)
		if len(arg) > 1024 {
			return nil, device.ErrDenied
		}
	}
	if argsBytes > 8<<10 {
		return nil, device.ErrDenied
	}
	data, err := executableBytes(opts.Executable)
	if err != nil || digestBytes(data) != opts.ArtifactDigest {
		return nil, device.ErrDenied
	}
	ancestor := opts.WorkDir
	for {
		if _, err = os.Lstat(ancestor); err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return nil, device.ErrDenied
		}
		next := filepath.Dir(ancestor)
		if next == ancestor {
			return nil, device.ErrDenied
		}
		ancestor = next
	}
	if noSymlinks(ancestor) != nil {
		return nil, device.ErrDenied
	}
	if err = os.MkdirAll(opts.WorkDir, 0700); err != nil {
		return nil, device.ErrDenied
	}
	info, err := os.Lstat(opts.WorkDir)
	if err != nil || noSymlinks(opts.WorkDir) != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, device.ErrDenied
	}
	stage, err := os.MkdirTemp(opts.WorkDir, "adapter-")
	if err != nil {
		return nil, device.ErrDenied
	}
	staged := filepath.Join(stage, "adapter")
	f, err := os.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0500)
	if err != nil {
		return nil, device.ErrDenied
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || ctx.Err() != nil {
		return nil, device.ErrDenied
	}
	cmd := exec.Command(staged, opts.Args...)
	cmd.Dir = stage
	cmd.Env = []string{"LANG=C", "TZ=UTC"}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, device.ErrDenied
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, device.ErrDenied
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		stdout.Close()
		return nil, device.ErrDenied
	}
	if err = cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return nil, device.ErrDenied
	}
	c := &Client{snapshot: snapshot, cmd: cmd, stdin: stdin, stdout: stdout, stderr: stderr, writer: protocolWriter{out: stdin}, done: make(chan struct{}), waited: make(chan struct{}), pending: map[string]*pendingCall{}, ids: map[string]string{}, plans: map[string]device.Plan{}, domain: make(chan struct{}, 1), clock: make(chan struct{}, 1), controlGate: make(chan struct{}, 1), stageDir: stage, log: opts.Log}
	go c.readResponses()
	go c.drainStderr()
	go func() { _ = cmd.Wait(); close(c.waited); c.stop(false) }()
	permissions, err := ExpectedPermissions(snapshot)
	if err != nil {
		c.stop(false)
		return nil, err
	}
	required := append([]string(nil), opts.RequiredCapabilities...)
	if len(required) == 0 {
		required = defaultRequired(snapshot)
	}
	if !sortedUnique(required, 32) {
		c.stop(false)
		return nil, device.ErrUnsupported
	}
	params := InitializeParams{[]string{ProtocolVersion}, []string{ErrorVersion}, []SchemaIdentity{Schema()}, opts.ArtifactDigest, snapshot.Digest(), snapshot.Composition.Digest(), snapshot.Profile, snapshot.Bytes(), required, permissions, DefaultLimits()}
	initCtx, cancel := context.WithTimeout(ctx, initializeTimeout)
	defer cancel()
	var result InitializeResult
	if err = c.control(initCtx, "plugin.initialize", params, "initializeResult", &result); err != nil {
		c.stop(false)
		return nil, err
	}
	if result.ProtocolVersion != ProtocolVersion || result.ErrorVersion != ErrorVersion || len(result.Schemas) != 1 || result.Schemas[0] != Schema() || result.ArtifactDigest != opts.ArtifactDigest || result.SnapshotDigest != snapshot.Digest() || result.CompositionDigest != snapshot.Composition.Digest() || result.Profile != snapshot.Profile || result.Limits != DefaultLimits() || !samePermissions(result.Permissions, permissions) || !sortedUnique(result.Capabilities, 32) {
		c.stop(false)
		return nil, device.ErrUnknown
	}
	for _, capability := range required {
		if !has(result.Capabilities, capability) {
			c.stop(false)
			return nil, device.ErrUnsupported
		}
	}
	c.capabilities = result.Capabilities
	return c, nil
}

func (c *Client) stop(grace bool) {
	c.mu.Lock()
	if c.terminal {
		c.mu.Unlock()
		return
	}
	c.terminal = true
	for id, p := range c.pending {
		p.grants = nil
		c.ids[id] = "canceled"
	}
	close(c.done)
	c.mu.Unlock()
	go func() {
		if grace {
			timer := time.NewTimer(time.Second)
			select {
			case <-timer.C:
			case <-c.waited:
				timer.Stop()
			}
		}
		_ = c.stdin.Close()
		_ = c.cmd.Process.Kill()
		_ = c.stdout.Close()
		_ = c.stderr.Close()
	}()
}

func (c *Client) send(ctx context.Context, m message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- c.writer.write(m) }()
	select {
	case err := <-finished:
		if err != nil {
			c.stop(false)
		}
		return err
	case <-ctx.Done():
		c.stop(false)
		return device.ErrUnknown
	case <-c.done:
		return device.ErrUnknown
	}
}

func (c *Client) begin(method string, scope *Scope) (string, *pendingCall, error) {
	random, err := device.RandomID()
	if err != nil {
		return "", nil, device.ErrDenied
	}
	id := "h-" + random
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal {
		return "", nil, device.ErrUnknown
	}
	if len(c.ids) >= DefaultLimits().MaxRequests {
		return "", nil, device.ErrUnsupported
	}
	if _, exists := c.ids[id]; exists {
		return "", nil, device.ErrUnknown
	}
	p := &pendingCall{method: method, scope: scope, grants: map[string]grant{}, response: make(chan message, 1)}
	c.ids[id] = "pending"
	c.pending[id] = p
	return id, p, nil
}

func (c *Client) finish(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.pending[id]; p != nil {
		p.grants = nil
		delete(c.pending, id)
		if c.ids[id] != "canceled" {
			c.ids[id] = "completed"
		}
	}
}

func (c *Client) exchange(ctx context.Context, id string, p *pendingCall, params any, resultDef string, out any) (err error) {
	started := time.Now()
	defer func() { c.logRequest(ctx, p.method, started, err) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	m, err := request(id, p.method, params)
	if err != nil {
		return err
	}
	if _, ok := domainMethods[p.method]; ok {
		if validateDefinition(domainMethods[p.method], m.Params) != nil {
			return device.ErrDenied
		}
	}
	if err = c.send(ctx, m); err != nil {
		return device.ErrUnknown
	}
	select {
	case response := <-p.response:
		if err := ctx.Err(); err != nil {
			c.cancel(id, p)
			return device.ErrUnknown
		}
		if response.Error != nil {
			data, _ := json.Marshal(response.Error)
			if validateDefinition("rpcError", data) != nil || !validError(response.Error, p.method, p.scope) {
				c.stop(false)
				return device.ErrUnknown
			}
			err := mapError(response.Error, p.method, p.scope)
			return err
		}
		if decodeDefinition(resultDef, response.Result, out) != nil {
			c.stop(false)
			return device.ErrUnknown
		}
		if p.scope != nil {
			var bound struct {
				Scope Scope `json:"scope"`
			}
			if json.Unmarshal(response.Result, &bound) != nil || !p.scope.equal(bound.Scope) || !time.Now().Before(p.scope.Deadline) {
				c.stop(false)
				return device.ErrUnknown
			}
		}
		return nil
	case <-ctx.Done():
		c.cancel(id, p)
		return device.ErrUnknown
	case <-c.done:
		return device.ErrUnknown
	}
}

// logRequest writes one line per request with the method, the elapsed and
// available milliseconds and a coarse result; identifiers and payloads stay out.
func (c *Client) logRequest(ctx context.Context, method string, started time.Time, err error) {
	if c.log == nil {
		return
	}
	budget := "none"
	if deadline, ok := ctx.Deadline(); ok {
		budget = strconv.FormatInt(deadline.Sub(started).Milliseconds(), 10)
	}
	_, _ = fmt.Fprintf(c.log, "adapter request method=%s elapsed_ms=%d budget_ms=%s result=%s\n", method, time.Since(started).Milliseconds(), budget, requestResult(err))
}

func requestResult(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, device.ErrUnknown):
		return "unknown"
	case errors.Is(err, device.ErrDenied):
		return "denied"
	case errors.Is(err, device.ErrConflict):
		return "conflict"
	case errors.Is(err, device.ErrUnsupported):
		return "unsupported"
	case errors.Is(err, device.ErrPlanExpired):
		return "plan-expired"
	case errors.Is(err, device.ErrNotFound):
		return "not-found"
	}
	return "error"
}

func (c *Client) cancel(id string, p *pendingCall) {
	c.mu.Lock()
	p.grants = nil
	c.mu.Unlock()
	if p.scope != nil {
		m, _ := request("", "operation.cancel", CancelParams{id, *p.scope})
		m.ID = nil
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_ = c.send(ctx, m)
		cancel()
	}
	c.stop(true)
}

func (c *Client) control(ctx context.Context, method string, params any, resultDef string, out any) error {
	select {
	case c.controlGate <- struct{}{}:
		defer func() { <-c.controlGate }()
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return device.ErrUnknown
	}
	id, p, err := c.begin(method, nil)
	if err != nil {
		return err
	}
	defer c.finish(id)
	return c.exchange(ctx, id, p, params, resultDef, out)
}

func (c *Client) invoke(ctx context.Context, method string, plan device.Plan, operands []device.Credential, params func(Scope, []WireCredential) any, resultDef string, out any) error {
	if !has(c.capabilities, method) {
		return device.ErrUnsupported
	}
	select {
	case c.domain <- struct{}{}:
		defer func() { <-c.domain }()
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return device.ErrUnknown
	}
	deadline := time.Now().Add(time.Duration(c.snapshot.RequestTimeoutSeconds) * time.Second)
	if plan.ExpiresAt.Before(deadline) {
		deadline = plan.ExpiresAt
	}
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	scope := scopeFor(plan, deadline)
	if err := validateScope(c.snapshot, plan, scope); err != nil {
		return err
	}
	if err := c.SetPlan(plan); err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	id, p, err := c.begin(method, &scope)
	if err != nil {
		return err
	}
	defer c.finish(id)
	wires := make([]WireCredential, 0, len(operands))
	for index, credential := range operands {
		artifactOnly := index == 0 && (method == "authority.revoke" || method == "authority.revocationStatus")
		ref := ""
		if !artifactOnly {
			ref, err = device.RandomID()
			if err != nil {
				return device.ErrDenied
			}
		}
		w, signer, err := wirePublic(credential, ref)
		if err != nil {
			return err
		}
		key, err := publicKey(w.PublicSPKI)
		if err != nil {
			return err
		}
		c.mu.Lock()
		if c.terminal || p.grants == nil {
			c.mu.Unlock()
			return device.ErrUnknown
		}
		if !artifactOnly {
			p.grants[ref] = grant{signer, key}
		}
		c.mu.Unlock()
		wires = append(wires, w)
	}
	return c.exchange(ctx, id, p, params(scope, wires), resultDef, out)
}

func (c *Client) readResponses() {
	r := bufio.NewReaderSize(c.stdout, 32<<10)
	for {
		line, err := readLine(r, DefaultLimits())
		if err != nil {
			c.stop(false)
			return
		}
		m, err := decodeMessage(line, DefaultLimits())
		if err != nil {
			c.stop(false)
			return
		}
		if m.Method != "" {
			if m.Method != "signer.sign" || m.ID == nil || (*m.ID)[:2] != "s-" {
				c.stop(false)
				return
			}
			if validateDefinition("request", line) != nil {
				c.stop(false)
				return
			}
			c.mu.Lock()
			_, duplicate := c.ids[*m.ID]
			if !duplicate && len(c.ids) < DefaultLimits().MaxRequests {
				c.ids[*m.ID] = "reverse"
			} else {
				duplicate = true
			}
			c.mu.Unlock()
			if duplicate {
				c.stop(false)
				return
			}
			go c.sign(m)
			continue
		}
		if m.ID == nil || (*m.ID)[:2] != "h-" {
			c.stop(false)
			return
		}
		c.mu.Lock()
		p := c.pending[*m.ID]
		state := c.ids[*m.ID]
		if state == "canceled" {
			c.mu.Unlock()
			continue
		}
		if p == nil || p.delivered {
			c.mu.Unlock()
			c.stop(false)
			return
		}
		p.delivered = true
		c.mu.Unlock()
		p.response <- m
	}
}

func (c *Client) sign(m message) {
	var input SignParams
	if decodeDefinition("signParams", m.Params, &input) != nil {
		c.stop(false)
		return
	}
	c.mu.Lock()
	p := c.pending[input.ParentID]
	var g grant
	allowed := false
	if p != nil && !c.terminal && p.scope != nil && p.scope.equal(input.Scope) && !p.delivered && time.Now().Before(input.Scope.Deadline) && p.signCalls < DefaultLimits().MaxSignerCalls {
		g, allowed = p.grants[input.SignerRef]
		if allowed {
			p.signCalls++
		}
	}
	c.mu.Unlock()
	if !allowed {
		c.stop(false)
		return
	}
	h, err := hashAlgorithm(input.Hash, len(input.Digest))
	if err != nil {
		c.stop(false)
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), input.Scope.Deadline)
	defer cancel()
	type signed struct {
		bytes []byte
		err   error
	}
	result := make(chan signed, 1)
	go func() {
		signature, err := g.signer.Sign(rand.Reader, input.Digest, h)
		result <- signed{signature, err}
	}()
	var response message
	select {
	case signature := <-result:
		if signature.err != nil || len(signature.bytes) > DefaultLimits().MaxSignatureBytes || !ecdsa.VerifyASN1(g.key, input.Digest, signature.bytes) {
			response = message{JSONRPC: "2.0", ID: m.ID, Error: rpcError("denied", &input.Scope)}
		} else {
			response, _ = success(m.ID, SignResult{signature.bytes})
		}
	case <-ctx.Done():
		return
	case <-c.done:
		return
	}
	c.mu.Lock()
	active := p.grants != nil && !c.terminal
	c.mu.Unlock()
	if !active {
		return
	}
	_ = c.send(ctx, response)
}

func (c *Client) drainStderr() {
	buffer := make([]byte, 4096)
	total := 0
	for {
		n, err := c.stderr.Read(buffer)
		total += n
		if total > DefaultLimits().MaxStderrBytes {
			c.stop(false)
			break
		}
		if err != nil {
			break
		}
	}
	if c.log != nil {
		_, _ = fmt.Fprintf(c.log, "adapter stderr bytes=%d\n", total)
	}
}

func (c *Client) SetPlan(plan device.Plan) error {
	if c.snapshot.ValidatePlan(plan) != nil {
		return device.ErrConflict
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.plans[plan.OperationID]; ok && old != plan {
		return device.ErrConflict
	}
	if len(c.plans) >= DefaultLimits().MaxRequests {
		return device.ErrUnsupported
	}
	c.plans[plan.OperationID] = plan
	return nil
}

func (c *Client) Adapters() device.Adapters {
	return device.Adapters{Entitlement: c, Authority: c, Platform: c, Transport: c, Application: c, Clock: c, Withdrawal: c}
}
func (c *Client) Roles() device.Roles {
	return device.Roles{Entitlement: c, Platform: c, Transport: c, Application: c, Withdrawal: c, Clock: c}
}

func (c *Client) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var result HealthResult
	err := c.control(ctx, "plugin.health", Empty{}, "healthResult", &result)
	if err == nil && result.Status != "ok" {
		return device.ErrUnknown
	}
	return err
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		var result Empty
		_ = c.control(ctx, "plugin.shutdown", Empty{}, "empty", &result)
		cancel()
		c.stop(false)
		select {
		case <-c.waited:
		case <-time.After(time.Second):
			_ = c.cmd.Process.Kill()
		}
	})
	return nil
}
