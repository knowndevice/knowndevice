// SPDX-License-Identifier: Apache-2.0

package process

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"sync"
	"time"

	"knowndevice.local/knowndevice/sdk/device"
)

type runningCall struct {
	scope     *Scope
	cancel    context.CancelFunc
	ctx       context.Context
	signCalls int
}
type server struct {
	writer       protocolWriter
	options      ServerOptions
	snapshot     *device.PublicSnapshot
	adapters     device.Adapters
	capabilities []string
	initialized  bool
	mu           sync.Mutex
	ids          map[string]string
	running      map[string]runningCall
	signs        map[string]chan message
	domainBusy   bool
	clockBusy    bool
	ctx          context.Context
	abort        func()
	sendGate     chan struct{}
}

// Serve dispatches only the negotiated public roles. Backend persistence remains
// the service/controller's responsibility; this stream never retries a mutation.
func Serve(ctx context.Context, input io.Reader, output io.Writer, opts ServerOptions) error {
	if opts.Limits != (Limits{}) && opts.Limits != DefaultLimits() {
		return device.ErrUnsupported
	}
	if !sha256ID.MatchString(opts.ArtifactDigest) {
		return device.ErrUnsupported
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var abortOnce sync.Once
	abort := func() {
		abortOnce.Do(func() {
			cancel()
			if closer, ok := input.(io.Closer); ok {
				_ = closer.Close()
			}
			if closer, ok := output.(io.Closer); ok {
				_ = closer.Close()
			}
		})
	}
	s := &server{writer: protocolWriter{out: output}, options: opts, ids: map[string]string{}, running: map[string]runningCall{}, signs: map[string]chan message{}, ctx: ctx, abort: abort, sendGate: make(chan struct{}, 1)}
	defer func() {
		s.mu.Lock()
		for _, call := range s.running {
			call.cancel()
		}
		s.mu.Unlock()
	}()
	type incoming struct {
		line []byte
		err  error
	}
	lines := make(chan incoming, 1)
	go func() {
		r := bufio.NewReaderSize(input, 32<<10)
		for {
			line, err := readLine(r, DefaultLimits())
			select {
			case lines <- incoming{line, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		if closer, ok := input.(io.Closer); ok {
			_ = closer.Close()
		}
		if closer, ok := output.(io.Closer); ok {
			_ = closer.Close()
		}
	}()
	for {
		var received incoming
		select {
		case received = <-lines:
		case <-ctx.Done():
			return ctx.Err()
		}
		if received.err != nil {
			if received.err == io.EOF {
				return nil
			}
			_ = s.writeError(nil, "parse-error", nil)
			return ErrProtocol
		}
		if checkTokens(received.line, DefaultLimits()) != nil {
			kind := "invalid-request"
			if !json.Valid(received.line) {
				kind = "parse-error"
			}
			_ = s.writeError(nil, kind, nil)
			return ErrProtocol
		}
		m, err := decodeMessage(received.line, DefaultLimits())
		if err != nil {
			_ = s.writeError(nil, "invalid-request", nil)
			return ErrProtocol
		}
		if m.Method == "" {
			if m.ID == nil || (*m.ID)[:2] != "s-" || validateDefinition("response", received.line) != nil {
				return ErrProtocol
			}
			s.mu.Lock()
			ch := s.signs[*m.ID]
			state := s.ids[*m.ID]
			if ch != nil {
				delete(s.signs, *m.ID)
				s.ids[*m.ID] = "sign-completed"
			}
			s.mu.Unlock()
			if ch == nil {
				if state == "sign-canceled" {
					continue
				}
				return ErrProtocol
			}
			ch <- m
			continue
		}
		if m.ID == nil {
			if m.Method != "operation.cancel" {
				continue
			}
			if !s.initialized || validateDefinition("notification", received.line) != nil {
				return ErrProtocol
			}
			var params CancelParams
			if decodeDefinition("cancelParams", m.Params, &params) != nil {
				return ErrProtocol
			}
			s.mu.Lock()
			call, ok := s.running[params.ParentID]
			if ok && call.scope != nil && call.scope.equal(params.Scope) {
				call.cancel()
			} else if ok {
				s.mu.Unlock()
				return ErrProtocol
			}
			s.mu.Unlock()
			continue
		}
		if (*m.ID)[:2] != "h-" {
			return ErrProtocol
		}
		s.mu.Lock()
		_, duplicate := s.ids[*m.ID]
		if !duplicate && len(s.ids) < DefaultLimits().MaxRequests {
			s.ids[*m.ID] = "request"
		} else {
			duplicate = true
		}
		s.mu.Unlock()
		if duplicate {
			_ = s.writeError(m.ID, "invalid-request", nil)
			return ErrProtocol
		}
		_, domain := domainMethods[m.Method]
		known := domain || m.Method == "plugin.initialize" || m.Method == "plugin.health" || m.Method == "plugin.shutdown" || m.Method == "clock.assess"
		if !known {
			if s.writeError(m.ID, "method-not-found", nil) != nil {
				return ErrProtocol
			}
			if !s.initialized {
				return ErrProtocol
			}
			continue
		}
		if validateDefinition("request", received.line) != nil {
			if s.writeError(m.ID, "invalid-params", nil) != nil {
				return ErrProtocol
			}
			continue
		}
		if !s.initialized {
			if m.Method != "plugin.initialize" {
				_ = s.writeError(m.ID, "unsupported", nil)
				return device.ErrUnsupported
			}
			result, err := s.initialize(m.Params)
			if err != nil {
				_ = s.writeError(m.ID, "unsupported", nil)
				return device.ErrUnsupported
			}
			if s.writeSuccess(m.ID, result) != nil {
				return ErrProtocol
			}
			continue
		}
		switch m.Method {
		case "plugin.initialize":
			if s.writeError(m.ID, "invalid-request", nil) != nil {
				return ErrProtocol
			}
			return ErrProtocol
		case "plugin.health":
			if s.writeSuccess(m.ID, HealthResult{"ok"}) != nil {
				return ErrProtocol
			}
			continue
		case "plugin.shutdown":
			_ = s.writeSuccess(m.ID, Empty{})
			return nil
		case "clock.assess":
			var params ClockParams
			if decodeDefinition("clockParams", m.Params, &params) != nil {
				_ = s.writeError(m.ID, "invalid-params", nil)
				continue
			}
			s.mu.Lock()
			busy := s.clockBusy
			if !busy {
				s.clockBusy = true
			}
			s.mu.Unlock()
			if busy {
				_ = s.writeError(m.ID, "internal-error", nil)
				continue
			}
			callCtx, callCancel := context.WithTimeout(ctx, time.Duration(s.snapshot.RequestTimeoutSeconds)*time.Second)
			s.mu.Lock()
			s.running[*m.ID] = runningCall{scope: nil, cancel: callCancel, ctx: callCtx}
			s.mu.Unlock()
			go s.runClock(callCtx, callCancel, m.ID, params)
			continue
		}
		scope, execute, err := s.prepare(m)
		if err != nil {
			if scope == nil {
				_ = s.writeError(m.ID, "invalid-params", nil)
			} else {
				_ = s.send(message{JSONRPC: "2.0", ID: m.ID, Error: backendError(err, m.Method, scope)})
			}
			continue
		}
		if !has(s.capabilities, m.Method) {
			_ = s.writeError(m.ID, "unsupported", scope)
			continue
		}
		s.mu.Lock()
		busy := s.domainBusy
		if !busy {
			s.domainBusy = true
		}
		s.mu.Unlock()
		if busy {
			_ = s.writeError(m.ID, "resource-limit", scope)
			continue
		}
		callCtx, callCancel := context.WithDeadline(ctx, scope.Deadline)
		s.mu.Lock()
		s.running[*m.ID] = runningCall{scope: scope, cancel: callCancel, ctx: callCtx}
		s.mu.Unlock()
		go func(m message, scope *Scope, run func(context.Context) (any, error)) {
			defer callCancel()
			defer func() { s.mu.Lock(); delete(s.running, *m.ID); s.domainBusy = false; s.mu.Unlock() }()
			var value any
			var err error
			if callCtx.Err() != nil {
				err = device.ErrUnknown
			} else {
				value, err = run(callCtx)
			}
			if callCtx.Err() != nil {
				err = device.ErrUnknown
			}
			if err != nil {
				_ = s.send(message{JSONRPC: "2.0", ID: m.ID, Error: backendError(err, m.Method, scope)})
				return
			}
			_ = s.writeSuccess(m.ID, value)
		}(m, scope, execute)
	}
}

func (s *server) initialize(data []byte) (InitializeResult, error) {
	var params InitializeParams
	if decodeDefinition("initializeParams", data, &params) != nil || len(params.Snapshot) > MaxSnapshotBytes || params.Limits != DefaultLimits() || len(params.Schemas) != 1 || params.Schemas[0] != Schema() || !sortedUnique(params.ProtocolVersions, 8) || !sortedUnique(params.ErrorVersions, 8) || !has(params.ProtocolVersions, ProtocolVersion) || !has(params.ErrorVersions, ErrorVersion) || !sortedUnique(params.RequiredCapabilities, 32) {
		return InitializeResult{}, device.ErrUnsupported
	}
	snapshot, err := device.DecodeSnapshot(params.Snapshot)
	if err != nil {
		return InitializeResult{}, device.ErrUnsupported
	}
	snapshot, err = processSnapshot(snapshot, s.options.ArtifactDigest)
	if err != nil {
		return InitializeResult{}, err
	}
	if s.options.Snapshot != nil && !bytesEqual(s.options.Snapshot.Bytes(), snapshot.Bytes()) {
		return InitializeResult{}, device.ErrUnsupported
	}
	if params.ArtifactDigest != s.options.ArtifactDigest || params.SnapshotDigest != snapshot.Digest() || params.CompositionDigest != snapshot.Composition.Digest() || params.Profile != snapshot.Profile {
		return InitializeResult{}, device.ErrUnsupported
	}
	permissions, err := ExpectedPermissions(snapshot)
	if err != nil || !samePermissions(params.Permissions, permissions) {
		return InitializeResult{}, device.ErrUnsupported
	}
	if s.options.Permissions.NetworkOrigins != nil && !samePermissions(s.options.Permissions, permissions) {
		return InitializeResult{}, device.ErrUnsupported
	}
	adapters := s.options.Adapters
	if s.options.Factory != nil {
		type built struct {
			adapters device.Adapters
			err      error
		}
		result := make(chan built, 1)
		go func() { a, err := s.options.Factory(snapshot); result <- built{a, err} }()
		factoryCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		defer cancel()
		select {
		case value := <-result:
			adapters, err = value.adapters, value.err
		case <-factoryCtx.Done():
			return InitializeResult{}, device.ErrUnsupported
		}
		if err != nil {
			return InitializeResult{}, device.ErrUnsupported
		}
	}
	caps, err := capabilities(snapshot, adapters)
	if err != nil {
		return InitializeResult{}, err
	}
	for _, required := range params.RequiredCapabilities {
		if !has(caps, required) {
			return InitializeResult{}, device.ErrUnsupported
		}
	}
	s.snapshot, s.adapters, s.capabilities, s.initialized = snapshot, adapters, caps, true
	return InitializeResult{ProtocolVersion, ErrorVersion, []SchemaIdentity{Schema()}, s.options.ArtifactDigest, snapshot.Digest(), snapshot.Composition.Digest(), snapshot.Profile, caps, permissions, DefaultLimits()}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (s *server) writeError(id *string, kind string, scope *Scope) error {
	return s.send(message{JSONRPC: "2.0", ID: id, Error: rpcError(kind, scope)})
}
func (s *server) writeSuccess(id *string, value any) error {
	m, err := success(id, value)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(m)
	if validateDefinition("response", data) != nil {
		return ErrProtocol
	}
	return s.send(m)
}

func (s *server) send(m message) error {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	select {
	case s.sendGate <- struct{}{}:
		defer func() { <-s.sendGate }()
	case <-ctx.Done():
		s.abort()
		return ErrProtocol
	}
	finished := make(chan error, 1)
	go func() { finished <- s.writer.write(m) }()
	select {
	case err := <-finished:
		if err != nil {
			s.abort()
		}
		return err
	case <-ctx.Done():
		s.abort()
		return ErrProtocol
	}
}

func (s *server) credential(w WireCredential, parent string, scope Scope, artifactOnly ...bool) (device.Credential, error) {
	key, err := publicKey(w.PublicSPKI)
	if err != nil {
		return device.Credential{}, err
	}
	if len(artifactOnly) > 0 && artifactOnly[0] {
		if w.SignerRef != "" {
			return device.Credential{}, device.ErrDenied
		}
		return credentialFromWire(w, publicOnlySigner{key})
	}
	if w.SignerRef == "" {
		return device.Credential{}, device.ErrDenied
	}
	proxy := &remoteSigner{server: s, parent: parent, scope: scope, ref: w.SignerRef, key: key}
	return credentialFromWire(w, proxy)
}

type publicOnlySigner struct{ key *ecdsa.PublicKey }

func (p publicOnlySigner) Public() crypto.PublicKey { return p.key }
func (p publicOnlySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, device.ErrUnsupported
}

func (s *server) prepare(m message) (*Scope, func(context.Context) (any, error), error) {
	parent := *m.ID
	switch domainMethods[m.Method] {
	case "authorizeParams":
		var p AuthorizeParams
		if decodeDefinition("authorizeParams", m.Params, &p) != nil {
			return nil, nil, device.ErrDenied
		}
		if err := validateScope(s.snapshot, p.Plan, p.Scope); err != nil {
			return &p.Scope, nil, err
		}
		if p.Credential == nil {
			return &p.Scope, nil, device.ErrDenied
		}
		k, err := s.credential(*p.Credential, parent, p.Scope)
		if err == nil {
			err = validateCaller(s.snapshot, p.Plan, &k)
		}
		if err != nil {
			return &p.Scope, nil, err
		}
		return &p.Scope, func(ctx context.Context) (any, error) {
			err := s.adapters.Entitlement.Authorize(ctx, p.Plan, &k)
			return BoundResult[Empty]{p.Scope, Empty{}}, err
		}, nil
	case "issueParams", "importParams":
		var scope Scope
		var plan device.Plan
		var csr, certificate []byte
		var wire *WireCredential
		if m.Method == "authority.import" {
			var p ImportParams
			if decodeDefinition("importParams", m.Params, &p) != nil {
				return nil, nil, device.ErrDenied
			}
			scope, plan, csr, certificate, wire = p.Scope, p.Plan, p.CSR, p.Certificate, p.Credential
		} else {
			var p IssueParams
			if decodeDefinition("issueParams", m.Params, &p) != nil {
				return nil, nil, device.ErrDenied
			}
			scope, plan, csr, wire = p.Scope, p.Plan, p.CSR, p.Credential
		}
		if err := validateScope(s.snapshot, plan, scope); err != nil {
			return &scope, nil, err
		}
		if _, err := s.snapshot.Profile.ValidateCSR(csr, plan.DeviceID, plan.TargetGeneration); err != nil {
			return &scope, nil, device.ErrDenied
		}
		if wire == nil {
			return &scope, nil, device.ErrDenied
		}
		k, err := s.credential(*wire, parent, scope)
		if err == nil {
			err = validateCaller(s.snapshot, plan, &k)
		}
		if err != nil {
			return &scope, nil, err
		}
		if m.Method == "authority.import" && validateCertificate(s.snapshot, plan, csr, certificate) != nil {
			return &scope, nil, device.ErrDenied
		}
		return &scope, func(ctx context.Context) (any, error) {
			r := device.IssueRequest{Plan: plan, CSR: csr, Credential: &k}
			if m.Method == "authority.import" {
				importer, ok := s.adapters.Authority.(device.Importer)
				if !ok {
					return nil, device.ErrUnsupported
				}
				err := importer.Import(ctx, r, certificate)
				return BoundResult[Empty]{scope, Empty{}}, err
			}
			var chain []byte
			var err error
			if m.Method == "authority.issue" {
				chain, err = s.adapters.Authority.Issue(ctx, r)
			} else {
				chain, err = s.adapters.Authority.Lookup(ctx, r)
			}
			if err == nil {
				err = validateCertificate(s.snapshot, plan, csr, chain)
			}
			return BoundResult[[]byte]{scope, chain}, err
		}, nil
	case "credentialParams":
		var p CredentialParams
		if decodeDefinition("credentialParams", m.Params, &p) != nil {
			return nil, nil, device.ErrDenied
		}
		if err := validateScope(s.snapshot, p.Plan, p.Scope); err != nil {
			return &p.Scope, nil, err
		}
		k, err := s.credential(p.Credential, parent, p.Scope)
		if err == nil {
			err = validateTarget(s.snapshot, p.Plan, k)
		}
		if err != nil {
			return &p.Scope, nil, err
		}
		return &p.Scope, func(ctx context.Context) (any, error) {
			switch m.Method {
			case "platform.register":
				return BoundResult[Empty]{p.Scope, Empty{}}, s.adapters.Platform.Register(ctx, p.Plan, k)
			case "platform.registrationStatus":
				return BoundResult[Empty]{p.Scope, Empty{}}, s.adapters.Platform.Registration(ctx, p.Plan, k)
			}
			var a device.Activation
			var err error
			if m.Method == "application.activate" {
				a, err = s.adapters.Application.Activate(ctx, p.Plan, k)
			} else {
				a, err = s.adapters.Application.ActivationStatus(ctx, p.Plan, k)
			}
			if err == nil {
				err = validateActivation(s.snapshot, p.Plan, k, a)
			}
			return BoundResult[device.Activation]{p.Scope, a}, err
		}, nil
	case "probeParams":
		var p ProbeParams
		if decodeDefinition("probeParams", m.Params, &p) != nil {
			return nil, nil, device.ErrDenied
		}
		if err := validateScope(s.snapshot, p.Plan, p.Scope); err != nil {
			return &p.Scope, nil, err
		}
		k, err := s.credential(p.Credential, parent, p.Scope)
		if err == nil {
			err = validateTarget(s.snapshot, p.Plan, k)
		}
		if err != nil {
			return &p.Scope, nil, err
		}
		role, _ := s.snapshot.Role("transport")
		if p.Probe.OperationID != p.Plan.OperationID || p.Probe.DeviceID != p.Plan.DeviceID || p.Probe.Generation != p.Plan.TargetGeneration || p.Probe.Endpoint != role.Endpoint || p.Probe.Deadline.After(p.Plan.ExpiresAt) || !time.Now().Before(p.Probe.Deadline) {
			return &p.Scope, nil, device.ErrDenied
		}
		return &p.Scope, func(ctx context.Context) (any, error) {
			if setter, ok := s.adapters.Transport.(interface{ SetPlan(device.Plan) error }); ok {
				if err := setter.SetPlan(p.Plan); err != nil {
					return nil, err
				}
			}
			result, err := s.adapters.Transport.Probe(ctx, p.Probe, k)
			if err == nil {
				err = device.MatchProbe(p.Probe, result, time.Now().UTC())
			}
			return BoundResult[device.Probe]{p.Scope, result}, err
		}, nil
	case "pairParams":
		var p PairParams
		if decodeDefinition("pairParams", m.Params, &p) != nil {
			return nil, nil, device.ErrDenied
		}
		if err := validateScope(s.snapshot, p.Plan, p.Scope); err != nil {
			return &p.Scope, nil, err
		}
		previous, err := s.credential(p.Previous, parent, p.Scope, m.Method == "authority.revoke" || m.Method == "authority.revocationStatus")
		if err != nil {
			return &p.Scope, nil, err
		}
		target, err := s.credential(p.Target, parent, p.Scope)
		if err == nil {
			err = validatePair(s.snapshot, p.Plan, previous, target)
		}
		if err != nil {
			return &p.Scope, nil, err
		}
		return &p.Scope, func(ctx context.Context) (any, error) {
			switch m.Method {
			case "authority.revoke":
				return BoundResult[Empty]{p.Scope, Empty{}}, s.adapters.Authority.Revoke(ctx, p.Plan, previous, target)
			case "authority.revocationStatus":
				return BoundResult[Empty]{p.Scope, Empty{}}, s.adapters.Authority.RevocationStatus(ctx, p.Plan, previous, target)
			}
			var r device.Retirement
			var err error
			if m.Method == "withdrawal.withdraw" {
				r, err = s.adapters.Withdrawal.Retire(ctx, p.Plan, previous, target)
			} else {
				r, err = s.adapters.Withdrawal.RetirementStatus(ctx, p.Plan, previous, target)
			}
			if err == nil {
				err = validateRetirement(s.snapshot, p.Plan, previous, target, r)
			}
			return BoundResult[device.Retirement]{p.Scope, r}, err
		}, nil
	}
	return nil, nil, device.ErrUnsupported
}

func (s *server) runClock(ctx context.Context, cancel context.CancelFunc, id *string, params ClockParams) {
	defer cancel()
	defer func() { s.mu.Lock(); delete(s.running, *id); s.clockBusy = false; s.mu.Unlock() }()
	a, err := s.adapters.Clock.Assess(ctx, params.Floor)
	now := time.Now()
	early, late, intervalErr := a.Interval(now, params.Floor)
	age := a.MaximumAge - now.Sub(a.AssessedAt)
	if err != nil || intervalErr != nil || age <= 0 || ctx.Err() != nil {
		_ = s.writeError(id, "internal-error", nil)
		return
	}
	result := ClockResult{early, late, a.DriftPPM, age.Milliseconds(), a.Trusted, a.Source}
	data, _ := json.Marshal(result)
	if validateDefinition("clockResult", data) != nil {
		_ = s.writeError(id, "internal-error", nil)
		return
	}
	_ = s.writeSuccess(id, result)
}

type remoteSigner struct {
	server *server
	parent string
	scope  Scope
	ref    string
	key    *ecdsa.PublicKey
}

func (p *remoteSigner) Public() crypto.PublicKey { return p.key }
func (p *remoteSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var name string
	switch opts.HashFunc() {
	case crypto.SHA256:
		name = "SHA256"
	case crypto.SHA384:
		name = "SHA384"
	case crypto.SHA512:
		name = "SHA512"
	default:
		return nil, device.ErrUnsupported
	}
	if _, err := hashAlgorithm(name, len(digest)); err != nil {
		return nil, err
	}
	p.server.mu.Lock()
	running, ok := p.server.running[p.parent]
	if !ok || running.scope == nil || !p.scope.equal(*running.scope) || running.signCalls >= DefaultLimits().MaxSignerCalls || running.ctx.Err() != nil || !time.Now().Before(p.scope.Deadline) {
		p.server.mu.Unlock()
		return nil, device.ErrUnknown
	}
	running.signCalls++
	p.server.running[p.parent] = running
	p.server.mu.Unlock()
	random, err := device.RandomID()
	if err != nil {
		return nil, device.ErrUnknown
	}
	id := "s-" + random
	ch := make(chan message, 1)
	p.server.mu.Lock()
	if len(p.server.ids) >= DefaultLimits().MaxRequests {
		p.server.mu.Unlock()
		return nil, device.ErrUnknown
	}
	p.server.ids[id] = "sign-pending"
	p.server.signs[id] = ch
	p.server.mu.Unlock()
	defer func() {
		p.server.mu.Lock()
		if p.server.signs[id] != nil {
			delete(p.server.signs, id)
			p.server.ids[id] = "sign-canceled"
		}
		p.server.mu.Unlock()
	}()
	m, _ := request(id, "signer.sign", SignParams{p.parent, p.ref, p.scope, name, digest})
	if p.server.send(m) != nil {
		return nil, device.ErrUnknown
	}
	timer := time.NewTimer(time.Until(p.scope.Deadline))
	defer timer.Stop()
	select {
	case response := <-ch:
		if response.Error != nil {
			return nil, mapError(response.Error, "signer.sign", &p.scope)
		}
		var result SignResult
		if decodeDefinition("signResult", response.Result, &result) != nil || len(result.Signature) > DefaultLimits().MaxSignatureBytes || !ecdsa.VerifyASN1(p.key, digest, result.Signature) {
			return nil, device.ErrUnknown
		}
		return result.Signature, nil
	case <-timer.C:
		return nil, device.ErrUnknown
	case <-running.ctx.Done():
		return nil, device.ErrUnknown
	}
}
