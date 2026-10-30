// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"knowndevice.local/knowndevice/internal/credentialprofile"
	"knowndevice.local/knowndevice/internal/device"
)

type connectionKey struct{}
type connection struct {
	id      string
	conn    net.Conn
	binding *device.CredentialBinding
	closed  chan struct{}
}
type connections struct {
	mu    sync.Mutex
	items map[net.Conn]*connection
}

func newConnections() *connections { return &connections{items: map[net.Conn]*connection{}} }
func (c *connections) context(ctx context.Context, conn net.Conn) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, _ := device.RandomID()
	entry := &connection{id: id, conn: conn, closed: make(chan struct{})}
	c.items[conn] = entry
	return context.WithValue(ctx, connectionKey{}, entry)
}
func (c *connections) state(conn net.Conn, state http.ConnState) {
	if state != http.StateClosed && state != http.StateHijacked {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry := c.items[conn]; entry != nil {
		close(entry.closed)
		delete(c.items, conn)
	}
}
func (c *connections) bind(ctx context.Context, b device.CredentialBinding) (string, error) {
	entry, ok := ctx.Value(connectionKey{}).(*connection)
	if !ok {
		return "", device.ErrUnknown
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry.binding != nil && *entry.binding != b {
		return "", device.ErrDenied
	}
	copy := b
	entry.binding = &copy
	return entry.id, nil
}
func (c *connections) terminate(ctx context.Context, previous device.CredentialBinding) (bool, error) {
	c.mu.Lock()
	var old []*connection
	for _, entry := range c.items {
		if entry.binding == nil || *entry.binding == previous {
			old = append(old, entry)
		}
	}
	c.mu.Unlock()
	for _, entry := range old {
		if e := entry.conn.Close(); e != nil {
			return false, device.ErrUnknown
		}
	}
	for _, entry := range old {
		select {
		case <-entry.closed:
		case <-ctx.Done():
			return false, device.ErrUnknown
		case <-time.After(time.Second):
			return false, device.ErrUnknown
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, entry := range c.items {
		if entry.binding == nil || *entry.binding == previous {
			return false, device.ErrUnknown
		}
	}
	return true, nil
}

func (s *control) mapped(ctx context.Context, fingerprint, keyDigest string) (*reservation, *reservation, error) {
	rows, e := s.store.db.QueryContext(ctx, "SELECT body FROM operations ORDER BY target")
	if e != nil {
		return nil, nil, e
	}
	defer rows.Close()
	var matched, denied *reservation
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return nil, nil, e
		}
		var r reservation
		if e = json.Unmarshal(b, &r); e != nil {
			return nil, nil, device.ErrUnknown
		}
		if e = s.store.validateReservation(&r); e != nil {
			return nil, nil, e
		}
		if r.Candidate.CertificateFingerprint == fingerprint && r.Candidate.PublicKeyDigest == keyDigest {
			copy := r
			matched = &copy
		}
		if r.Withdrawal != nil && r.Withdrawal.Previous.CertificateFingerprint == fingerprint && r.Withdrawal.Previous.PublicKeyDigest == keyDigest {
			copy := r
			denied = &copy
		}
	}
	return matched, denied, rows.Err()
}

func (s *control) challenge(w http.ResponseWriter, req *http.Request) {
	in, e := decodeRequest(w, req)
	if e != nil {
		reply(w, device.RoleResponse{}, e)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	response, e := s.challengeRequest(req, in)
	reply(w, response, e)
}
func (s *control) challengeRequest(req *http.Request, in device.RoleRequest) (device.RoleResponse, error) {
	p := in.Plan
	if req.URL.Path != "/challenge" || verifyPeerRole(req, s.snapshot, "operational") != nil || s.snapshot.ValidatePlan(p) != nil {
		return device.RoleResponse{}, device.ErrDenied
	}
	if e := s.plan(req.Context(), p, false); e != nil {
		return device.RoleResponse{}, e
	}
	c := peer(req)
	r, denied, e := s.mapped(req.Context(), device.Hash(c.Raw), device.Hash(c.RawSubjectPublicKeyInfo))
	if e != nil {
		return device.RoleResponse{}, e
	}
	if r == nil || !r.Registered || s.snapshot.Profile.ValidateLeaf(c, r.Plan.DeviceID, r.Plan.TargetGeneration) != nil {
		if e = s.store.observePeer(req.Context(), in.RequestID, device.Hash(c.Raw), device.Hash(c.RawSubjectPublicKeyInfo), 0, "unregistered-denied"); e != nil {
			return device.RoleResponse{}, device.ErrUnknown
		}
		entry := evidence(p, device.CredentialBinding{DeploymentID: s.snapshot.DeploymentID, DeviceID: s.snapshot.DeviceID, PublicKeyDigest: device.Hash(c.RawSubjectPublicKeyInfo), CertificateFingerprint: device.Hash(c.Raw)}, "transport", "challenge", in.RequestID, 1, source(s.snapshot, "transport"), "denied")
		return device.RoleResponse{Status: "denied", Evidence: &entry}, nil
	}
	certs, e := credentialprofile.ParseChain(r.Certificate)
	if e != nil || !bytes.Equal(c.Raw, certs[0].Raw) || !bytes.Equal(c.RawSubjectPublicKeyInfo, r.SPKI) {
		return device.RoleResponse{}, device.ErrDenied
	}
	connectionID, e := s.connections.bind(req.Context(), r.Candidate)
	if e != nil {
		return device.RoleResponse{}, e
	}
	probe := in.Probe
	endpoint, _ := s.snapshot.Role("transport")
	operation := r.Plan.OperationID
	if denied != nil && denied.Plan == p {
		operation = p.OperationID
	}
	if probe.DeviceID != r.Plan.DeviceID || probe.OperationID != operation || probe.Generation != r.Plan.TargetGeneration || probe.Endpoint != endpoint.Endpoint || device.MatchProbe(probe, probe, time.Now().Add(time.Second)) != nil {
		return device.RoleResponse{}, device.ErrDenied
	}
	if e = s.store.challenge(req.Context(), probe.Nonce, probe.Deadline); e != nil {
		return device.RoleResponse{}, e
	}
	if denied != nil {
		if e = s.store.observePeer(req.Context(), in.RequestID, device.Hash(c.Raw), device.Hash(c.RawSubjectPublicKeyInfo), r.Plan.TargetGeneration, "registered-denied"); e != nil {
			return device.RoleResponse{}, device.ErrUnknown
		}
		observation := device.AccessObservation{Evidence: evidence(p, r.Candidate, "transport", "challenge", in.RequestID, denied.Withdrawal.PolicyRevision, source(s.snapshot, "transport"), "denied"), Kind: "denied", ConnectionID: connectionID, Challenge: probe}
		observation.Evidence.Reference = connectionID
		observation.Evidence.Deadline = probe.Deadline
		if denied.Plan == p {
			denied.Withdrawal.Denial = observation
			if e = s.store.save(req.Context(), denied); e != nil {
				return device.RoleResponse{}, e
			}
		}
		return device.RoleResponse{Status: "denied", Evidence: &observation.Evidence}, nil
	}
	if r.Plan != p || validateInstalled(s.snapshot, r, false, false) != nil {
		return device.RoleResponse{}, device.ErrDenied
	}
	if _, e = checkEntitlement(s.dir, p); e != nil {
		return device.RoleResponse{}, e
	}
	var fixture policy
	if e = readJSON(s.dir+"/fixtures/policy.json", &fixture); e != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	if fixture.DenyGeneration == r.Candidate.Generation {
		return device.RoleResponse{}, device.ErrDenied
	}
	entry := evidence(p, r.Candidate, "transport", "challenge", in.RequestID, r.Revision, source(s.snapshot, "transport"), "accepted")
	if e = s.store.observePeer(req.Context(), in.RequestID, device.Hash(c.Raw), device.Hash(c.RawSubjectPublicKeyInfo), r.Plan.TargetGeneration, "accepted"); e != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	entry.Reference = connectionID
	entry.Deadline = probe.Deadline
	return device.RoleResponse{Status: "ok", Evidence: &entry}, nil
}

func (s *control) previous(ctx context.Context, in device.RoleRequest, r *reservation) (*reservation, error) {
	reg, e := s.store.registry(ctx)
	if e != nil {
		return nil, e
	}
	if !r.Activated || reg.Active == nil || *reg.Active != r.Candidate || r.Expected == nil {
		return nil, device.ErrConflict
	}
	old, e := s.store.generation(ctx, r.Plan.ExpectedGeneration)
	if e != nil {
		return nil, device.ErrDenied
	}
	if old.Candidate != *r.Expected || len(in.Previous) == 0 || string(in.Previous) != string(old.Certificate) {
		return nil, device.ErrDenied
	}
	return old, nil
}
func (s *control) withdraw(ctx context.Context, in device.RoleRequest, r *reservation, mutation bool) (device.WithdrawalEvidence, error) {
	old, e := s.previous(ctx, in, r)
	if e != nil {
		return device.WithdrawalEvidence{}, e
	}
	if r.Withdrawal == nil {
		if !mutation {
			return device.WithdrawalEvidence{}, device.ErrNotFound
		}
		entry := device.WithdrawalEvidence{Evidence: evidence(r.Plan, old.Candidate, "withdrawal", "withdraw", in.RequestID, r.Revision+1, source(s.snapshot, "control"), "unknown"), Previous: old.Candidate, Target: r.Candidate, PolicyRevision: r.Revision + 1, Scope: s.snapshot.Composition.WithdrawalScope, Denial: device.AccessObservation{Kind: "unknown"}}
		r.Withdrawal = &entry
		if e = s.store.save(ctx, r); e != nil {
			return entry, e
		}
		if e = labCheckpoint(ctx, s.dir, "control", "deny-durable", r.Plan); e != nil {
			return entry, e
		}
		if e = ctx.Err(); e != nil {
			return entry, device.ErrUnknown
		}
		if e = s.plan(ctx, r.Plan, false); e != nil {
			return entry, e
		}
	}
	// The exact deny is durable before any live connection is closed.
	terminated, e := s.connections.terminate(ctx, old.Candidate)
	if e != nil {
		return *r.Withdrawal, e
	}
	app, e := s.application(ctx, r, false)
	if e != nil {
		return *r.Withdrawal, e
	}
	if _, e = s.previous(ctx, in, r); e != nil {
		return *r.Withdrawal, e
	}
	r.Withdrawal.SessionsTerminated = terminated
	r.Withdrawal.Current = app
	r.Withdrawal.Evidence = evidence(r.Plan, old.Candidate, "withdrawal", "withdraw", in.RequestID, r.Revision+1, source(s.snapshot, "control"), "unknown")
	if r.Withdrawal.Denial.Kind == "denied" {
		r.Withdrawal.Evidence.Status = "ok"
	}
	if e = s.store.save(ctx, r); e != nil {
		return *r.Withdrawal, e
	}
	return *r.Withdrawal, nil
}
