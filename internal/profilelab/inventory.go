// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"crypto/tls"
	"net/http"
	"sort"
	"time"

	"github.com/knowndevice/knowndevice/internal/device"
)

func (c *connections) inventory() ([]device.ConnectionRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) > 256 {
		return nil, device.ErrUnknown
	}
	result := make([]device.ConnectionRecord, 0, len(c.items))
	for _, entry := range c.items {
		record := device.ConnectionRecord{ConnectionID: entry.id}
		if socket, ok := entry.conn.(*tls.Conn); ok {
			state := socket.ConnectionState()
			if state.HandshakeComplete && len(state.PeerCertificates) > 0 && len(state.VerifiedChains) > 0 {
				peer := state.PeerCertificates[0]
				record.Authenticated = true
				record.CertificateFingerprint = device.Hash(peer.Raw)
				record.PublicKeyDigest = device.Hash(peer.RawSubjectPublicKeyInfo)
			}
		}
		if entry.binding != nil {
			if !record.Authenticated || entry.binding.CertificateFingerprint != record.CertificateFingerprint || entry.binding.PublicKeyDigest != record.PublicKeyDigest {
				return nil, device.ErrUnknown
			}
			binding := *entry.binding
			record.Binding = &binding
		}
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ConnectionID < result[j].ConnectionID })
	return result, nil
}

func (s *control) inventory(w http.ResponseWriter, req *http.Request) {
	in, err := decodeRequest(w, req)
	if err != nil {
		reply(w, device.RoleResponse{}, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if verifyPeerRole(req, s.snapshot, "observer") != nil || device.Hash(peer(req).Raw) != s.config.ObserverFingerprint || device.Hash(peer(req).RawSubjectPublicKeyInfo) != s.config.ObserverPublicKeyDigest {
		reply(w, device.RoleResponse{}, device.ErrDenied)
		return
	}
	if s.snapshot.ValidatePlan(in.Plan) != nil || in.Plan.Validate(time.Now().Add(time.Second)) != nil {
		reply(w, device.RoleResponse{}, device.ErrDenied)
		return
	}
	r, err := s.store.operation(req.Context(), in.Plan)
	if err != nil || r == nil {
		reply(w, device.RoleResponse{}, device.ErrDenied)
		return
	}
	reg, err := s.store.registry(req.Context())
	if err != nil || !r.Activated || reg.Active == nil || *reg.Active != r.Candidate {
		reply(w, device.RoleResponse{}, device.ErrDenied)
		return
	}
	connections, err := s.connections.inventory()
	if err != nil {
		reply(w, device.RoleResponse{}, err)
		return
	}
	entry := device.SessionInventory{Evidence: evidence(in.Plan, r.Candidate, "transport", "session-inventory", in.RequestID, r.Revision, source(s.snapshot, "control"), "ok"), Scope: s.snapshot.Composition.WithdrawalScope, Complete: true, Connections: connections}
	reply(w, device.RoleResponse{Status: "ok", Inventory: &entry}, nil)
}
