// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"knowndevice.local/knowndevice/sdk/conformance"
	"knowndevice.local/knowndevice/sdk/device"
)

func (b *backend) source(role string) string {
	r, _ := b.snapshot.Role(role)
	if len(r.LeafPins) == 0 {
		return ""
	}
	return r.LeafPins[0]
}

func (b *backend) evidence(in device.RoleRequest, subject device.CredentialBinding, role, sourceRole, action, status string, deadline time.Time) device.Evidence {
	return device.Evidence{APIVersion: device.V2, Role: role, Action: action, RequestID: in.RequestID, Plan: in.Plan, Subject: subject, Revision: 2, Reference: in.Plan.OperationID, Source: b.source(sourceRole), ObservedAt: time.Now().UTC(), Deadline: deadline, Status: status}
}

func roleAction(path string) string {
	switch path {
	case "/entitlement":
		return "entitlement"
	case "/issue", "/lookup", "/import", "/revoke", "/revocation-status":
		return "authority"
	case "/register", "/registration":
		return "platform"
	case "/activate", "/activation-status":
		return "application"
	case "/withdraw", "/withdrawal-status":
		return "withdrawal"
	case "/challenge":
		return "transport"
	default:
		return ""
	}
}

func (b *backend) response(in device.RoleRequest, service, path, status string, subject device.CredentialBinding) device.RoleResponse {
	e := b.evidence(in, subject, roleAction(path), service, strings.TrimPrefix(path, "/"), status, in.Plan.ExpiresAt)
	if path == "/challenge" {
		e.Deadline = in.Probe.Deadline
	}
	return device.RoleResponse{Status: status, Evidence: &e}
}

func (b *backend) actualPeer(req *http.Request, expected device.Credential) bool {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 || len(req.TLS.VerifiedChains) == 0 || len(expected.TLS.Certificate) == 0 {
		return false
	}
	actual := req.TLS.PeerCertificates[0]
	leaves, err := x509.ParseCertificate(expected.TLS.Certificate[0])
	if err != nil || !bytes.Equal(actual.Raw, leaves.Raw) || !bytes.Equal(actual.RawSubjectPublicKeyInfo, leaves.RawSubjectPublicKeyInfo) || device.Hash(actual.RawSubjectPublicKeyInfo) != expected.Handle.PublicKeyDigest {
		return false
	}
	if b.snapshot.Profile.ValidateLeaf(actual, expected.Handle.Binding.DeviceID, expected.Handle.Binding.Generation) != nil {
		return false
	}
	now := time.Now().UTC()
	v, err := b.snapshot.Validation(now.Add(-time.Second), now.Add(time.Second), false, false)
	return err == nil && b.snapshot.Profile.ValidatePublicChain(req.TLS.PeerCertificates, expected.Handle.Binding.DeviceID, expected.Handle.Binding.Generation, v) == nil
}

func (b *backend) serve(service string, w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/json" || roleAction(req.URL.Path) == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var in device.RoleRequest
	if device.DecodeStrict(io.LimitReader(req.Body, device.MaxInput+1), &in) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	b.mu.Lock()
	response := b.handle(service, req, in)
	drop := req.URL.Path == "/issue" && b.fault == conformance.LostIssueResponse && response.Status == "issued"
	late := req.URL.Path == "/issue" && b.fault == conformance.LateIssueResponse && response.Status == "issued"
	b.mu.Unlock()
	if drop {
		if hijacker, ok := w.(http.Hijacker); ok {
			connection, _, err := hijacker.Hijack()
			if err == nil {
				_ = connection.Close()
			}
		}
		return
	}
	if late {
		// This deliberate fault attempts a reply after the caller has ended.
		// The fixture keeps the reservation and makes no further domain effect.
		<-b.release
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
	if late {
		b.mu.Lock()
		b.observation.LateResponses++
		b.mu.Unlock()
		b.lateOnce.Do(func() { close(b.lateObserved) })
	}
}

func (b *backend) handle(service string, req *http.Request, in device.RoleRequest) device.RoleResponse {
	p, path := in.Plan, req.URL.Path
	target := credentialBinding(b.target)
	old := credentialBinding(b.previous)
	response := b.response(in, service, path, "denied", target)
	if b.snapshot == nil || p != b.plan || b.snapshot.ValidatePlan(p) != nil || p.Validate(time.Now().UTC().Add(time.Second)) != nil || req.Context().Err() != nil {
		response.Status, response.Evidence.Status = "conflict", "conflict"
		return response
	}
	if service == "issuance" || service == "authority-transport" || service == "application" && path != "/activate" || service == "transport" && path != "/challenge" || service == "control" && path == "/challenge" {
		return response
	}
	previousPeer, targetPeer := b.actualPeer(req, b.previous), b.actualPeer(req, b.target)
	issuance := path == "/entitlement" || path == "/issue" || path == "/lookup" || path == "/import"
	if issuance && !previousPeer || !issuance && path != "/challenge" && !targetPeer {
		return response
	}
	if b.fault == conformance.DeniedScope {
		return response
	}
	if b.fault == conformance.StaleGeneration {
		response.Status, response.Evidence.Status = "conflict", "conflict"
		return response
	}
	if path == "/entitlement" {
		return b.response(in, service, path, "authorized", old)
	}
	if path == "/issue" || path == "/lookup" || path == "/import" {
		if !bytes.Equal(in.CSR, b.target.CSR) || b.observation.ActiveGeneration != p.ExpectedGeneration {
			return b.response(in, service, path, "conflict", target)
		}
		if path == "/lookup" {
			b.observation.LookupCalls++
			if b.fault == conformance.LookupUnavailable {
				return b.response(in, service, path, "unknown", target)
			}
			if b.observation.ReservedGeneration == 0 {
				return b.response(in, service, path, "not-started", target)
			}
		} else if path == "/issue" {
			b.observation.IssueCalls++
			if b.observation.ReservedGeneration == 0 {
				// Reserve before signing. The single attempt is never cleared by
				// cancellation, response loss, lookup or adapter session restart.
				b.observation.ReservedGeneration = p.TargetGeneration
				b.observation.IssueEffects++
				b.issuedAt = time.Now().UTC()
				var err error
				b.target.TLS.Certificate, b.target.TLS.Leaf, err = b.issuers["operational"].issue(b.snapshot.Profile, p, in.CSR)
				b.issueOnce.Do(func() { close(b.issueObserved) })
				if err != nil {
					return b.response(in, service, path, "unknown", target)
				}
			}
		} else if !bytes.Equal(in.Certificate, publicChain(b.target.TLS.Certificate)) {
			return response
		}
		if len(b.target.TLS.Certificate) == 0 {
			return b.response(in, service, path, "unknown", target)
		}
		target = credentialBinding(b.target)
		result := b.response(in, service, path, "issued", target)
		result.Certificate = publicChain(b.target.TLS.Certificate)
		result.Evidence.IssuanceEarliest = b.issuedAt.Add(-time.Millisecond)
		result.Evidence.IssuanceLatest = b.issuedAt.Add(time.Millisecond)
		return result
	}
	if path == "/challenge" {
		return b.access(req, in, previousPeer, targetPeer)
	}
	if b.observation.ReservedGeneration == 0 || len(b.target.TLS.Certificate) == 0 {
		return response
	}
	if len(in.Certificate) > 0 && !bytes.Equal(in.Certificate, publicChain(b.target.TLS.Certificate)) {
		return response
	}
	switch path {
	case "/register":
		if !b.registered {
			b.registered = true
			b.observation.RegistrationEffects++
		}
		return b.response(in, service, path, "registered", target)
	case "/registration":
		if !b.registered {
			return b.response(in, service, path, "not-started", target)
		}
		return b.response(in, service, path, "registered", target)
	case "/activate", "/activation-status":
		if !b.registered {
			return response
		}
		if b.activationFault() {
			app := b.malformedApplicationProof(in)
			result := b.response(in, service, path, "activated", target)
			result.Application = &app
			b.recordProofFault()
			return result
		}
		if service == "application" {
			if !b.candidateVerified {
				return response
			}
			if !b.selected {
				b.selected = true
				b.activationRev = 2
				b.observation.ApplicationSelections++
			}
			return b.response(in, service, path, "ok", target)
		}
		if !b.selected {
			return b.response(in, service, path, "not-started", target)
		}
		// The model separates selection from control activation, and issues a
		// new application observation before changing its registry generation.
		app := b.applicationProof(in)
		if b.observation.ActiveGeneration != p.TargetGeneration {
			if b.observation.ActiveGeneration != p.ExpectedGeneration || app.Phase != "activated" || app.ActivationRevision == 0 || app.ConnectionID == "" {
				return response
			}
			b.observation.ActiveGeneration = p.TargetGeneration
			b.observation.ActivationEffects++
		}
		result := b.response(in, service, path, "activated", target)
		result.Application = &app
		return result
	case "/withdraw", "/withdrawal-status":
		if b.observation.ActiveGeneration != p.TargetGeneration || !bytes.Equal(in.Previous, publicChain(b.previous.TLS.Certificate)) {
			return response
		}
		if b.retirementFault() {
			proof := b.malformedWithdrawalProof(in)
			result := b.response(in, service, path, "withdrawn", old)
			result.Withdrawal = &proof
			b.recordProofFault()
			return result
		}
		if !b.withdrawn {
			if path == "/withdrawal-status" {
				return b.response(in, service, path, "not-started", old)
			}
			b.withdrawn = true
			b.observation.WithdrawalEffects++
			b.observation.DeniedGenerations = []uint64{1}
		}
		proof := b.withdrawalProof(in)
		result := b.response(in, service, path, "withdrawn", old)
		result.Withdrawal = &proof
		return result
	case "/revoke", "/revocation-status":
		if !b.withdrawn || b.denial.Kind != "denied" || b.observation.ActiveGeneration != 2 || !bytes.Equal(in.Previous, publicChain(b.previous.TLS.Certificate)) {
			return response
		}
		if b.observation.RevocationEffects == 0 {
			if path == "/revocation-status" {
				return b.response(in, service, path, "not-started", old)
			}
			b.observation.RevocationEffects++
		}
		return b.response(in, service, path, "revoked", old)
	}
	return response
}

func (b *backend) access(req *http.Request, in device.RoleRequest, previousPeer, targetPeer bool) device.RoleResponse {
	role, _ := b.snapshot.Role("transport")
	p := in.Probe
	nonce, nonceErr := hex.DecodeString(p.Nonce)
	if p.OperationID != in.Plan.OperationID || p.DeviceID != in.Plan.DeviceID || p.Endpoint != role.Endpoint || nonceErr != nil || len(nonce) != 16 || hex.EncodeToString(nonce) != p.Nonce || p.Deadline.After(in.Plan.ExpiresAt) || p.Deadline.Sub(time.Now().UTC()) > time.Duration(b.snapshot.Limits.ChallengeSeconds)*time.Second || !time.Now().Add(time.Second).Before(p.Deadline) {
		return b.response(in, "transport", "/challenge", "denied", device.CredentialBinding{})
	}
	if previousPeer && p.Generation == 1 {
		status := "completed"
		if b.withdrawn || b.retirementFault() {
			status = "denied"
		}
		result := b.response(in, "transport", "/challenge", status, credentialBinding(b.previous))
		if b.withdrawn || b.retirementFault() {
			connection, _ := device.RandomID()
			b.denial = device.AccessObservation{Evidence: *result.Evidence, Kind: "denied", ConnectionID: connection, Challenge: p}
		}
		return result
	}
	if targetPeer && b.registered && p.Generation == 2 {
		b.candidateVerified = true
		return b.response(in, "transport", "/challenge", "completed", credentialBinding(b.target))
	}
	return b.response(in, "transport", "/challenge", "denied", device.CredentialBinding{})
}

func (b *backend) applicationProof(in device.RoleRequest) device.ApplicationEvidence {
	proof := b.applicationVector(in)
	b.observation.ApplicationObservations++
	return proof
}

func (b *backend) applicationVector(in device.RoleRequest) device.ApplicationEvidence {
	nonce, _ := device.RandomID()
	connection, _ := device.RandomID()
	requestID, _ := device.RandomID()
	role, _ := b.snapshot.Role("transport")
	probe := device.Probe{OperationID: in.Plan.OperationID, DeviceID: in.Plan.DeviceID, Generation: in.Plan.TargetGeneration, Endpoint: role.Endpoint, Nonce: nonce, Deadline: time.Now().UTC().Add(10 * time.Second)}
	if probe.Deadline.After(in.Plan.ExpiresAt) {
		probe.Deadline = in.Plan.ExpiresAt
	}
	copy := in
	copy.RequestID = requestID
	e := b.evidence(copy, credentialBinding(b.target), "application", "application", "observe", "completed", probe.Deadline)
	revision := b.activationRev
	if revision == 0 {
		revision = 2
	}
	e.Revision = revision
	return device.ApplicationEvidence{Evidence: e, Phase: "activated", ApplicationID: b.snapshot.Composition.ApplicationID, ActivationRevision: revision, Active: credentialBinding(b.target), InstanceID: b.instanceID, ConnectionID: connection, SessionID: b.sessionID, Challenge: probe, AcceptedScope: []string{"fresh-challenge"}}
}

func (b *backend) withdrawalProof(in device.RoleRequest) device.WithdrawalEvidence {
	old, target := credentialBinding(b.previous), credentialBinding(b.target)
	e := b.evidence(in, old, "withdrawal", "control", "withdraw", "ok", in.Plan.ExpiresAt)
	e.Revision = 3
	return device.WithdrawalEvidence{Evidence: e, Previous: old, Target: target, PolicyRevision: 3, Scope: b.snapshot.Composition.WithdrawalScope, SessionsTerminated: true, Denial: b.denial, Current: b.applicationProof(in)}
}

func (b *backend) activationFault() bool {
	return b.fault == conformance.CandidateOnly || b.fault == conformance.MissingActivationRevision || b.fault == conformance.MissingFreshObservation
}

func (b *backend) retirementFault() bool {
	return b.fault == conformance.TLSOnlyRetirement || b.fault == conformance.MissingSessions || b.fault == conformance.StaleRetirementTarget
}

func (b *backend) recordProofFault() {
	b.observation.InjectedProofFault = b.fault
	b.observation.InjectedProofResponses++
}

// The selected trusted fixture endpoint deliberately supplies an inconsistent
// proof. This is an authenticated fault vector, not a selection, CAS, fresh
// observation, durable deny policy or session-termination effect.
func (b *backend) malformedApplicationProof(in device.RoleRequest) device.ApplicationEvidence {
	proof := b.applicationVector(in)
	switch b.fault {
	case conformance.CandidateOnly:
		proof.Phase = "candidate-verified"
	case conformance.MissingActivationRevision:
		proof.ActivationRevision = 0
	case conformance.MissingFreshObservation:
		proof.Evidence.ObservedAt = time.Now().UTC().Add(-6 * time.Second)
	}
	return proof
}

func (b *backend) malformedWithdrawalProof(in device.RoleRequest) device.WithdrawalEvidence {
	old, target := credentialBinding(b.previous), credentialBinding(b.target)
	denial := b.denial
	if denial.Kind == "" {
		// A complete-shaped synthetic old denial lets each malformed field reach
		// the adapter validator. It does not change the model's deny policy.
		nonce, _ := device.RandomID()
		connection, _ := device.RandomID()
		role, _ := b.snapshot.Role("transport")
		probe := device.Probe{OperationID: in.Plan.OperationID, DeviceID: in.Plan.DeviceID, Generation: in.Plan.ExpectedGeneration, Endpoint: role.Endpoint, Nonce: nonce, Deadline: time.Now().UTC().Add(10 * time.Second)}
		request := in
		request.RequestID, _ = device.RandomID()
		e := b.evidence(request, old, "transport", "transport", "challenge", "denied", probe.Deadline)
		denial = device.AccessObservation{Evidence: e, Kind: "denied", ConnectionID: connection, Challenge: probe}
	}
	e := b.evidence(in, old, "withdrawal", "control", "withdraw", "ok", in.Plan.ExpiresAt)
	e.Revision = 3
	proof := device.WithdrawalEvidence{Evidence: e, Previous: old, Target: target, PolicyRevision: 3, Scope: b.snapshot.Composition.WithdrawalScope, SessionsTerminated: true, Denial: denial, Current: b.applicationVector(in)}
	switch b.fault {
	case conformance.TLSOnlyRetirement:
		proof.Denial.Kind = "unknown"
	case conformance.MissingSessions:
		proof.SessionsTerminated = false
	case conformance.StaleRetirementTarget:
		proof.Target.Generation = in.Plan.ExpectedGeneration
	}
	return proof
}
