// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/adapters/process"
	"github.com/knowndevice/knowndevice/sdk/conformance"
	"github.com/knowndevice/knowndevice/sdk/device"
)

// This test adapter reads the actual authenticated fixture response. It accepts
// a proof only when restoring the one omitted constraint makes the unchanged
// strict validator pass. Unlike post-return tampering, this exercises delivery
// of each deliberately malformed proof across the TLS adapter boundary.
func readFaultProof(ctx context.Context, snapshot *device.PublicSnapshot, path string, plan device.Plan, target device.Credential, previous []byte) (device.RoleResponse, error) {
	role, err := snapshot.Role("control")
	if err != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	roots, err := snapshot.Roots("control")
	if err != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	id, err := device.RandomID()
	if err != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	request := device.RoleRequest{Plan: plan, RequestID: id, Previous: previous}
	data, err := json.Marshal(request)
	if err != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: role.PeerName, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{target.TLS}, SessionTicketsDisabled: true}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
			return device.ErrDenied
		}
		leaf := state.PeerCertificates[0]
		if !testHas(role.LeafPins, device.Hash(leaf.Raw)) || !testHas(role.SPKIPins, device.Hash(leaf.RawSubjectPublicKeyInfo)) {
			return device.ErrDenied
		}
		for _, at := range []time.Time{time.Now().Add(-time.Second), time.Now().Add(time.Second)} {
			if role.ValidateVerifiedPaths(state.VerifiedChains, at) != nil {
				return device.ErrDenied
			}
		}
		return nil
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, role.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	defer response.Body.Close()
	var result device.RoleResponse
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" || device.DecodeStrict(io.LimitReader(response.Body, device.MaxInput+1), &result) != nil || result.Evidence == nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	e := result.Evidence
	if e.Plan != plan || e.RequestID != id || e.Action != path[1:] || !testHas(role.LeafPins, e.Source) || !e.Deadline.Equal(plan.ExpiresAt) || e.Revision == 0 || !time.Now().Add(time.Second).Before(e.Deadline) {
		return device.RoleResponse{}, device.ErrUnknown
	}
	return result, nil
}

func testHas(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type omittedApplicationCheck struct {
	device.Application
	t        *testing.T
	snapshot *device.PublicSnapshot
	fault    conformance.Fault
	seen     *int
}

func (a omittedApplicationCheck) Activate(ctx context.Context, p device.Plan, k device.Credential) (device.Activation, error) {
	response, err := readFaultProof(ctx, a.snapshot, "/activate", p, k, nil)
	if err != nil || response.Application == nil {
		a.t.Fatal("named activation fault did not cross the authenticated TLS boundary")
	}
	proof := response.Application
	result := device.Activation{OperationID: p.OperationID, PlanDigest: p.Digest, DeviceID: p.DeviceID, ApplicationID: proof.ApplicationID, Generation: proof.Active.Generation, CertificateFingerprint: proof.Active.CertificateFingerprint, SessionID: proof.SessionID, Probe: proof.Challenge, Evidence: proof}
	if process.ValidateActivation(a.snapshot, p, k, result) == nil {
		a.t.Fatal("fixture activation fault was valid")
	}
	repaired := result
	copy := *proof
	repaired.Evidence = &copy
	switch a.fault {
	case conformance.CandidateOnly:
		if proof.Phase != "candidate-verified" {
			a.t.Fatal("candidate fault did not contain the staged phase")
		}
		copy.Phase = "activated"
	case conformance.MissingActivationRevision:
		if proof.ActivationRevision != 0 {
			a.t.Fatal("revision fault did not contain a zero revision")
		}
		copy.ActivationRevision = copy.Evidence.Revision
	case conformance.MissingFreshObservation:
		if time.Since(proof.Evidence.ObservedAt) <= 5*time.Second || proof.ConnectionID == "" || proof.InstanceID == "" || proof.SessionID == "" {
			a.t.Fatal("freshness fault did not contain a complete but stale observation")
		}
		copy.Evidence.ObservedAt = time.Now().UTC()
	default:
		a.t.Fatal("unexpected activation mutant")
	}
	if process.ValidateActivation(a.snapshot, p, k, repaired) != nil {
		a.t.Fatal("activation fault had another invalid constraint after the named check was restored")
	}
	*a.seen++
	return result, nil
}

func TestSuiteDetectsOmittedApplicationWireChecks(t *testing.T) {
	for _, variant := range []struct {
		name  string
		fault conformance.Fault
	}{{"candidate-not-activation", conformance.CandidateOnly}, {"activation-revision", conformance.MissingActivationRevision}, {"activation-fresh-observation", conformance.MissingFreshObservation}} {
		t.Run(variant.name, func(t *testing.T) {
			seen := 0
			rejectChangedAdapter(t, variant.name, "incomplete activation was reported as success", func(h *conformance.Harness) {
				h.Adapters.Application = omittedApplicationCheck{Application: h.Adapters.Application, t: t, snapshot: h.Snapshot, fault: variant.fault, seen: &seen}
			})
			if seen != 2 {
				t.Fatal("activation mutant did not consume both profile fault responses")
			}
		})
	}
}

type omittedWithdrawalCheck struct {
	device.Withdrawal
	t        *testing.T
	snapshot *device.PublicSnapshot
	fault    conformance.Fault
	seen     *int
}

func (w omittedWithdrawalCheck) Retire(ctx context.Context, p device.Plan, previous, target device.Credential) (device.Retirement, error) {
	var chain []byte
	for _, der := range previous.TLS.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	response, err := readFaultProof(ctx, w.snapshot, "/withdraw", p, target, chain)
	if err != nil || response.Withdrawal == nil {
		w.t.Fatal("named withdrawal fault did not cross the authenticated TLS boundary")
	}
	proof := response.Withdrawal
	result := device.Retirement{OperationID: p.OperationID, PlanDigest: p.Digest, Generation: p.ExpectedGeneration, PolicyDurable: true, SessionsTerminated: true, TLSObservation: "accepted", ApplicationAccessDenied: true, Evidence: proof}
	if process.ValidateRetirement(w.snapshot, p, previous, target, result) == nil {
		w.t.Fatal("fixture withdrawal fault was valid")
	}
	repaired := result
	copy := *proof
	repaired.Evidence = &copy
	switch w.fault {
	case conformance.TLSOnlyRetirement:
		if proof.Denial.Kind != "unknown" {
			w.t.Fatal("TLS-only fault did not omit explicit access denial")
		}
		copy.Denial.Kind = "denied"
	case conformance.MissingSessions:
		if proof.SessionsTerminated {
			w.t.Fatal("session fault did not omit session termination")
		}
		copy.SessionsTerminated = true
	case conformance.StaleRetirementTarget:
		if proof.Target.Generation != p.ExpectedGeneration {
			w.t.Fatal("target fault did not bind the stale generation")
		}
		copy.Target.Generation = p.TargetGeneration
	default:
		w.t.Fatal("unexpected withdrawal mutant")
	}
	if process.ValidateRetirement(w.snapshot, p, previous, target, repaired) != nil {
		w.t.Fatal("withdrawal fault had another invalid constraint after the named check was restored")
	}
	*w.seen++
	return result, nil
}

func TestSuiteDetectsOmittedWithdrawalWireChecks(t *testing.T) {
	for _, variant := range []struct {
		name  string
		fault conformance.Fault
	}{{"retirement-tls-only", conformance.TLSOnlyRetirement}, {"retirement-missing-sessions", conformance.MissingSessions}, {"retirement-stale-target", conformance.StaleRetirementTarget}} {
		t.Run(variant.name, func(t *testing.T) {
			seen := 0
			rejectChangedAdapter(t, variant.name, "incomplete withdrawal was reported as effective", func(h *conformance.Harness) {
				h.Adapters.Withdrawal = omittedWithdrawalCheck{Withdrawal: h.Adapters.Withdrawal, t: t, snapshot: h.Snapshot, fault: variant.fault, seen: &seen}
			})
			if seen != 2 {
				t.Fatal("withdrawal mutant did not consume both profile fault responses")
			}
		})
	}
}
