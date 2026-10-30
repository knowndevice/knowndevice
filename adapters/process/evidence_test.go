// SPDX-License-Identifier: Apache-2.0

package process

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/sdk/credentialprofile"
	"knowndevice.local/knowndevice/sdk/device"
)

func TestPublicEvidenceChecksRefuseUnboundInput(t *testing.T) {
	s, p, old, target, retirement := completedRetirement(t, credentialprofile.StableID)
	a := retirement.Evidence.Current
	activation := device.Activation{OperationID: p.OperationID, PlanDigest: p.Digest, DeviceID: p.DeviceID, ApplicationID: a.ApplicationID, Generation: a.Active.Generation, CertificateFingerprint: a.Active.CertificateFingerprint, SessionID: a.SessionID, Probe: a.Challenge, Evidence: &a}
	if ValidateActivation(s, p, target, activation) != nil || ValidateRetirement(s, p, old, target, retirement) != nil {
		t.Fatal("complete public evidence was refused")
	}
	for _, snapshot := range []*device.PublicSnapshot{nil, {}} {
		if !errors.Is(ValidateActivation(snapshot, p, target, activation), device.ErrUnknown) || !errors.Is(ValidateRetirement(snapshot, p, old, target, retirement), device.ErrUnknown) {
			t.Fatal("unbound public snapshot accepted")
		}
	}
	changed := p
	changed.DeviceID = "another-device"
	changed.Digest, _ = changed.CalculateDigest()
	if !errors.Is(ValidateActivation(s, changed, target, activation), device.ErrUnknown) || !errors.Is(ValidateRetirement(s, changed, old, target, retirement), device.ErrUnknown) {
		t.Fatal("evidence accepted under another plan scope")
	}
}

func completedEvidence(s *device.PublicSnapshot, p device.Plan, subject device.CredentialBinding, role, sourceRole, action, status string, deadline time.Time) device.Evidence {
	source, _ := s.Role(sourceRole)
	return device.Evidence{APIVersion: device.V2, Role: role, Action: action, RequestID: strings.Repeat("c", 32), Plan: p, Subject: subject, Revision: 2, Reference: p.OperationID, Source: source.LeafPins[0], ObservedAt: time.Now().UTC(), Deadline: deadline, Status: status}
}

func completedRetirement(t *testing.T, profile string) (*device.PublicSnapshot, device.Plan, device.Credential, device.Credential, device.Retirement) {
	t.Helper()
	s, p, old, target := rotateFixture(t, strings.Repeat("b", 64), profile)
	previous, _ := binding(old)
	current, _ := binding(target)
	transport, _ := s.Role("transport")
	deadline := time.Now().UTC().Add(10 * time.Second)
	probe := device.Probe{OperationID: p.OperationID, DeviceID: p.DeviceID, Generation: p.TargetGeneration, Endpoint: transport.Endpoint, Nonce: strings.Repeat("d", 32), Deadline: deadline}
	app := device.ApplicationEvidence{Evidence: completedEvidence(s, p, current, "application", "application", "observe", "completed", deadline), Phase: "activated", ApplicationID: s.Composition.ApplicationID, ActivationRevision: 2, Active: current, InstanceID: strings.Repeat("e", 32), ConnectionID: strings.Repeat("f", 32), SessionID: strings.Repeat("a", 32), Challenge: probe, AcceptedScope: []string{"fresh-challenge"}}
	deniedProbe := probe
	deniedProbe.Generation = p.ExpectedGeneration
	deniedProbe.Nonce = strings.Repeat("c", 32)
	w := device.WithdrawalEvidence{Evidence: completedEvidence(s, p, previous, "withdrawal", "control", "withdraw", "ok", p.ExpiresAt), Previous: previous, Target: current, PolicyRevision: 3, Scope: s.Composition.WithdrawalScope, SessionsTerminated: true, Denial: device.AccessObservation{Evidence: completedEvidence(s, p, previous, "transport", "transport", "challenge", "denied", deadline), Kind: "denied", ConnectionID: strings.Repeat("b", 32), Challenge: deniedProbe}, Current: app}
	w.Evidence.Revision = w.PolicyRevision
	w.Current.Evidence.ObservedAt = w.Denial.Evidence.ObservedAt.Add(time.Millisecond)
	r := device.Retirement{OperationID: p.OperationID, PlanDigest: p.Digest, Generation: p.ExpectedGeneration, PolicyDurable: true, SessionsTerminated: true, TLSObservation: "accepted", ApplicationAccessDenied: true, Evidence: &w}
	return s, p, old, target, r
}

func TestNativeShapedCompletedWithdrawalAndIncompleteRefusals(t *testing.T) {
	for _, profile := range []string{credentialprofile.ReferenceID, credentialprofile.StableID} {
		t.Run(profile, func(t *testing.T) {
			s, p, old, target, positive := completedRetirement(t, profile)
			data, _ := json.Marshal(positive)
			if validateDefinition("retirement", data) != nil {
				t.Fatal("actual-shaped role status ok rejected by process schema")
			}
			if err := validateRetirement(s, p, old, target, positive); err != nil {
				t.Fatal("complete withdrawal refused", err)
			}
			for _, variant := range []string{"policy", "sessions", "remote-sessions", "denial", "tls-alert", "wrong-role", "stale-previous", "stale-target", "staging", "revision", "revision-mismatch", "empty-connection", "old-nonce", "scope", "old-observation", "stale-policy-revision", "target-before-denial", "equal-nonce", "wrong-withdrawal-action", "wrong-denial-action", "app-window-too-long", "denial-window-too-long"} {
				t.Run(variant, func(t *testing.T) {
					var r device.Retirement
					_ = json.Unmarshal(data, &r)
					switch variant {
					case "policy":
						r.PolicyDurable = false
					case "sessions":
						r.SessionsTerminated = false
					case "remote-sessions":
						r.Evidence.SessionsTerminated = false
					case "denial":
						r.Evidence.Denial.Kind = "unknown"
					case "tls-alert":
						r.TLSObservation = "denied"
					case "wrong-role":
						role, _ := s.Role("application")
						r.Evidence.Denial.Evidence.Source = role.LeafPins[0]
					case "stale-previous":
						r.Evidence.Previous.PublicKeyDigest = strings.Repeat("f", 64)
					case "stale-target":
						r.Evidence.Target.Generation--
					case "staging":
						r.Evidence.Current.Phase = "candidate-verified"
					case "revision":
						r.Evidence.Current.ActivationRevision = 0
					case "revision-mismatch":
						r.Evidence.Current.ActivationRevision++
					case "empty-connection":
						r.Evidence.Current.ConnectionID = ""
					case "old-nonce":
						r.Evidence.Current.Challenge.Generation--
					case "scope":
						r.Evidence.Scope = "unrelated"
					case "old-observation":
						r.Evidence.Current.Evidence.ObservedAt = time.Now().Add(-6 * time.Second)
					case "stale-policy-revision":
						r.Evidence.Evidence.Revision = r.Evidence.PolicyRevision - 1
					case "target-before-denial":
						r.Evidence.Current.Evidence.ObservedAt = r.Evidence.Denial.Evidence.ObservedAt.Add(-time.Millisecond)
					case "equal-nonce":
						r.Evidence.Current.Challenge.Nonce = r.Evidence.Denial.Challenge.Nonce
					case "wrong-withdrawal-action":
						r.Evidence.Evidence.Action = "status"
					case "wrong-denial-action":
						r.Evidence.Denial.Evidence.Action = "status"
					case "app-window-too-long":
						r.Evidence.Current.Challenge.Deadline = r.Evidence.Current.Evidence.ObservedAt.Add(time.Duration(s.Limits.ChallengeSeconds+1) * time.Second)
						r.Evidence.Current.Evidence.Deadline = r.Evidence.Current.Challenge.Deadline
					case "denial-window-too-long":
						r.Evidence.Denial.Challenge.Deadline = r.Evidence.Denial.Evidence.ObservedAt.Add(time.Duration(s.Limits.ChallengeSeconds+1) * time.Second)
						r.Evidence.Denial.Evidence.Deadline = r.Evidence.Denial.Challenge.Deadline
					}
					if validateRetirement(s, p, old, target, r) == nil {
						t.Fatal("incomplete withdrawal supplied success")
					}
				})
			}
		})
	}
}
