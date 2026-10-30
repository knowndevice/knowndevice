// SPDX-License-Identifier: Apache-2.0

// Package controller orders durable device transitions through internal adapters.
package controller

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"knowndevice.local/knowndevice/adapters/credentials"
	"knowndevice.local/knowndevice/internal/device"
)

type Engine struct {
	Config     device.Config
	Journal    device.Journal
	Keys       device.KeyStore
	Authority  device.Authority
	Platform   device.Platform
	Recovery   *device.Credential
	Now        func() time.Time
	Snapshot   *device.PublicSnapshot
	Clock      device.Clock
	assessment *device.ClockAssessment
	// Checkpoint is a lab interruption hook. Production callers leave it nil.
	Checkpoint func(string) error
}

type Receipt struct {
	APIVersion        string       `json:"apiVersion"`
	Scope             string       `json:"scope"`
	DeviceID          string       `json:"deviceId"`
	OperationID       string       `json:"operationId,omitempty"`
	PlanDigest        string       `json:"planDigest,omitempty"`
	Phase             device.Phase `json:"phase,omitempty"`
	Outcome           string       `json:"outcome"`
	Health            string       `json:"health"`
	ActiveGeneration  uint64       `json:"activeGeneration"`
	TargetGeneration  uint64       `json:"targetGeneration,omitempty"`
	PreviousRetired   bool         `json:"previousRetired"`
	Reason            string       `json:"reason,omitempty"`
	DeploymentID      string       `json:"deploymentId,omitempty"`
	ProfileID         string       `json:"profileId,omitempty"`
	ProfileVersion    int          `json:"profileVersion,omitempty"`
	ProfileDigest     string       `json:"profileDigest,omitempty"`
	CompositionDigest string       `json:"compositionDigest,omitempty"`
	SnapshotDigest    string       `json:"snapshotDigest,omitempty"`
}

func NewPlan(c device.Config, s device.State, mode string, now time.Time) (device.Plan, error) {
	if s.Operation != nil && s.Operation.Phase != device.Retired {
		return device.Plan{}, fmt.Errorf("an unfinished operation requires reconciliation")
	}
	if s.DeviceID != c.DeviceID || s.Counter >= 1<<53-1 {
		return device.Plan{}, device.ErrConflict
	}
	id, err := device.RandomID()
	if err != nil {
		return device.Plan{}, err
	}
	digest, err := c.Digest()
	if err != nil {
		return device.Plan{}, err
	}
	p := device.Plan{APIVersion: "knowndevice/v1alpha1", OperationID: id, DeviceID: c.DeviceID, Mode: mode, TargetGeneration: s.Counter + 1, TargetSlot: "A", ConfigDigest: digest, ExpiresAt: now.UTC().Add(time.Duration(c.PlanTTLSeconds) * time.Second)}
	if s.Active != nil {
		p.ExpectedGeneration = s.Active.Binding.Generation
		if s.Active.Binding.Slot == "A" {
			p.TargetSlot = "B"
		}
	}
	if c.APIVersion == device.V2 {
		snap, err := c.ResolveSnapshot()
		if err != nil {
			return p, err
		}
		if s.SchemaVersion != 2 || s.DeploymentID != c.DeploymentID || s.ProfileID != snap.Profile.ID || s.ProfileVersion != snap.Profile.Version || s.ProfileDigest != snap.Profile.PolicyDigest {
			return p, device.ErrConflict
		}
		p.APIVersion = device.V2
		p.DigestEncodingVersion = 2
		p.DeploymentID = snap.DeploymentID
		p.ProfileID = snap.Profile.ID
		p.ProfileVersion = snap.Profile.Version
		p.ProfileDigest = snap.Profile.PolicyDigest
		p.CompositionDigest = snap.Composition.Digest()
		p.SnapshotDigest = snap.Digest()
		for _, item := range []struct {
			role   string
			target *string
		}{{"control", &p.ControlTrustDigest}, {"application", &p.ApplicationTrustDigest}, {"issuance", &p.IssuanceTrustDigest}, {"recovery", &p.RecoveryTrustDigest}, {"transport", &p.TransportTrustDigest}} {
			r, e := snap.Role(item.role)
			if e != nil {
				return p, e
			}
			*item.target = r.Digest()
		}
	} else if s.SchemaVersion > 1 {
		return p, device.ErrUnsupported
	}
	p.Digest, err = p.CalculateDigest()
	if err != nil {
		return p, err
	}
	return p, p.Validate(now)
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Engine) checkpoint(name string) error {
	if e.Checkpoint != nil {
		return e.Checkpoint(name)
	}
	return nil
}

func (e *Engine) save(ctx context.Context, s device.State, phase device.Phase) (device.State, error) {
	original := s
	early, _, err := e.decision(ctx, s.Operation.Plan, s.ClockFloor)
	if err != nil {
		return s, err
	}
	s.ClockFloor = early
	operation := *s.Operation
	s.Operation = &operation
	s.Operation.Phase = phase
	s.Operation.Outcome = "running"
	if s.SchemaVersion == 2 && phase == device.Retired {
		s.Operation.Outcome = "succeeded"
	}
	s.Operation.Reason = ""
	next, err := e.Journal.Save(ctx, s, s.Revision)
	if err != nil {
		return original, err
	}
	if err := e.checkpoint(string(phase)); err != nil {
		return next, err
	}
	return next, nil
}

func Report(s device.State) Receipt {
	r := Receipt{APIVersion: "knowndevice/v1alpha1", Scope: "reference-device-path", DeviceID: s.DeviceID, Outcome: "idle", Health: "unknown"}
	if s.SchemaVersion == 2 {
		r.APIVersion = device.V2
		r.Scope = "profile-device-path"
		r.DeploymentID = s.DeploymentID
		r.ProfileID = s.ProfileID
		r.ProfileVersion = s.ProfileVersion
		r.ProfileDigest = s.ProfileDigest
	}
	if s.Active != nil {
		r.ActiveGeneration = s.Active.Binding.Generation
	}
	if o := s.Operation; o != nil {
		r.OperationID = o.Plan.OperationID
		r.PlanDigest = o.Plan.Digest
		r.Phase = o.Phase
		r.Outcome = o.Outcome
		if s.SchemaVersion == 2 && o.Phase == device.Retired && o.Outcome == "running" {
			r.Outcome = "succeeded"
		}
		r.TargetGeneration = o.Plan.TargetGeneration
		r.PreviousRetired = o.Phase == device.Retired && o.Previous != nil
		r.Reason = o.Reason
		if s.SchemaVersion == 2 {
			switch r.Phase {
			case device.BrokerRetireIntent:
				r.Phase = "withdrawal-intent"
			case device.BrokerRetired:
				r.Phase = "withdrawn"
			}
			r.CompositionDigest = o.Plan.CompositionDigest
			r.SnapshotDigest = o.Plan.SnapshotDigest
		}
	}
	return r
}

// Failures use an allowlist; arbitrary adapter error strings never enter receipts.
func reason(err error) (string, string) {
	switch {
	case errors.Is(err, device.ErrPlanExpired):
		return "intervention_required", "plan-expired-intervention-required"
	case errors.Is(err, device.ErrUnknown):
		return "unknown", "remote-outcome-unknown"
	case errors.Is(err, device.ErrUnsupported):
		return "blocked", "capability-unsupported"
	case errors.Is(err, device.ErrDenied):
		return "blocked", "authorization-or-application-denied"
	case errors.Is(err, device.ErrConflict):
		return "blocked", "generation-or-writer-conflict"
	default:
		return "intervention_required", "local-or-adapter-failure"
	}
}

func (e *Engine) failure(ctx context.Context, s device.State, err error) (Receipt, error) {
	r := Report(s)
	if s.SchemaVersion == 2 && s.Operation != nil && s.Operation.Phase == device.Retired {
		return r, err
	}
	r.Outcome, r.Reason = reason(err)
	if s.Operation != nil {
		operation := *s.Operation
		s.Operation = &operation
		s.Operation.Outcome = r.Outcome
		s.Operation.Reason = r.Reason
		if saved, saveErr := e.Journal.Save(ctx, s, s.Revision); saveErr == nil {
			s = saved
			r = Report(s)
		}
	}
	return r, err
}

func (e *Engine) authorizationCredential(ctx context.Context, s device.State, p device.Plan) (*device.Credential, error) {
	if p.Mode == "enroll" || p.Mode == "recover" {
		if e.Recovery == nil || !e.Recovery.Recovery || e.Recovery.DeviceID != p.DeviceID {
			return nil, device.ErrDenied
		}
		return e.Recovery, nil
	}
	if s.Active == nil {
		return nil, device.ErrDenied
	}
	c, err := e.credential(ctx, *s.Active)
	return &c, err
}

func (e *Engine) credential(ctx context.Context, h device.Handle) (device.Credential, error) {
	signer, err := e.Keys.Signer(ctx, h)
	if err != nil {
		return device.Credential{}, err
	}
	chain, err := e.Keys.Certificate(ctx, h)
	if err != nil {
		return device.Credential{}, err
	}
	if h.Binding.ProfileID != "" {
		return e.v2Credential(ctx, h, signer, chain, false)
	}
	roots, err := e.Config.Roots()
	if err != nil {
		return device.Credential{}, err
	}
	cert, err := ValidateChain(chain, signer, device.Subject(h.Binding.DeviceID, h.Binding.Generation), roots, e.now())
	if err != nil {
		return device.Credential{}, err
	}
	return device.Credential{Handle: h, TLS: cert}, nil
}

func CredentialFor(ctx context.Context, e *Engine, h device.Handle) (device.Credential, error) {
	return e.credential(ctx, h)
}

func (e *Engine) previousArtifact(ctx context.Context, h device.Handle) (device.Credential, error) {
	signer, err := e.Keys.Signer(ctx, h)
	if err != nil {
		return device.Credential{}, err
	}
	chain, err := e.Keys.Certificate(ctx, h)
	if err != nil {
		return device.Credential{}, err
	}
	if h.Binding.ProfileID != "" {
		return e.v2Credential(ctx, h, signer, chain, true)
	}
	block, _ := pem.Decode(chain)
	if block == nil {
		return device.Credential{}, device.ErrDenied
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return device.Credential{}, device.ErrDenied
	}
	at := e.now()
	if !at.Before(leaf.NotAfter) {
		at = leaf.NotAfter.Add(-time.Nanosecond)
	}
	if at.Before(leaf.NotBefore) {
		return device.Credential{}, device.ErrDenied
	}
	roots, err := e.Config.Roots()
	if err != nil {
		return device.Credential{}, err
	}
	cert, err := ValidateChain(chain, signer, device.Subject(h.Binding.DeviceID, h.Binding.Generation), roots, at)
	if err != nil {
		return device.Credential{}, err
	}
	return device.Credential{Handle: h, TLS: cert}, nil
}

func CSR(signer crypto.Signer, b device.Binding) ([]byte, error) {
	p, e := policyFor(b)
	if e != nil {
		return nil, e
	}
	return p.CreateCSR(signer, b.DeviceID, b.Generation)
}

func ValidateChain(chain []byte, signer crypto.Signer, subject string, roots *x509.CertPool, now time.Time) (tls.Certificate, error) {
	if signer == nil || roots == nil || len(roots.Subjects()) == 0 || now.IsZero() {
		return tls.Certificate{}, device.ErrDenied
	}
	certs, err := credentials.ParseCertificateChain(chain)
	if err != nil {
		return tls.Certificate{}, device.ErrDenied
	}
	var ders [][]byte
	for _, cert := range certs {
		ders = append(ders, cert.Raw)
	}
	if len(certs) == 0 || signer == nil {
		return tls.Certificate{}, device.ErrDenied
	}
	leaf := certs[0]
	actual, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	expected, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || device.Hash(actual) != device.Hash(expected) {
		return tls.Certificate{}, device.ErrDenied
	}
	if credentials.ValidateIdentity(leaf, subject) != nil {
		return tls.Certificate{}, device.ErrDenied
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, DNSName: subject, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return tls.Certificate{}, device.ErrDenied
	}
	return tls.Certificate{Certificate: ders, PrivateKey: signer, Leaf: leaf}, nil
}

func fingerprint(c device.Credential) string { return device.Hash(c.TLS.Certificate[0]) }

func (e *Engine) verify(ctx context.Context, s device.State, c device.Credential) (device.Probe, error) {
	nonce, err := device.RandomID()
	if err != nil {
		return device.Probe{}, err
	}
	endpoint := e.Config.MQTTEndpoint
	if e.Config.APIVersion == device.V2 {
		endpoint = e.Config.TransportEndpoint
	}
	_, latest, err := e.decision(ctx, s.Operation.Plan, s.ClockFloor)
	if err != nil {
		return device.Probe{}, err
	}
	deadline := latest.Add(e.Config.Timeout())
	if deadline.After(s.Operation.Plan.ExpiresAt) {
		deadline = s.Operation.Plan.ExpiresAt
	}
	p := device.Probe{OperationID: s.Operation.Plan.OperationID, DeviceID: s.DeviceID, Generation: c.Handle.Binding.Generation, Endpoint: endpoint, Nonce: nonce, Deadline: deadline}
	reply, err := e.Platform.Probe(ctx, p, c)
	if err != nil {
		return p, err
	}
	_, latest, err = e.decision(ctx, s.Operation.Plan, s.ClockFloor)
	if err != nil {
		return p, err
	}
	return p, device.MatchProbe(p, reply, latest)
}

func (e *Engine) checkActivation(p device.Plan, a device.Activation, c device.Credential) error {
	if a.OperationID != p.OperationID || a.PlanDigest != p.Digest || a.DeviceID != p.DeviceID || a.ApplicationID != e.Config.ApplicationID || a.Generation != p.TargetGeneration || a.CertificateFingerprint != fingerprint(c) {
		return device.ErrDenied
	}
	if p.APIVersion == device.V2 {
		return e.checkV2Activation(p, a, c)
	}
	probe := a.Probe
	if probe.OperationID != p.OperationID || probe.DeviceID != p.DeviceID || probe.Generation != p.TargetGeneration || probe.Endpoint != e.Config.MQTTEndpoint {
		return device.ErrDenied
	}
	return device.MatchProbe(probe, probe, e.now())
}

func checkRetirement(p device.Plan, r device.Retirement) error {
	if r.OperationID != p.OperationID || r.PlanDigest != p.Digest || r.Generation != p.ExpectedGeneration || !r.PolicyDurable || !r.SessionsTerminated || !r.ApplicationAccessDenied || (r.TLSObservation != "accepted" && r.TLSObservation != "denied") {
		return device.ErrUnknown
	}
	return nil
}

// Apply either starts this exact plan or reconciles its persisted operation.
func (e *Engine) Apply(ctx context.Context, p device.Plan) (Receipt, error) {
	s, err := e.Journal.Load(ctx)
	if err != nil {
		return Receipt{}, err
	}
	if p.APIVersion == device.V2 && s.Operation != nil && s.Operation.Plan == p && s.Operation.Phase == device.Retired {
		return CompletedHistory(s, p)
	}
	if err = e.prepareSnapshot(&s, p); err != nil {
		return e.failure(ctx, s, err)
	}
	early, latest, clockErr := e.interval(ctx, s.ClockFloor)
	if clockErr != nil || e.Config.ClockTrust != "trusted-system-clock" {
		return e.failure(ctx, s, device.ErrDenied)
	}
	if !p.ExpiresAt.After(latest) {
		if s.Operation != nil && s.Operation.Plan == p && s.Operation.Phase == device.Retired {
			r := Report(s)
			r.Outcome = "succeeded"
			r.Reason = ""
			return r, nil
		}
		return e.failure(ctx, s, device.ErrPlanExpired)
	}
	if err := p.Validate(latest); err != nil {
		return e.failure(ctx, s, device.ErrDenied)
	}
	digest, err := e.Config.Digest()
	if err != nil {
		return e.failure(ctx, s, err)
	}
	if p.DeviceID != s.DeviceID || digest != p.ConfigDigest {
		return e.failure(ctx, s, device.ErrConflict)
	}
	if s.Operation != nil && s.Operation.Plan.OperationID == p.OperationID {
		if s.Operation.Plan != p {
			return e.failure(ctx, s, device.ErrConflict)
		}
	} else {
		active := uint64(0)
		if s.Active != nil {
			active = s.Active.Binding.Generation
		}
		if (s.Operation != nil && s.Operation.Phase != device.Retired) || active != p.ExpectedGeneration || p.TargetGeneration != s.Counter+1 {
			return e.failure(ctx, s, device.ErrConflict)
		}
		s.Counter = p.TargetGeneration
		s.Operation = &device.Operation{Plan: p, Phase: device.Planned, Previous: s.Active, Outcome: "running"}
		if p.APIVersion == device.V2 {
			s.Operation.Snapshot = e.Snapshot.Bytes()
			if s.Active != nil {
				store, ok := e.Keys.(publicStore)
				if !ok {
					return e.failure(ctx, s, device.ErrUnsupported)
				}
				previousCSR, loadErr := store.CSR(ctx, *s.Active)
				if loadErr != nil {
					return e.failure(ctx, s, loadErr)
				}
				previousChain, loadErr := e.Keys.Certificate(ctx, *s.Active)
				if loadErr != nil {
					return e.failure(ctx, s, loadErr)
				}
				s.Operation.PreviousCSR = previousCSR
				s.Operation.PreviousCertificate = previousChain
			}
		}
	}
	s.ClockFloor = early
	s, err = e.Journal.Save(ctx, s, s.Revision)
	if err != nil {
		return e.failure(ctx, s, err)
	}
	if err := e.checkpoint(string(s.Operation.Phase)); err != nil {
		return e.failure(ctx, s, err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return e.failure(ctx, s, err)
		}
		if _, _, decisionErr := e.decision(ctx, p, s.ClockFloor); decisionErr != nil {
			return e.failure(ctx, s, decisionErr)
		}

		currentDigest, digestErr := e.Config.Digest()
		if digestErr != nil || currentDigest != p.ConfigDigest {
			return e.failure(ctx, s, device.ErrConflict)
		}
		o := s.Operation
		var target device.Credential
		if o.Phase == device.Issued {
			if err = e.Keys.StoreCertificate(ctx, *o.Target, o.Certificate); err != nil {
				return e.failure(ctx, s, err)
			}
		}
		if o.Target != nil && o.Phase != device.Planned && o.Phase != device.KeyReady && o.Phase != device.IssueIntent {
			target, err = e.credential(ctx, *o.Target)
			if err != nil {
				return e.failure(ctx, s, err)
			}
		}
		switch o.Phase {
		case device.Planned:
			auth, authErr := e.authorizationCredential(ctx, s, p)
			if authErr != nil {
				return e.failure(ctx, s, authErr)
			}
			if err = e.Platform.Authorize(ctx, p, auth); err != nil {
				return e.failure(ctx, s, err)
			}
			h, keyErr := e.Keys.Stage(ctx, p.Binding())
			if keyErr != nil {
				return e.failure(ctx, s, keyErr)
			}
			if err = e.checkpoint("key-created"); err != nil {
				return e.failure(ctx, s, err)
			}
			o.Target = &h
			o.CSR, err = e.stageCSR(ctx, h)
			if err == nil {
				s, err = e.save(ctx, s, device.KeyReady)
			}
		case device.KeyReady:
			s, err = e.save(ctx, s, device.IssueIntent)
			if err != nil {
				break
			}
			s, err = e.issue(ctx, s, false)
		case device.IssueIntent:
			s, err = e.issue(ctx, s, true)
		case device.Issued:
			// A certificate may have been journaled before its slot write.
			if err = e.Keys.StoreCertificate(ctx, *o.Target, o.Certificate); err != nil {
				break
			}
			s, err = e.save(ctx, s, device.RegisterIntent)
			if err != nil {
				break
			}
			err = e.Platform.Register(ctx, p, target)
			if err == nil {
				if err = e.checkpoint("registered-remote"); err == nil {
					s, err = e.save(ctx, s, device.Registered)
				}
			}
		case device.RegisterIntent:
			err = e.Platform.Registration(ctx, p, target)
			if errors.Is(err, device.ErrNotFound) {
				err = e.Platform.Register(ctx, p, target)
			}
			if err == nil {
				s, err = e.save(ctx, s, device.Registered)
			}
		case device.Registered:
			o.Probe, err = e.probePointer(ctx, s, target)
			if err == nil {
				s, err = e.save(ctx, s, device.Verified)
			}
		case device.Verified:
			// Never authorize activation using a probe persisted by a previous run.
			o.Probe, err = e.probePointer(ctx, s, target)
			if err != nil {
				break
			}
			s, err = e.save(ctx, s, device.ActivateIntent)
			if err != nil {
				break
			}
			a, activateErr := e.Platform.Activate(ctx, p, target)
			err = activateErr
			if err == nil {
				err = e.checkActivation(p, a, target)
				if err == nil {
					s.Operation.Activation = &a
					err = e.checkpoint("activated-remote")
					if err == nil {
						s, err = e.save(ctx, s, device.Activated)
					}
				}
			}
		case device.ActivateIntent:
			a, activateErr := e.Platform.ActivationStatus(ctx, p, target)
			err = activateErr
			if errors.Is(err, device.ErrNotFound) {
				a, err = e.Platform.Activate(ctx, p, target)
			}
			if err == nil {
				err = e.checkActivation(p, a, target)
				if err == nil {
					o.Activation = &a
					s, err = e.save(ctx, s, device.Activated)
				}
			}
		case device.Activated:
			a, observeErr := e.Platform.ActivationStatus(ctx, p, target)
			err = observeErr
			if err == nil {
				err = e.checkActivation(p, a, target)
			}
			if err == nil {
				s, err = e.rememberActivation(ctx, s, a)
			}
			if err != nil {
				break
			}
			if err = e.activatePointer(ctx, *o.Target, p, s.ClockFloor); err != nil {
				break
			}
			if err = e.checkpoint("pointer-written"); err != nil {
				break
			}
			s.Active = o.Target
			s, err = e.save(ctx, s, device.Committed)
		case device.Committed:
			active, pointerErr := e.Keys.Active(ctx)
			if pointerErr != nil || active == nil || *active != *o.Target {
				return e.failure(ctx, s, device.ErrConflict)
			}
			if o.Previous == nil {
				s, err = e.save(ctx, s, device.Retired)
				break
			}
			_, err = e.verify(ctx, s, target)
			if err != nil {
				break
			}
			a, observeErr := e.Platform.ActivationStatus(ctx, p, target)
			err = observeErr
			if err == nil {
				err = e.checkActivation(p, a, target)
			}
			if err == nil {
				s, err = e.rememberActivation(ctx, s, a)
			}
			if err != nil {
				break
			}
			previous, loadErr := e.previousArtifact(ctx, *o.Previous)
			err = loadErr
			if err != nil {
				break
			}
			s, err = e.save(ctx, s, device.BrokerRetireIntent)
			if err != nil {
				break
			}
			r, retireErr := e.Platform.Retire(ctx, p, previous, target)
			err = retireErr
			if err == nil {
				err = e.retirement(ctx, p, r, target)
				if err == nil {
					s.Operation.Retirement = &r
					err = e.checkpoint("broker-retired-remote")
					if err == nil {
						s, err = e.save(ctx, s, device.BrokerRetired)
					}
				}
			}
		case device.BrokerRetireIntent:
			previous, loadErr := e.previousArtifact(ctx, *o.Previous)
			err = loadErr
			if err != nil {
				break
			}
			r, retireErr := e.Platform.RetirementStatus(ctx, p, previous, target)
			err = retireErr
			if errors.Is(err, device.ErrNotFound) {
				r, err = e.Platform.Retire(ctx, p, previous, target)
			}
			if err == nil {
				err = e.retirement(ctx, p, r, target)
				if err == nil {
					o.Retirement = &r
					s, err = e.save(ctx, s, device.BrokerRetired)
				}
			}
		case device.BrokerRetired:
			// Broker restart also disconnects the new application session.
			a, observeErr := e.Platform.ActivationStatus(ctx, p, target)
			err = observeErr
			if err == nil {
				err = e.checkActivation(p, a, target)
			}
			if err == nil {
				s, err = e.rememberActivation(ctx, s, a)
			}
			if err != nil {
				break
			}
			previous, loadErr := e.previousArtifact(ctx, *o.Previous)
			err = loadErr
			if err != nil {
				break
			}
			s, err = e.save(ctx, s, device.CARevokeIntent)
			if err != nil {
				break
			}
			err = e.Authority.Revoke(ctx, p, previous, target)
			if err == nil {
				err = e.checkpoint("ca-revoked-remote")
				if err == nil {
					s, err = e.save(ctx, s, device.CARevoked)
				}
			}
		case device.CARevokeIntent:
			previous, loadErr := e.previousArtifact(ctx, *o.Previous)
			err = loadErr
			if err != nil {
				break
			}
			err = e.Authority.RevocationStatus(ctx, p, previous, target)
			if errors.Is(err, device.ErrNotFound) {
				err = e.Authority.Revoke(ctx, p, previous, target)
			}
			if err == nil {
				s, err = e.save(ctx, s, device.CARevoked)
			}
		case device.CARevoked:
			a, observeErr := e.Platform.ActivationStatus(ctx, p, target)
			err = observeErr
			if err == nil {
				err = e.checkActivation(p, a, target)
			}
			if err == nil {
				s, err = e.rememberActivation(ctx, s, a)
			}
			if err != nil {
				break
			}
			s, err = e.save(ctx, s, device.DestroyIntent)
		case device.DestroyIntent:
			a, observeErr := e.Platform.ActivationStatus(ctx, p, target)
			err = observeErr
			if err == nil {
				err = e.checkActivation(p, a, target)
			}
			if err == nil {
				s, err = e.rememberActivation(ctx, s, a)
			}
			if err != nil {
				break
			}
			err = e.Keys.Destroy(ctx, *o.Previous)
			if err == nil {
				err = e.checkpoint("key-destroyed")
				if err == nil {
					s, err = e.save(ctx, s, device.Retired)
				}
			}
		case device.Retired:
			if s.SchemaVersion != 2 {
				o.Outcome = "succeeded"
				o.Reason = ""
				s, err = e.Journal.Save(ctx, s, s.Revision)
				if err != nil {
					return e.failure(ctx, s, err)
				}
			}
			r := Report(s)
			if a, liveErr := e.Platform.ActivationStatus(ctx, p, target); liveErr == nil && e.checkActivation(p, a, target) == nil {
				r.Health = "application-confirmed"
			}
			return r, nil
		default:
			return e.failure(ctx, s, device.ErrConflict)
		}
		if err != nil {
			return e.failure(ctx, s, err)
		}
	}
}

func (e *Engine) probePointer(ctx context.Context, s device.State, c device.Credential) (*device.Probe, error) {
	p, err := e.verify(ctx, s, c)
	return &p, err
}

func (e *Engine) issue(ctx context.Context, s device.State, lookup bool) (device.State, error) {
	o := s.Operation
	auth, err := e.authorizationCredential(ctx, s, o.Plan)
	if err != nil {
		return s, err
	}
	r := device.IssueRequest{Plan: o.Plan, CSR: o.CSR, Credential: auth}
	var chain []byte
	knownResult := lookup
	if lookup {
		chain, err = e.Authority.Lookup(ctx, r)
		if errors.Is(err, device.ErrNotFound) {
			knownResult = false
			chain, err = e.Authority.Issue(ctx, r)
		}
	} else {
		chain, err = e.Authority.Issue(ctx, r)
	}
	if err != nil {
		return s, err
	}
	if err = e.checkpoint("issued-remote"); err != nil {
		return s, err
	}
	signer, err := e.Keys.Signer(ctx, *o.Target)
	if err != nil {
		return s, err
	}
	if o.Plan.APIVersion == device.V2 {
		early, late, err := e.decision(ctx, o.Plan, s.ClockFloor)
		if err != nil {
			return s, err
		}
		policy, err := policyFor(o.Target.Binding)
		if err != nil {
			return s, err
		}
		v, err := e.Snapshot.Validation(early, late, false, false)
		if err != nil {
			return s, err
		}
		if !knownResult {
			v.MaxBackdate = time.Duration(e.Snapshot.Limits.MaxBackdateSeconds) * time.Second
		}
		if err = policy.ValidateChain(chain, o.CSR, o.Target.PublicKeyDigest, s.DeviceID, o.Plan.TargetGeneration, v); err != nil {
			return s, device.ErrDenied
		}
		if _, err = e.validateV2Credential(ctx, *o.Target, signer, chain, false, false); err != nil {
			return s, err
		}
	} else {
		roots, err := e.Config.Roots()
		if err != nil {
			return s, err
		}
		if _, err = ValidateChain(chain, signer, device.Subject(s.DeviceID, o.Plan.TargetGeneration), roots, e.now()); err != nil {
			return s, err
		}
	}
	o.Certificate = chain
	// Store the public result before the slot; a crash can reconstruct the slot.
	s, err = e.save(ctx, s, device.Issued)
	if err != nil {
		return s, err
	}
	if err = e.Keys.StoreCertificate(ctx, *o.Target, chain); err != nil {
		return s, err
	}
	return s, e.checkpoint("certificate-written")
}
