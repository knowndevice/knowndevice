// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
	"github.com/knowndevice/knowndevice/internal/keystore"
)

type applicationRecord struct {
	SchemaVersion      int                      `json:"schemaVersion"`
	Plan               device.Plan              `json:"plan"`
	Active             device.CredentialBinding `json:"active"`
	ActivationRevision uint64                   `json:"activationRevision"`
	SelectedAt         time.Time                `json:"selectedAt"`
	SessionID          string                   `json:"sessionId"`
	Certificate        []byte                   `json:"certificate"`
}
type applicationIntent struct {
	SchemaVersion int                      `json:"schemaVersion"`
	Plan          device.Plan              `json:"plan"`
	Candidate     device.CredentialBinding `json:"candidate"`
	Phase         string                   `json:"phase"`
	Revision      uint64                   `json:"revision"`
}
type application struct {
	mu         sync.Mutex
	dir        string
	config     servicesConfig
	snapshot   *device.PublicSnapshot
	active     *applicationRecord
	pending    *applicationRecord
	instanceID string
	lock       *os.File
	lockInfo   os.FileInfo
	clockFloor time.Time
}

func (s *control) application(ctx context.Context, r *reservation, mutation bool) (device.ApplicationEvidence, error) {
	revision := r.Revision
	// The application uses the independent transport listener. No registry lock
	// crosses that callback; the original reservation is fenced on return.
	s.mu.Unlock()
	result, err := s.observeApplication(ctx, r, mutation)
	s.mu.Lock()
	latest, e := s.store.operation(ctx, r.Plan)
	if e != nil {
		return result, e
	}
	if latest == nil || latest.Revision != revision || latest.Candidate != r.Candidate || latest.Registered != r.Registered {
		return result, device.ErrConflict
	}
	if e = s.plan(ctx, r.Plan, false); e != nil {
		return result, e
	}
	return result, err
}

func (s *control) observeApplication(ctx context.Context, r *reservation, _ bool) (device.ApplicationEvidence, error) {
	id, e := device.RandomID()
	if e != nil {
		return device.ApplicationEvidence{}, e
	}
	in := device.RoleRequest{Plan: r.Plan, CSR: r.CSR, Certificate: r.Certificate, RequestID: id}
	var status device.RoleResponse
	if e = post(ctx, s.snapshot, "application", "/status", &s.observer, in, &status); e != nil {
		return device.ApplicationEvidence{}, device.ErrUnknown
	}
	if status.Status == "not-started" && status.Evidence != nil {
		v := status.Evidence
		if v.Plan == r.Plan && v.Subject == r.Candidate && v.RequestID == id && v.Role == "application" && v.Action == "status" && v.Source == source(s.snapshot, "application") && v.Status == "not-started" && v.Revision > 0 && v.Reference != "" && time.Now().Add(time.Second).Before(v.Deadline) {
			return device.ApplicationEvidence{}, device.ErrNotFound
		}
		return device.ApplicationEvidence{}, device.ErrUnknown
	}
	if status.Status != "ok" || status.Application == nil {
		return device.ApplicationEvidence{}, device.ErrUnknown
	}
	prior := *status.Application
	if e = s.validateApplication(prior, r, in, false); e != nil {
		return prior, e
	}
	nonce, e := device.RandomID()
	if e != nil {
		return prior, e
	}
	id, e = device.RandomID()
	if e != nil {
		return prior, e
	}
	endpoint, e := s.snapshot.Role("transport")
	if e != nil {
		return prior, e
	}
	deadline := time.Now().UTC().Add(time.Duration(s.snapshot.Limits.ChallengeSeconds) * time.Second)
	if deadline.After(r.Plan.ExpiresAt) {
		deadline = r.Plan.ExpiresAt
	}
	in.RequestID = id
	in.Probe = device.Probe{OperationID: r.Plan.OperationID, DeviceID: r.Plan.DeviceID, Generation: r.Plan.TargetGeneration, Endpoint: endpoint.Endpoint, Nonce: nonce, Deadline: deadline}
	started := time.Now()
	var observed device.RoleResponse
	if e = post(ctx, s.snapshot, "application", "/observe", &s.observer, in, &observed); e != nil || observed.Status != "ok" || observed.Application == nil {
		return prior, device.ErrUnknown
	}
	result := *observed.Application
	if time.Since(started) > 5*time.Second || result.ActivationRevision != prior.ActivationRevision {
		return result, device.ErrDenied
	}
	if e = s.validateApplication(result, r, in, true); e != nil {
		return result, e
	}
	return result, nil
}

func (s *control) validateApplication(a device.ApplicationEvidence, r *reservation, in device.RoleRequest, live bool) error {
	role, e := s.snapshot.Role("application")
	if e != nil {
		return e
	}
	expectedSource := source(s.snapshot, role.Role)
	now := time.Now().UTC()
	if a.Phase != "activated" || a.ActivationRevision == 0 || a.Active != r.Candidate || a.ApplicationID != s.snapshot.Composition.ApplicationID || a.Evidence.Plan != r.Plan || a.Evidence.Role != "application" || a.Evidence.RequestID != in.RequestID || a.Evidence.Source != expectedSource || a.Evidence.Subject != r.Candidate || a.Evidence.Status != "completed" || a.Evidence.Revision != a.ActivationRevision || a.Evidence.ObservedAt.After(now.Add(time.Second)) || now.Sub(a.Evidence.ObservedAt) > 5*time.Second || !now.Add(time.Second).Before(a.Evidence.Deadline) {
		return device.ErrDenied
	}
	if live && (a.Evidence.Action != "observe" || a.InstanceID == "" || a.ConnectionID == "" || a.SessionID == "" || a.Challenge != in.Probe || device.MatchProbe(in.Probe, a.Challenge, now.Add(time.Second)) != nil || len(a.AcceptedScope) != 1 || a.AcceptedScope[0] != "fresh-challenge") {
		return device.ErrDenied
	}
	if !live && a.Evidence.Action != "status" {
		return device.ErrDenied
	}
	return nil
}

func openApplication(dir string) (*application, error) {
	cfg, snapshot, e := loadServices(dir)
	if e != nil {
		return nil, e
	}
	id, e := device.RandomID()
	if e != nil {
		return nil, e
	}
	w := &application{dir: dir, config: cfg, snapshot: snapshot, instanceID: id}
	info, e := os.Lstat(filepath.Join(dir, "application"))
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("private application state directory required")
	}
	if info, e := os.Lstat(filepath.Join(dir, "application", "writer.lock")); e == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return nil, device.ErrConflict
	} else if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	w.lock, e = os.OpenFile(filepath.Join(dir, "application", "writer.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(w.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		w.lock.Close()
		return nil, device.ErrConflict
	}
	w.lockInfo, e = w.lock.Stat()
	if e != nil {
		w.lock.Close()
		return nil, e
	}
	var record applicationRecord
	if e = readPrivateJSON(filepath.Join(dir, "application", "active.json"), &record); e == nil {
		if record.SchemaVersion != 2 || snapshot.ValidatePlan(record.Plan) != nil || record.Active.Generation != record.Plan.TargetGeneration || record.ActivationRevision == 0 || record.Active.ProfileDigest != record.Plan.ProfileDigest {
			w.lock.Close()
			return nil, fmt.Errorf("application state version or binding refused")
		}
		w.active = &record
	} else if !os.IsNotExist(e) {
		w.lock.Close()
		return nil, e
	}
	var pending applicationRecord
	if e = readPrivateJSON(filepath.Join(dir, "application", "active.json.pending"), &pending); e == nil {
		if pending.SchemaVersion != 2 || snapshot.ValidatePlan(pending.Plan) != nil || pending.Active.PlanDigest != pending.Plan.Digest || pending.ActivationRevision == 0 {
			w.lock.Close()
			return nil, fmt.Errorf("incomplete application selection requires intervention")
		}
		w.pending = &pending
	} else if !os.IsNotExist(e) {
		w.lock.Close()
		return nil, e
	}
	var clock struct {
		Earliest time.Time `json:"earliest"`
	}
	if e = readPrivateJSON(filepath.Join(dir, "application", "clock.json"), &clock); e == nil {
		w.clockFloor = clock.Earliest
	} else if !os.IsNotExist(e) {
		w.lock.Close()
		return nil, e
	}
	return w, nil
}

func (w *application) effect(ctx context.Context, p device.Plan) error {
	clock := device.SystemClock{Uncertainty: time.Second, MaximumAge: time.Duration(w.snapshot.Limits.MaximumAssessmentAgeSeconds) * time.Second, DriftPPM: float64(w.snapshot.Limits.DriftPPM)}
	assessment, e := clock.Assess(ctx, w.clockFloor)
	if e != nil {
		return e
	}
	early, late, e := assessment.Interval(time.Now(), w.clockFloor)
	if e != nil {
		return e
	}
	if !late.Before(p.ExpiresAt) {
		return device.ErrPlanExpired
	}
	cfg, e := device.LoadConfig(w.config.DeviceConfig)
	if e != nil {
		return device.ErrDenied
	}
	digest, e := cfg.Digest()
	if e != nil || digest != p.ConfigDigest {
		return device.ErrDenied
	}
	if _, e = checkEntitlement(w.dir, p); e != nil {
		return e
	}
	if e = writeJSON(filepath.Join(w.dir, "application", "clock.json"), struct {
		Earliest time.Time `json:"earliest"`
	}{early}); e != nil {
		return device.ErrUnknown
	}
	w.clockFloor = early
	return nil
}

func readPrivateJSON(path string, v any) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return device.ErrConflict
	}
	return readJSON(path, v)
}
func (w *application) intent(p device.Plan) (*applicationIntent, error) {
	path := filepath.Join(w.dir, "application", "operation-"+p.OperationID+".json")
	var record applicationIntent
	e := readPrivateJSON(path, &record)
	if os.IsNotExist(e) {
		e = readPrivateJSON(path+".pending", &record)
	}
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if record.SchemaVersion != 2 || record.Plan != p || record.Candidate.PlanDigest != p.Digest || record.Revision == 0 {
		return nil, device.ErrConflict
	}
	if record.Phase != "stage-intent" && record.Phase != "candidate-verified" && record.Phase != "switch-intent" && record.Phase != "activated" {
		return nil, device.ErrConflict
	}
	return &record, nil
}
func (w *application) saveIntent(record *applicationIntent) error {
	return writeJSON(filepath.Join(w.dir, "application", "operation-"+record.Plan.OperationID+".json"), record)
}
func (w *application) notStarted(in device.RoleRequest) (device.RoleResponse, error) {
	csr, e := w.snapshot.Profile.ValidateCSR(in.CSR, in.Plan.DeviceID, in.Plan.TargetGeneration)
	if e != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	certs, e := credentialprofile.ParseChain(in.Certificate)
	if e != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	v, e := certificateValidation(w.snapshot, false, false)
	if e != nil || w.snapshot.Profile.ValidateChain(in.Certificate, in.CSR, device.Hash(csr.RawSubjectPublicKeyInfo), in.Plan.DeviceID, in.Plan.TargetGeneration, v) != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	candidate := bound(in.Plan, csr)
	candidate.CertificateFingerprint = device.Hash(certs[0].Raw)
	// A lost directory-sync acknowledgment is reconciled from both files, even
	// without a process restart. It cannot establish effect absence.
	var actual applicationRecord
	if e = readPrivateJSON(filepath.Join(w.dir, "application", "active.json"), &actual); e == nil && actual.Plan == in.Plan {
		if actual.SchemaVersion != 2 || actual.Active != candidate || actual.ActivationRevision == 0 {
			return device.RoleResponse{}, device.ErrConflict
		}
		if e = w.effect(context.Background(), in.Plan); e != nil {
			return device.RoleResponse{}, e
		}
		if e = writeJSON(filepath.Join(w.dir, "application", "active.json"), actual); e != nil {
			return device.RoleResponse{}, device.ErrUnknown
		}
		w.active = &actual
		return device.RoleResponse{}, nil
	} else if e != nil && !os.IsNotExist(e) {
		return device.RoleResponse{}, device.ErrUnknown
	}
	if w.pending == nil {
		var pending applicationRecord
		if e = readPrivateJSON(filepath.Join(w.dir, "application", "active.json.pending"), &pending); e == nil {
			if pending.SchemaVersion != 2 || pending.Plan != in.Plan || pending.Active != candidate || pending.ActivationRevision == 0 {
				return device.RoleResponse{}, device.ErrConflict
			}
			w.pending = &pending
		} else if !os.IsNotExist(e) {
			return device.RoleResponse{}, device.ErrUnknown
		}
	}
	record, e := w.intent(in.Plan)
	if e != nil {
		return device.RoleResponse{}, device.ErrUnknown
	}
	revision := uint64(1)
	if record != nil {
		if record.Candidate != candidate {
			return device.RoleResponse{}, device.ErrConflict
		}
		revision = record.Revision
		if record.Phase == "activated" {
			return device.RoleResponse{}, device.ErrConflict
		}
	}
	if w.pending != nil {
		if w.pending.Plan != in.Plan || w.pending.Active != candidate || !time.Now().Add(time.Second).Before(in.Plan.ExpiresAt) {
			return device.RoleResponse{}, device.ErrUnknown
		}
		if e = w.effect(context.Background(), in.Plan); e != nil {
			return device.RoleResponse{}, e
		}
		if e = writeJSON(filepath.Join(w.dir, "application", "active.json"), w.pending); e != nil {
			return device.RoleResponse{}, device.ErrUnknown
		}
		w.active = w.pending
		w.pending = nil
		return device.RoleResponse{}, nil
	}
	entry := evidence(in.Plan, candidate, "application", "status", in.RequestID, revision, source(w.snapshot, "application"), "not-started")
	return device.RoleResponse{Status: "not-started", Evidence: &entry}, nil
}

func (w *application) target(ctx context.Context, p device.Plan, chain []byte) (tls.Certificate, device.CredentialBinding, error) {
	certs, e := credentialprofile.ParseChain(chain)
	if e != nil {
		return tls.Certificate{}, device.CredentialBinding{}, device.ErrDenied
	}
	v, e := certificateValidation(w.snapshot, true, false)
	if e != nil {
		return tls.Certificate{}, device.CredentialBinding{}, e
	}
	if e = w.snapshot.Profile.ValidatePublicChain(certs, p.DeviceID, p.TargetGeneration, v); e != nil {
		return tls.Certificate{}, device.CredentialBinding{}, device.ErrDenied
	}
	store, e := keystore.OpenReadOnlyV2(filepath.Join(w.dir, "device", "slots"), w.snapshot.DeploymentID, w.snapshot.DeviceID, w.snapshot.Profile.ID, w.snapshot.Profile.Version, w.snapshot.Profile.PolicyDigest)
	if e != nil {
		return tls.Certificate{}, device.CredentialBinding{}, device.ErrUnknown
	}
	defer store.Close()
	h := device.Handle{Binding: p.Binding(), PublicKeyDigest: device.Hash(certs[0].RawSubjectPublicKeyInfo)}
	signer, e := store.Signer(ctx, h)
	if e != nil {
		return tls.Certificate{}, device.CredentialBinding{}, device.ErrUnknown
	}
	stored, e := store.Certificate(ctx, h)
	if e != nil || !bytes.Equal(stored, chain) {
		return tls.Certificate{}, device.CredentialBinding{}, device.ErrDenied
	}
	credential := tls.Certificate{PrivateKey: signer, Leaf: certs[0]}
	for _, c := range certs {
		credential.Certificate = append(credential.Certificate, c.Raw)
	}
	if w.active != nil && w.active.Plan == p && bytes.Equal(w.active.Certificate, chain) {
		return credential, w.active.Active, nil
	}
	var response device.RoleResponse
	id, e := device.RandomID()
	if e != nil {
		return credential, device.CredentialBinding{}, e
	}
	if e = post(ctx, w.snapshot, "control", "/registration", &credential, device.RoleRequest{Plan: p, Certificate: chain, RequestID: id}, &response); e != nil || response.Status != "ok" || response.Evidence == nil {
		return credential, device.CredentialBinding{}, device.ErrDenied
	}
	binding := response.Evidence.Subject
	if binding.PlanDigest != p.Digest || binding.ConfigDigest != p.ConfigDigest || binding.PublicKeyDigest != h.PublicKeyDigest || binding.CertificateFingerprint != device.Hash(certs[0].Raw) || response.Evidence.Role != "platform" || response.Evidence.Plan != p || response.Evidence.RequestID != id {
		return credential, binding, device.ErrDenied
	}
	return credential, binding, nil
}

func (w *application) observe(ctx context.Context, p device.Plan, chain []byte, probe device.Probe, requestID string) (device.ApplicationEvidence, error) {
	credential, binding, e := w.target(ctx, p, chain)
	if e != nil {
		return device.ApplicationEvidence{}, e
	}
	if probe.Nonce == "" {
		nonce, e := device.RandomID()
		if e != nil {
			return device.ApplicationEvidence{}, e
		}
		role, e := w.snapshot.Role("transport")
		if e != nil {
			return device.ApplicationEvidence{}, e
		}
		deadline := time.Now().UTC().Add(time.Duration(w.snapshot.Limits.ChallengeSeconds) * time.Second)
		if deadline.After(p.ExpiresAt) {
			deadline = p.ExpiresAt
		}
		probe = device.Probe{OperationID: p.OperationID, DeviceID: p.DeviceID, Generation: p.TargetGeneration, Endpoint: role.Endpoint, Nonce: nonce, Deadline: deadline}
	}
	id, e := device.RandomID()
	if e != nil {
		return device.ApplicationEvidence{}, e
	}
	var observed device.RoleResponse
	started := time.Now()
	if e = post(ctx, w.snapshot, "transport", "/challenge", &credential, device.RoleRequest{Plan: p, Probe: probe, RequestID: id}, &observed); e != nil || observed.Status != "ok" || observed.Evidence == nil {
		return device.ApplicationEvidence{}, device.ErrDenied
	}
	entry := *observed.Evidence
	transport, _ := w.snapshot.Role("transport")
	if entry.Subject != binding || entry.Plan != p || entry.RequestID != id || entry.Role != "transport" || entry.Status != "accepted" || entry.Source != source(w.snapshot, transport.Role) || entry.Deadline != probe.Deadline || time.Since(started) > 5*time.Second || device.MatchProbe(probe, probe, time.Now().Add(time.Second)) != nil {
		return device.ApplicationEvidence{}, device.ErrDenied
	}
	result := device.ApplicationEvidence{Evidence: evidence(p, binding, "application", "observe", requestID, 0, source(w.snapshot, "application"), "completed"), Phase: "candidate-verified", ApplicationID: w.snapshot.Composition.ApplicationID, Active: binding, InstanceID: w.instanceID, ConnectionID: entry.Reference, Challenge: probe, AcceptedScope: []string{"fresh-challenge"}}
	result.Evidence.Deadline = probe.Deadline
	if w.active != nil && w.active.Plan == p && w.active.Active == binding {
		result.Phase = "activated"
		result.ActivationRevision = w.active.ActivationRevision
		result.Evidence.Revision = w.active.ActivationRevision
		result.SessionID = w.active.SessionID
	}
	return result, nil
}

func (w *application) request(out http.ResponseWriter, req *http.Request) {
	in, e := decodeRequest(out, req)
	if e != nil {
		reply(out, device.RoleResponse{}, e)
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	response, e := w.handle(req, in)
	reply(out, response, e)
}
func (w *application) handle(req *http.Request, in device.RoleRequest) (device.RoleResponse, error) {
	p := in.Plan
	status := req.URL.Path == "/status"
	now := time.Now().Add(time.Second)
	if status {
		now = p.ExpiresAt.Add(-time.Nanosecond)
	}
	if w.snapshot.ValidatePlan(p) != nil || p.Validate(now) != nil {
		return device.RoleResponse{}, device.ErrDenied
	}
	if _, e := checkEntitlement(w.dir, p); e != nil {
		return device.RoleResponse{}, e
	}
	if req.URL.Path == "/status" || req.URL.Path == "/observe" {
		if verifyPeerRole(req, w.snapshot, "observer") != nil || peer(req) == nil || device.Hash(peer(req).Raw) != w.config.ObserverFingerprint || device.Hash(peer(req).RawSubjectPublicKeyInfo) != w.config.ObserverPublicKeyDigest {
			return device.RoleResponse{}, device.ErrDenied
		}
		if w.active == nil || w.active.Plan != p {
			response, e := w.notStarted(in)
			if e != nil || response.Status != "" {
				return response, e
			}
		}
		if status {
			a := device.ApplicationEvidence{Evidence: evidence(p, w.active.Active, "application", "status", in.RequestID, w.active.ActivationRevision, source(w.snapshot, "application"), "completed"), Phase: "activated", ApplicationID: w.snapshot.Composition.ApplicationID, ActivationRevision: w.active.ActivationRevision, Active: w.active.Active, InstanceID: w.instanceID, SessionID: w.active.SessionID}
			var fixture policy
			if e := readJSON(filepath.Join(w.dir, "fixtures", "policy.json"), &fixture); e != nil {
				return device.RoleResponse{}, device.ErrUnknown
			}
			if fixture.StagedStatusOnly {
				a.Phase = "candidate-verified"
			}
			return device.RoleResponse{Status: "ok", Application: &a, Evidence: &a.Evidence}, nil
		}
		if e := w.effect(req.Context(), p); e != nil {
			return device.RoleResponse{}, e
		}
		a, e := w.observe(req.Context(), p, w.active.Certificate, in.Probe, in.RequestID)
		if e != nil {
			return device.RoleResponse{}, e
		}
		var fixture policy
		if e = readJSON(filepath.Join(w.dir, "fixtures", "policy.json"), &fixture); e != nil {
			return device.RoleResponse{}, device.ErrUnknown
		}
		if fixture.WrongObservationRevision {
			a.ActivationRevision++
		}
		return device.RoleResponse{Status: "ok", Application: &a, Evidence: &a.Evidence}, nil
	}
	if req.URL.Path != "/activate" || verifyPeerRole(req, w.snapshot, "operational") != nil {
		return device.RoleResponse{}, device.ErrDenied
	}
	if e := w.effect(req.Context(), p); e != nil {
		return device.RoleResponse{}, e
	}
	certs, e := credentialprofile.ParseChain(in.Certificate)
	if e != nil || device.Hash(certs[0].Raw) != device.Hash(peer(req).Raw) || !bytes.Equal(certs[0].RawSubjectPublicKeyInfo, peer(req).RawSubjectPublicKeyInfo) {
		return device.RoleResponse{}, device.ErrDenied
	}
	if w.active != nil && w.active.Plan != p && (p.ExpectedGeneration != w.active.Active.Generation || p.TargetGeneration <= w.active.Active.Generation) {
		return device.RoleResponse{}, device.ErrConflict
	}
	_, candidate, e := w.target(req.Context(), p, in.Certificate)
	if e != nil {
		return device.RoleResponse{}, e
	}
	intent, e := w.intent(p)
	if e != nil {
		return device.RoleResponse{}, e
	}
	if intent == nil {
		intent = &applicationIntent{SchemaVersion: 2, Plan: p, Candidate: candidate, Phase: "stage-intent", Revision: 1}
		if e = w.saveIntent(intent); e != nil {
			return device.RoleResponse{}, device.ErrUnknown
		}
	} else if intent.Candidate != candidate {
		return device.RoleResponse{}, device.ErrConflict
	}
	a, e := w.observe(req.Context(), p, in.Certificate, device.Probe{}, in.RequestID)
	if e != nil {
		return device.RoleResponse{}, e
	}
	if w.active == nil || w.active.Plan != p {
		intent.Phase = "candidate-verified"
		intent.Revision++
		if e = w.saveIntent(intent); e != nil {
			return device.RoleResponse{}, device.ErrUnknown
		}
		if e = labCheckpoint(req.Context(), w.dir, "application", "candidate-verified", p); e != nil {
			return device.RoleResponse{}, e
		}
		if e = w.effect(req.Context(), p); e != nil {
			return device.RoleResponse{}, e
		}
		var fixture policy
		if e = readJSON(filepath.Join(w.dir, "fixtures", "policy.json"), &fixture); e != nil || fixture.FailActivationPersistence {
			return device.RoleResponse{Application: &a}, device.ErrUnknown
		}
		info, e := os.Lstat(filepath.Join(w.dir, "application", "writer.lock"))
		if e != nil || !os.SameFile(info, w.lockInfo) {
			return device.RoleResponse{}, device.ErrConflict
		}
		revision := uint64(1)
		if w.active != nil {
			revision = w.active.ActivationRevision + 1
		}
		session, e := device.RandomID()
		if e != nil {
			return device.RoleResponse{}, e
		}
		record := applicationRecord{SchemaVersion: 2, Plan: p, Active: a.Active, ActivationRevision: revision, SelectedAt: time.Now().UTC(), SessionID: session, Certificate: append([]byte(nil), in.Certificate...)}
		if w.pending != nil {
			if w.pending.Plan != p || w.pending.Active != candidate {
				return device.RoleResponse{}, device.ErrConflict
			}
			record = *w.pending
		}
		intent.Phase = "switch-intent"
		intent.Revision++
		if e = w.saveIntent(intent); e != nil {
			return device.RoleResponse{}, device.ErrUnknown
		}
		if e = writeJSON(filepath.Join(w.dir, "application", "active.json"), record); e != nil {
			return device.RoleResponse{}, device.ErrUnknown
		}
		w.active = &record
		w.pending = nil
		if e = labCheckpoint(req.Context(), w.dir, "application", "active-synced", p); e != nil {
			return device.RoleResponse{}, e
		}
		if e = w.effect(req.Context(), p); e != nil {
			return device.RoleResponse{}, e
		}
		intent.Phase = "activated"
		intent.Revision++
		if e = w.saveIntent(intent); e != nil {
			return device.RoleResponse{}, device.ErrUnknown
		}
	}
	a.Phase = "activated"
	a.ActivationRevision = w.active.ActivationRevision
	a.Evidence.Revision = w.active.ActivationRevision
	a.SessionID = w.active.SessionID
	a.Evidence.Action = "activate"
	return device.RoleResponse{Status: "ok", Application: &a, Evidence: &a.Evidence}, nil
}
func runApplication(dir string) error {
	w, e := openApplication(dir)
	if e != nil {
		return e
	}
	defer w.lock.Close()
	config, e := serviceTLS(dir, "application", w.snapshot, []string{"operational", "observer"})
	if e != nil {
		return e
	}
	return newServer(w.config.ApplicationAddress, http.HandlerFunc(w.request), config).ListenAndServeTLS("", "")
}
func source(snapshot *device.PublicSnapshot, role string) string {
	r, e := snapshot.Role(role)
	if e != nil {
		return ""
	}
	if len(r.LeafPins) > 0 {
		return r.LeafPins[0]
	}
	if len(r.SPKIPins) > 0 {
		return r.SPKIPins[0]
	}
	return ""
}
