// SPDX-License-Identifier: Apache-2.0

package process

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/url"
	"sort"
	"time"

	"knowndevice.local/knowndevice/adapters/credentials"
	"knowndevice.local/knowndevice/sdk/credentialprofile"
	"knowndevice.local/knowndevice/sdk/device"
)

func sortedUnique(list []string, max int) bool {
	if len(list) > max {
		return false
	}
	last := ""
	for _, value := range list {
		if value == "" || len(value) > 2048 || value <= last {
			return false
		}
		last = value
	}
	return true
}
func has(list []string, value string) bool {
	i := sort.SearchStrings(list, value)
	return i < len(list) && list[i] == value
}

// ExpectedPermissions describes the selected role backend, rather than an OS sandbox.
func ExpectedPermissions(s *device.PublicSnapshot) (Permissions, error) {
	if s == nil || s.Validate() != nil {
		return Permissions{}, device.ErrUnsupported
	}
	set := map[string]bool{}
	for _, name := range []string{"control", "application", "issuance", "transport"} {
		role, err := s.Role(name)
		if err != nil {
			return Permissions{}, err
		}
		origin, err := url.Parse(role.Endpoint)
		if err != nil || origin.Scheme != "https" || origin.User != nil || origin.Host == "" || origin.RawQuery != "" || origin.Fragment != "" {
			return Permissions{}, device.ErrUnsupported
		}
		set[origin.Scheme+"://"+origin.Host] = true
	}
	p := Permissions{NetworkOrigins: []string{}, FilesystemRead: []string{}, FilesystemWrite: []string{}, SignerBroker: true}
	for origin := range set {
		if origin == "" {
			return Permissions{}, device.ErrUnsupported
		}
		p.NetworkOrigins = append(p.NetworkOrigins, origin)
	}
	sort.Strings(p.NetworkOrigins)
	return p, nil
}
func samePermissions(a, b Permissions) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func capabilities(s *device.PublicSnapshot, a device.Adapters) ([]string, error) {
	if a.Validate() != nil {
		return nil, device.ErrUnsupported
	}
	set := map[string]bool{"clock.assess": true}
	for method := range domainMethods {
		if method == "authority.import" {
			if _, ok := a.Authority.(device.Importer); !ok {
				continue
			}
		}
		set[method] = true
	}
	for _, adapter := range s.Composition.Adapters {
		required, err := device.RequiredCapability(adapter.Role)
		if err != nil {
			return nil, err
		}
		set[required] = true
	}
	list := []string{}
	for value := range set {
		list = append(list, value)
	}
	sort.Strings(list)
	return list, nil
}
func defaultRequired(s *device.PublicSnapshot) []string {
	list := []string{}
	for _, adapter := range s.Composition.Adapters {
		required, err := device.RequiredCapability(adapter.Role)
		if err == nil {
			list = append(list, required)
		}
	}
	sort.Strings(list)
	return list
}

func processSnapshot(s *device.PublicSnapshot, pin string) (*device.PublicSnapshot, error) {
	if s == nil || len(s.Bytes()) > MaxSnapshotBytes {
		return nil, device.ErrUnsupported
	}
	copy, err := device.DecodeSnapshot(s.Bytes())
	if err != nil {
		return nil, device.ErrUnsupported
	}
	if copy.Composition.ID != "local-http-process-lab" || copy.Composition.Version != 1 || !sha256ID.MatchString(pin) || copy.Composition.ProcessArtifactDigest != pin {
		return nil, device.ErrUnsupported
	}
	return copy, nil
}

func validateScope(s *device.PublicSnapshot, p device.Plan, scope Scope) error {
	now := time.Now().UTC()
	if s.ValidatePlan(p) != nil || !scope.equal(scopeFor(p, scope.Deadline)) {
		return device.ErrConflict
	}
	if p.Validate(now) != nil {
		if !now.Before(p.ExpiresAt) {
			return device.ErrPlanExpired
		}
		return device.ErrConflict
	}
	if scope.Deadline.IsZero() || scope.Deadline.After(p.ExpiresAt) || scope.Deadline.After(now.Add(time.Duration(s.RequestTimeoutSeconds)*time.Second)) {
		return device.ErrDenied
	}
	if !now.Before(scope.Deadline) {
		return device.ErrUnknown
	}
	return nil
}

func publicKey(spki []byte) (*ecdsa.PublicKey, error) {
	if len(spki) == 0 || len(spki) > 1024 {
		return nil, device.ErrDenied
	}
	key, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, device.ErrDenied
	}
	k, ok := key.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() || !k.Curve.IsOnCurve(k.X, k.Y) {
		return nil, device.ErrUnsupported
	}
	return k, nil
}

func validateCredential(s *device.PublicSnapshot, k device.Credential, historical bool) error {
	if credentials.ValidateCredential(k) != nil || len(k.CSR) > credentialprofile.MaxCSRSize {
		return device.ErrDenied
	}
	now := time.Now().UTC()
	early, late := now.Add(-time.Second), now.Add(time.Second)
	if k.Recovery {
		if k.DeviceID != s.DeviceID || device.Hash(k.TLS.Certificate[0]) != s.RecoveryLeafPin {
			return device.ErrDenied
		}
		leaf, _ := x509.ParseCertificate(k.TLS.Certificate[0])
		if device.Hash(leaf.RawSubjectPublicKeyInfo) != s.RecoverySPKIPin {
			return device.ErrDenied
		}
		roots, err := s.Roots("recovery")
		if err != nil {
			return err
		}
		if credentials.ValidateRecovery(k, roots, early) != nil || credentials.ValidateRecovery(k, roots, late) != nil {
			return device.ErrDenied
		}
		role, err := s.Role("recovery")
		if err != nil {
			return err
		}
		intermediates := x509.NewCertPool()
		for _, der := range k.TLS.Certificate[1:] {
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				return device.ErrDenied
			}
			intermediates.AddCert(certificate)
		}
		for _, at := range []time.Time{early, late} {
			paths, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
			if err != nil || role.ValidateVerifiedInterval(paths, early, late) != nil {
				return device.ErrDenied
			}
		}
		return nil
	}
	if s.ValidateBinding(k.Handle.Binding) != nil {
		return device.ErrConflict
	}
	chain, err := credentials.PublicChain(k)
	if err != nil {
		return device.ErrDenied
	}
	certs, err := credentialprofile.ParseChain(chain)
	if err != nil {
		return device.ErrDenied
	}
	if historical {
		early, late = certs[0].NotBefore, certs[0].NotBefore
	}
	v, err := s.Validation(early, late, false, historical)
	if err != nil {
		return err
	}
	if s.Profile.ValidateChain(chain, k.CSR, k.Handle.PublicKeyDigest, k.Handle.Binding.DeviceID, k.Handle.Binding.Generation, v) != nil {
		return device.ErrDenied
	}
	return nil
}

func validateCaller(s *device.PublicSnapshot, p device.Plan, k *device.Credential) error {
	if k == nil {
		return device.ErrDenied
	}
	if (p.Mode == "enroll" || p.Mode == "recover") != k.Recovery {
		return device.ErrDenied
	}
	if !k.Recovery && k.Handle.Binding.Generation != p.ExpectedGeneration {
		return device.ErrConflict
	}
	return validateCredential(s, *k, false)
}
func validateTarget(s *device.PublicSnapshot, p device.Plan, k device.Credential) error {
	if k.Recovery || k.Handle.Binding != p.Binding() {
		return device.ErrConflict
	}
	return validateCredential(s, k, false)
}
func validatePair(s *device.PublicSnapshot, p device.Plan, previous, target device.Credential) error {
	if err := validateTarget(s, p, target); err != nil {
		return err
	}
	if previous.Recovery || previous.Handle.Binding.Generation != p.ExpectedGeneration || previous.Handle.PublicKeyDigest == target.Handle.PublicKeyDigest {
		return device.ErrConflict
	}
	return validateCredential(s, previous, true)
}

func wirePublic(k device.Credential, ref string) (WireCredential, crypto.Signer, error) {
	if credentials.ValidateCredential(k) != nil {
		return WireCredential{}, nil, device.ErrDenied
	}
	signer, ok := k.TLS.PrivateKey.(crypto.Signer)
	if !ok {
		return WireCredential{}, nil, device.ErrDenied
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return WireCredential{}, nil, device.ErrDenied
	}
	if _, err = publicKey(spki); err != nil {
		return WireCredential{}, nil, err
	}
	id := k.DeviceID
	if id == "" {
		id = k.Handle.Binding.DeviceID
	}
	w := WireCredential{k.Handle, k.TLS.Certificate, k.CSR, k.Recovery, id, ref, spki}
	data, _ := json.Marshal(w)
	if validateDefinition("wireCredential", data) != nil {
		return WireCredential{}, nil, device.ErrDenied
	}
	return w, signer, nil
}
func credentialFromWire(w WireCredential, signer crypto.Signer) (device.Credential, error) {
	if (w.SignerRef != "" && !signerID.MatchString(w.SignerRef)) || len(w.CSR) > credentialprofile.MaxCSRSize || len(w.Chain) == 0 || len(w.Chain) > 8 {
		return device.Credential{}, device.ErrDenied
	}
	key, err := publicKey(w.PublicSPKI)
	if err != nil {
		return device.Credential{}, err
	}
	actual, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(actual, w.PublicSPKI) || key == nil {
		return device.Credential{}, device.ErrDenied
	}
	k := device.Credential{Handle: w.Handle, TLS: tls.Certificate{Certificate: w.Chain, PrivateKey: signer}, CSR: w.CSR, Recovery: w.Recovery, DeviceID: w.DeviceID}
	if credentials.ValidateCredential(k) != nil {
		return device.Credential{}, device.ErrDenied
	}
	return k, nil
}

func binding(k device.Credential) (device.CredentialBinding, error) {
	b := k.Handle.Binding
	csr, err := credentialprofile.Resolve(b.ProfileID, b.ProfileVersion, b.ProfileDigest)
	if err != nil {
		return device.CredentialBinding{}, device.ErrDenied
	}
	r, err := csr.ValidateCSR(k.CSR, b.DeviceID, b.Generation)
	if err != nil {
		return device.CredentialBinding{}, device.ErrDenied
	}
	return device.CredentialBinding{DeploymentID: b.DeploymentID, DeviceID: b.DeviceID, OperationID: b.OperationID, PlanDigest: b.PlanDigest, ConfigDigest: b.ConfigDigest, SnapshotDigest: b.SnapshotDigest, ProfileID: b.ProfileID, ProfileVersion: b.ProfileVersion, ProfileDigest: b.ProfileDigest, Generation: b.Generation, PublicKeyDigest: k.Handle.PublicKeyDigest, CertificateFingerprint: device.Hash(k.TLS.Certificate[0]), CSRDigest: device.Hash(r.Raw)}, nil
}

func evidenceOK(s *device.PublicSnapshot, p device.Plan, e device.Evidence, role, sourceRole string) bool {
	r, err := s.Role(sourceRole)
	if err != nil {
		return false
	}
	data, _ := json.Marshal(e)
	if validateDefinition("evidence", data) != nil {
		return false
	}
	now := time.Now().UTC()
	return e.Plan == p && e.Role == role && e.Revision > 0 && has(r.LeafPins, e.Source) && !e.Deadline.After(p.ExpiresAt) && !e.ObservedAt.After(now.Add(time.Second)) && now.Sub(e.ObservedAt) <= 5*time.Second && now.Add(time.Second).Before(e.Deadline)
}

func validateActivation(s *device.PublicSnapshot, p device.Plan, k device.Credential, a device.Activation) error {
	data, _ := json.Marshal(a)
	if validateDefinition("activation", data) != nil {
		return device.ErrUnknown
	}
	expected, err := binding(k)
	if err != nil {
		return err
	}
	e := a.Evidence
	if e == nil || a.OperationID != p.OperationID || a.PlanDigest != p.Digest || a.DeviceID != p.DeviceID || a.Generation != p.TargetGeneration || a.CertificateFingerprint != expected.CertificateFingerprint || a.ApplicationID != s.Composition.ApplicationID || a.SessionID == "" || e.Phase != "activated" || e.ActivationRevision == 0 || e.Active != expected || e.Evidence.Subject != expected || e.ApplicationID != a.ApplicationID || e.SessionID != a.SessionID || e.ConnectionID == "" || e.InstanceID == "" || e.Challenge != a.Probe || !evidenceOK(s, p, e.Evidence, "application", "application") {
		return device.ErrUnknown
	}
	if e.Evidence.Action != "observe" || e.Evidence.Status != "completed" || e.Evidence.Revision != e.ActivationRevision || len(e.AcceptedScope) != 1 || e.AcceptedScope[0] != "fresh-challenge" || !e.Evidence.Deadline.Equal(a.Probe.Deadline) || !e.Evidence.ObservedAt.Before(a.Probe.Deadline) || a.Probe.Deadline.Sub(e.Evidence.ObservedAt) > time.Duration(s.Limits.ChallengeSeconds)*time.Second {
		return device.ErrUnknown
	}
	r, _ := s.Role("transport")
	if a.Probe.OperationID != p.OperationID || a.Probe.DeviceID != p.DeviceID || a.Probe.Generation != p.TargetGeneration || a.Probe.Endpoint != r.Endpoint || !signerID.MatchString(a.Probe.Nonce) || a.Probe.Deadline.After(p.ExpiresAt) || !time.Now().Add(time.Second).Before(a.Probe.Deadline) {
		return device.ErrUnknown
	}
	chain, err := credentials.PublicChain(k)
	if err != nil {
		return err
	}
	now := time.Now()
	v, err := s.Validation(now.Add(-time.Second), now.Add(time.Second), true, false)
	if err != nil {
		return err
	}
	if s.Profile.ValidateChain(chain, k.CSR, k.Handle.PublicKeyDigest, p.DeviceID, p.TargetGeneration, v) != nil {
		return device.ErrUnknown
	}
	return nil
}

func validateRetirement(s *device.PublicSnapshot, p device.Plan, old, target device.Credential, r device.Retirement) error {
	data, _ := json.Marshal(r)
	if validateDefinition("retirement", data) != nil {
		return device.ErrUnknown
	}
	previous, e1 := binding(old)
	current, e2 := binding(target)
	w := r.Evidence
	if e1 != nil || e2 != nil || w == nil || r.OperationID != p.OperationID || r.PlanDigest != p.Digest || r.Generation != p.ExpectedGeneration || !r.PolicyDurable || !r.SessionsTerminated || !r.ApplicationAccessDenied || r.TLSObservation != "accepted" || w.Previous != previous || w.Target != current || w.Scope != s.Composition.WithdrawalScope || w.PolicyRevision == 0 || !w.SessionsTerminated || w.Denial.Kind != "denied" || w.Denial.Evidence.Subject != previous || !evidenceOK(s, p, w.Evidence, "withdrawal", "control") || !evidenceOK(s, p, w.Denial.Evidence, "transport", "transport") {
		return device.ErrUnknown
	}
	if w.Evidence.Subject != previous || w.Evidence.Status != "ok" || w.Evidence.Action != "withdraw" || w.Denial.Evidence.Action != "challenge" || w.Evidence.Revision < w.PolicyRevision || w.Current.Evidence.ObservedAt.Before(w.Denial.Evidence.ObservedAt) || w.Current.Challenge.Nonce == w.Denial.Challenge.Nonce || w.Denial.ConnectionID == "" || w.Denial.Evidence.Status != "denied" || !w.Evidence.Deadline.Equal(p.ExpiresAt) || !w.Denial.Evidence.Deadline.Equal(w.Denial.Challenge.Deadline) || !w.Denial.Evidence.ObservedAt.Before(w.Denial.Challenge.Deadline) || w.Denial.Challenge.Deadline.Sub(w.Denial.Evidence.ObservedAt) > time.Duration(s.Limits.ChallengeSeconds)*time.Second {
		return device.ErrUnknown
	}
	d := w.Denial.Challenge
	role, _ := s.Role("transport")
	if d.OperationID != p.OperationID || d.DeviceID != p.DeviceID || d.Generation != p.ExpectedGeneration || d.Endpoint != role.Endpoint || !signerID.MatchString(d.Nonce) || d.Deadline.After(p.ExpiresAt) || !time.Now().Add(time.Second).Before(d.Deadline) {
		return device.ErrUnknown
	}
	a := w.Current
	activation := device.Activation{OperationID: p.OperationID, PlanDigest: p.Digest, DeviceID: p.DeviceID, ApplicationID: a.ApplicationID, Generation: a.Active.Generation, CertificateFingerprint: a.Active.CertificateFingerprint, SessionID: a.SessionID, Probe: a.Challenge, Evidence: &a}
	return validateActivation(s, p, target, activation)
}

func validateCertificate(s *device.PublicSnapshot, p device.Plan, csr, chain []byte) error {
	r, err := s.Profile.ValidateCSR(csr, p.DeviceID, p.TargetGeneration)
	if err != nil {
		return device.ErrDenied
	}
	now := time.Now()
	v, err := s.Validation(now.Add(-time.Second), now.Add(time.Second), false, false)
	if err != nil {
		return err
	}
	if s.Profile.ValidateChain(chain, csr, device.Hash(r.RawSubjectPublicKeyInfo), p.DeviceID, p.TargetGeneration, v) != nil {
		return device.ErrUnknown
	}
	return nil
}

func hashAlgorithm(name string, size int) (crypto.Hash, error) {
	var h crypto.Hash
	switch name {
	case "SHA256":
		h = crypto.SHA256
	case "SHA384":
		h = crypto.SHA384
	case "SHA512":
		h = crypto.SHA512
	default:
		return 0, device.ErrUnsupported
	}
	if size != h.Size() {
		return 0, device.ErrDenied
	}
	return h, nil
}
