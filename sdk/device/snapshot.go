// SPDX-License-Identifier: Apache-2.0

package device

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"knowndevice.local/knowndevice/sdk/credentialprofile"
)

const V2 = "knowndevice/v1alpha2"

type Limits struct {
	MinLifetimeSeconds          int `json:"minLifetimeSeconds"`
	MaxLifetimeSeconds          int `json:"maxLifetimeSeconds"`
	MaxBackdateSeconds          int `json:"maxBackdateSeconds"`
	MinimumRemainingSeconds     int `json:"minimumRemainingSeconds"`
	MaximumUncertaintyMillis    int `json:"maximumUncertaintyMillis"`
	MaximumAssessmentAgeSeconds int `json:"maximumAssessmentAgeSeconds"`
	DriftPPM                    int `json:"driftPPM"`
	ChallengeSeconds            int `json:"challengeSeconds"`
}

func DefaultLimits() Limits { return Limits{300, 1260, 60, 120, 2000, 10, 50, 30} }
func (l Limits) Validate() error {
	if l.MinLifetimeSeconds < 300 || l.MaxLifetimeSeconds < l.MinLifetimeSeconds || l.MaxLifetimeSeconds > 1260 || l.MaxBackdateSeconds < 1 || l.MaxBackdateSeconds > 60 || l.MinimumRemainingSeconds < 120 || l.MinimumRemainingSeconds > l.MinLifetimeSeconds || l.MaximumUncertaintyMillis < 1000 || l.MaximumUncertaintyMillis > 2000 || l.MaximumAssessmentAgeSeconds < 1 || l.MaximumAssessmentAgeSeconds > 10 || l.DriftPPM < 0 || l.DriftPPM > 50 || l.ChallengeSeconds < 1 || l.ChallengeSeconds > 60 {
		return fmt.Errorf("unsupported issuance or time limits")
	}
	minimum := 1000 + (l.MaximumAssessmentAgeSeconds*l.DriftPPM+999)/1000
	if l.MaximumUncertaintyMillis < minimum {
		return fmt.Errorf("time limit cannot contain the selected clock's uncertainty and drift")
	}
	return nil
}

type AdapterSpec struct {
	Role           string   `json:"role"`
	ID             string   `json:"id"`
	Version        string   `json:"version"`
	ArtifactDigest string   `json:"artifactDigest"`
	Capabilities   []string `json:"capabilities"`
}
type Composition struct {
	ID                       string        `json:"id"`
	Version                  int           `json:"version"`
	AuthorityTemplateDigest  string        `json:"authorityTemplateDigest"`
	AuthorityLifetimeSeconds int           `json:"authorityLifetimeSeconds,omitempty"`
	ApplicationID            string        `json:"applicationId"`
	SessionPolicy            string        `json:"sessionPolicy"`
	ObservationRoute         string        `json:"observationRoute"`
	WithdrawalScope          string        `json:"withdrawalScope"`
	Adapters                 []AdapterSpec `json:"adapters"`
	ProcessArtifactDigest    string        `json:"processArtifactDigest,omitempty"`
}

func (c Composition) Digest() string { b, _ := json.Marshal(c); return Hash(b) }

// AuthorityLifetime preserves composition 1's fixed request and composition 2's explicit policy.
func (c Composition) AuthorityLifetime() time.Duration {
	if c.ID == "local-http-lab" && c.Version == 1 {
		return 1200 * time.Second
	}
	return time.Duration(c.AuthorityLifetimeSeconds) * time.Second
}

var requiredCapabilities = map[string]string{"entitlement": "current-entitlement", "authority": "bounded-unknown-issuance", "platform": "exact-peer-binding", "transport": "explicit-access-observation", "application": "durable-activation-and-fresh-observation", "clock": "bounded-interval", "withdrawal": "durable-deny-and-session-inventory"}

func (c Composition) Validate() error {
	if c.ID == "local-http-lab" {
		if (c.Version != 1 && c.Version != 2) || c.ProcessArtifactDigest != "" || c.Version == 1 && c.AuthorityLifetimeSeconds != 0 || c.Version == 2 && (c.AuthorityLifetimeSeconds < 300 || c.AuthorityLifetimeSeconds > 1200) {
			return ErrUnsupported
		}
	} else if c.ID != "local-http-process-lab" || c.Version != 1 || !digest.MatchString(c.ProcessArtifactDigest) || c.AuthorityLifetimeSeconds < 300 || c.AuthorityLifetimeSeconds > 1200 {
		return ErrUnsupported
	}
	if !digest.MatchString(c.AuthorityTemplateDigest) || !ValidDeviceID(c.ApplicationID) || c.SessionPolicy != "new-connection-no-state-transfer" || c.ObservationRoute != "authenticated-application-callback" || c.WithdrawalScope != "whole-service-lab" || len(c.Adapters) != 7 {
		return ErrUnsupported
	}
	seen := map[string]bool{}
	for _, a := range c.Adapters {
		capability, ok := requiredCapabilities[a.Role]
		if !ok || seen[a.Role] || a.ID != "local-http-lab-"+a.Role || a.Version != "1" || !digest.MatchString(a.ArtifactDigest) || len(a.Capabilities) > 16 {
			return ErrUnsupported
		}
		seen[a.Role] = true
		found := false
		last := ""
		for _, cap := range a.Capabilities {
			if cap <= last {
				return ErrUnsupported
			}
			last = cap
			if cap == capability {
				found = true
			}
		}
		if !found {
			return ErrUnsupported
		}
	}
	return nil
}

type RoleConfig struct {
	Role             string   `json:"role"`
	RootCertificates []string `json:"rootCertificates"`
	Endpoint         string   `json:"endpoint"`
	PeerName         string   `json:"peerName"`
	LeafPins         []string `json:"leafPins"`
	SPKIPins         []string `json:"spkiPins"`
	AllowedIssuers   []string `json:"allowedIssuers"`
	CallerLeafPins   []string `json:"callerLeafPins,omitempty"`
	CallerSPKIPins   []string `json:"callerSPKIPins,omitempty"`
}
type TrustConfig struct {
	Roles []RoleConfig `json:"roles"`
}
type RoleSnapshot struct {
	Role           string   `json:"role"`
	Endpoint       string   `json:"endpoint"`
	PeerName       string   `json:"peerName"`
	Anchors        [][]byte `json:"anchors"`
	LeafPins       []string `json:"leafPins"`
	SPKIPins       []string `json:"spkiPins"`
	AllowedIssuers []string `json:"allowedIssuers"`
	CallerLeafPins []string `json:"callerLeafPins,omitempty"`
	CallerSPKIPins []string `json:"callerSPKIPins,omitempty"`
}

// ValidateVerifiedPaths checks the role's issuer and validity after X.509 usage validation.
func (r RoleSnapshot) ValidateVerifiedPaths(paths [][]*x509.Certificate, at time.Time) error {
	return r.ValidateVerifiedInterval(paths, at, at)
}

// ValidateVerifiedInterval requires one allowed X.509-verified path to cover the
// entire closed interval. Independently valid endpoint paths can conceal a gap.
// The caller must first verify signatures, trust, identity and usage on these paths.
func (r RoleSnapshot) ValidateVerifiedInterval(paths [][]*x509.Certificate, earliest, latest time.Time) error {
	if earliest.IsZero() || latest.Before(earliest) {
		return ErrDenied
	}
	for _, path := range paths {
		if len(path) == 0 {
			continue
		}
		allowed := len(r.AllowedIssuers) == 0
		if len(path) > 1 && path[1] != nil {
			for _, issuer := range r.AllowedIssuers {
				if issuer == Hash(path[1].Raw) {
					allowed = true
				}
			}
		}
		for _, cert := range path {
			if cert == nil || earliest.Before(cert.NotBefore) || !latest.Before(cert.NotAfter) {
				allowed = false
			}
		}
		if allowed {
			return nil
		}
	}
	return ErrDenied
}

func (r RoleSnapshot) Digest() string { b, _ := json.Marshal(r); return Hash(b) }

type PublicSnapshot struct {
	APIVersion            string                   `json:"apiVersion"`
	EncodingVersion       int                      `json:"encodingVersion"`
	DeploymentID          string                   `json:"deploymentId"`
	DeviceID              string                   `json:"deviceId"`
	Profile               credentialprofile.Policy `json:"profile"`
	Composition           Composition              `json:"composition"`
	Trust                 []RoleSnapshot           `json:"trust"`
	RecoveryIdentity      string                   `json:"recoveryIdentity"`
	RecoveryLeafPin       string                   `json:"recoveryLeafPin"`
	RecoverySPKIPin       string                   `json:"recoverySPKIPin"`
	Limits                Limits                   `json:"limits"`
	RequestTimeoutSeconds int                      `json:"requestTimeoutSeconds"`
	PlanTTLSeconds        int                      `json:"planTTLSeconds"`
	ClockTrust            string                   `json:"clockTrust"`
}

func (s PublicSnapshot) Bytes() []byte  { b, _ := json.Marshal(s); return b }
func (s PublicSnapshot) Digest() string { return Hash(s.Bytes()) }
func (s PublicSnapshot) Role(role string) (RoleSnapshot, error) {
	for _, r := range s.Trust {
		if r.Role == role {
			b, _ := json.Marshal(r)
			var copy RoleSnapshot
			_ = json.Unmarshal(b, &copy)
			return copy, nil
		}
	}
	return RoleSnapshot{}, ErrUnsupported
}
func (s PublicSnapshot) Roots(role string) (*x509.CertPool, error) {
	r, e := s.Role(role)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	for _, der := range r.Anchors {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, ErrDenied
		}
		pool.AddCert(c)
	}
	return pool, nil
}
func (s PublicSnapshot) Validation(earliest, latest time.Time, activation, historical bool) (credentialprofile.Validation, error) {
	roots, e := s.Roots("operational")
	if e != nil {
		return credentialprofile.Validation{}, e
	}
	role, e := s.Role("operational")
	if e != nil {
		return credentialprofile.Validation{}, e
	}
	v := credentialprofile.Validation{Roots: roots, Earliest: earliest, Latest: latest, AllowedIssuers: role.AllowedIssuers, Historical: historical}
	if !historical {
		v.MinLifetime = time.Duration(s.Limits.MinLifetimeSeconds) * time.Second
		v.MaxLifetime = time.Duration(s.Limits.MaxLifetimeSeconds) * time.Second
		if activation {
			v.MinimumRemaining = time.Duration(s.Limits.MinimumRemainingSeconds) * time.Second
		}
	}
	return v, nil
}
func validPins(pins []string) bool {
	last := ""
	for _, p := range pins {
		if !digest.MatchString(p) || p <= last {
			return false
		}
		last = p
	}
	return len(pins) <= 8
}
func validateAnchor(der []byte) error {
	c, e := x509.ParseCertificate(der)
	if e != nil || !c.IsCA || c.KeyUsage&x509.KeyUsageCertSign == 0 || c.CheckSignatureFrom(c) != nil || len(c.UnhandledCriticalExtensions) != 0 || c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return fmt.Errorf("unsupported trust anchor")
	}
	k, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() {
		return fmt.Errorf("unsupported anchor key")
	}
	return nil
}
func (s PublicSnapshot) Validate() error {
	if s.APIVersion != V2 || s.EncodingVersion != 2 || !ValidDeviceID(s.DeploymentID) || !ValidDeviceID(s.DeviceID) || s.ClockTrust != "trusted-system-clock" || s.RequestTimeoutSeconds < 1 || s.RequestTimeoutSeconds > 60 || s.PlanTTLSeconds < 60 || s.PlanTTLSeconds > 600 || s.Limits.Validate() != nil || s.Composition.Validate() != nil || s.RecoveryIdentity != RecoverySubject(s.DeviceID) || !digest.MatchString(s.RecoveryLeafPin) || !digest.MatchString(s.RecoverySPKIPin) {
		return fmt.Errorf("invalid public snapshot")
	}
	if lifetime := s.Composition.AuthorityLifetime(); lifetime < time.Duration(s.Limits.MinLifetimeSeconds)*time.Second || lifetime > time.Duration(s.Limits.MaxLifetimeSeconds)*time.Second {
		return ErrUnsupported
	}
	if _, e := credentialprofile.Resolve(s.Profile.ID, s.Profile.Version, s.Profile.PolicyDigest); e != nil {
		return e
	}
	required := map[string]bool{"control": false, "application": false, "issuance": false, "operational": false, "recovery": false, "transport": false, "observer": false, "authority-transport": false}
	lastRole := ""
	domains := map[string]string{}
	for _, r := range s.Trust {
		done, ok := required[r.Role]
		if !ok || done || r.Role <= lastRole || len(r.Anchors) == 0 || len(r.Anchors) > 8 || !validPins(r.LeafPins) || !validPins(r.SPKIPins) || !validPins(r.AllowedIssuers) || !validPins(r.CallerLeafPins) || !validPins(r.CallerSPKIPins) {
			return fmt.Errorf("missing, duplicate or unsupported role trust")
		}
		lastRole = r.Role
		required[r.Role] = true
		last := ""
		for _, der := range r.Anchors {
			h := Hash(der)
			if h <= last || validateAnchor(der) != nil {
				return fmt.Errorf("invalid or duplicate trust anchor")
			}
			last = h
			if r.Role != "issuance" && r.Role != "observer" && r.Role != "authority-transport" {
				if prior, ok := domains[h]; ok && prior != r.Role {
					return fmt.Errorf("service, recovery and operational domains must be distinct")
				}
				domains[h] = r.Role
			}
		}
		if r.Role == "issuance" && len(r.CallerLeafPins) == 0 && len(r.CallerSPKIPins) == 0 {
			return fmt.Errorf("issuance caller pin required")
		}
		if r.Role == "operational" || r.Role == "recovery" {
			if r.Endpoint != "" || r.PeerName != "" {
				return fmt.Errorf("issuer trust cannot supply a service endpoint")
			}
			if r.Role == "operational" && len(r.AllowedIssuers) == 0 {
				return fmt.Errorf("operational issuer policy required")
			}
		} else if r.Role == "observer" {
			if r.Endpoint != "" || r.PeerName == "" || len(r.LeafPins) == 0 {
				return fmt.Errorf("observer requires exact caller identity/pins without a service endpoint")
			}
		} else {
			u, e := url.Parse(r.Endpoint)
			if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || r.PeerName != u.Hostname() {
				return fmt.Errorf("role endpoint/peer identity mismatch")
			}
			if r.Role != "authority-transport" && len(r.LeafPins) == 0 {
				return fmt.Errorf("exact service pin required")
			}
		}
	}
	for _, present := range required {
		if !present {
			return fmt.Errorf("missing role; root fallback forbidden")
		}
	}
	return nil
}
func DecodeSnapshot(data []byte) (*PublicSnapshot, error) {
	if len(data) == 0 || len(data) > MaxInput {
		return nil, ErrDenied
	}
	var s PublicSnapshot
	if e := DecodeStrict(bytes.NewReader(data), &s); e != nil {
		return nil, e
	}
	if e := s.Validate(); e != nil {
		return nil, e
	}
	if !bytes.Equal(s.Bytes(), data) {
		return nil, fmt.Errorf("noncanonical public snapshot")
	}
	return &s, nil
}
func (s PublicSnapshot) ValidateBinding(b Binding) error {
	if s.Validate() != nil || b.DeploymentID != s.DeploymentID || b.DeviceID != s.DeviceID || b.ProfileID != s.Profile.ID || b.ProfileVersion != s.Profile.Version || b.ProfileDigest != s.Profile.PolicyDigest || b.SnapshotDigest != s.Digest() || b.ConfigDigest != s.Digest() || !digest.MatchString(b.PlanDigest) {
		return ErrConflict
	}
	return nil
}
func (s PublicSnapshot) ValidatePlan(p Plan) error {
	if p.APIVersion != V2 || s.ValidateBinding(p.Binding()) != nil || p.CompositionDigest != s.Composition.Digest() {
		return ErrConflict
	}
	for _, v := range []struct{ role, want string }{{"control", p.ControlTrustDigest}, {"application", p.ApplicationTrustDigest}, {"issuance", p.IssuanceTrustDigest}, {"recovery", p.RecoveryTrustDigest}, {"transport", p.TransportTrustDigest}} {
		r, e := s.Role(v.role)
		if e != nil || r.Digest() != v.want {
			return ErrConflict
		}
	}
	return nil
}
func readBounded(path string, limit int) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, fmt.Errorf("read public trust material")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if e != nil || len(b) > limit {
		return nil, fmt.Errorf("public trust material exceeds limit")
	}
	return b, nil
}
func (c Config) ResolveSnapshot() (*PublicSnapshot, error) {
	if c.APIVersion != V2 || c.CredentialProfile == nil || c.Composition == nil || c.Trust == nil || c.Limits == nil {
		return nil, ErrUnsupported
	}
	s := &PublicSnapshot{APIVersion: V2, EncodingVersion: 2, DeploymentID: c.DeploymentID, DeviceID: c.DeviceID, Profile: *c.CredentialProfile, Composition: *c.Composition, Limits: *c.Limits, RequestTimeoutSeconds: c.RequestTimeoutSeconds, PlanTTLSeconds: c.PlanTTLSeconds, ClockTrust: c.ClockTrust, RecoveryIdentity: RecoverySubject(c.DeviceID)}
	s.Composition.Adapters = append([]AdapterSpec(nil), s.Composition.Adapters...)
	sort.Slice(s.Composition.Adapters, func(i, j int) bool { return s.Composition.Adapters[i].Role < s.Composition.Adapters[j].Role })
	for _, cfg := range c.Trust.Roles {
		r := RoleSnapshot{Role: cfg.Role, Endpoint: strings.TrimSuffix(cfg.Endpoint, "/"), PeerName: cfg.PeerName, LeafPins: append([]string{}, cfg.LeafPins...), SPKIPins: append([]string{}, cfg.SPKIPins...), AllowedIssuers: append([]string{}, cfg.AllowedIssuers...), CallerLeafPins: append([]string{}, cfg.CallerLeafPins...), CallerSPKIPins: append([]string{}, cfg.CallerSPKIPins...)}
		for _, path := range cfg.RootCertificates {
			b, e := readBounded(path, credentialprofile.MaxChainSize)
			if e != nil {
				return nil, e
			}
			certs, e := credentialprofile.ParseChain(b)
			if e != nil {
				return nil, e
			}
			for _, cert := range certs {
				r.Anchors = append(r.Anchors, cert.Raw)
			}
		}
		sort.Slice(r.Anchors, func(i, j int) bool { return Hash(r.Anchors[i]) < Hash(r.Anchors[j]) })
		sort.Strings(r.LeafPins)
		sort.Strings(r.SPKIPins)
		sort.Strings(r.AllowedIssuers)
		sort.Strings(r.CallerLeafPins)
		sort.Strings(r.CallerSPKIPins)
		s.Trust = append(s.Trust, r)
	}
	sort.Slice(s.Trust, func(i, j int) bool { return s.Trust[i].Role < s.Trust[j].Role })
	recovery, e := readBounded(c.RecoveryCertificate, credentialprofile.MaxChainSize)
	if e != nil {
		return nil, e
	}
	chain, e := credentialprofile.ParseChain(recovery)
	if e != nil {
		return nil, e
	}
	s.RecoveryLeafPin = Hash(chain[0].Raw)
	s.RecoverySPKIPin = Hash(chain[0].RawSubjectPublicKeyInfo)
	if s.Validate() != nil {
		return nil, fmt.Errorf("invalid resolved profile/trust composition")
	}
	if credentialprofile.ValidateReferenceIdentity(chain[0], s.RecoveryIdentity) != nil {
		return nil, fmt.Errorf("recovery identity policy mismatch")
	}
	recoveryRoots, e := s.Roots("recovery")
	if e != nil {
		return nil, e
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	now := time.Now()
	early, late := now.Add(-time.Second), now.Add(time.Second)
	for _, at := range []time.Time{early, late} {
		recoveryRole, _ := s.Role("recovery")
		paths, e := chain[0].Verify(x509.VerifyOptions{Roots: recoveryRoots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		if e != nil || recoveryRole.ValidateVerifiedInterval(paths, early, late) != nil {
			return nil, fmt.Errorf("recovery trust or interval validity mismatch")
		}
	}

	for _, binding := range []struct{ role, endpoint string }{{"control", c.ControlURL}, {"application", c.ApplicationURL}, {"transport", c.TransportEndpoint}} {
		r, e := s.Role(binding.role)
		if e != nil || r.Endpoint != strings.TrimSuffix(binding.endpoint, "/") {
			return nil, fmt.Errorf("configured endpoint differs from role snapshot")
		}
	}
	return DecodeSnapshot(s.Bytes())
}
