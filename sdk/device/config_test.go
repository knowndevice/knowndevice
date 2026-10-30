// SPDX-License-Identifier: Apache-2.0

package device

import (
	"strings"
	"testing"
	"time"
)

func TestStrictInputRejectsAmbiguousAndOversizedData(t *testing.T) {
	for _, input := range []string{`{"deviceId":"gateway","deviceId":"other"}`, `{"deviceId":"gateway","DeviceID":"other"}`, "deviceId: gateway\ndeviceId: other\n", "deviceId: &id gateway\n", "deviceId: gateway\nunknown: value\n", "deviceId: gateway\n---\ndeviceId: other\n", strings.Repeat("x", MaxInput+1)} {
		var cfg Config
		if DecodeStrict(strings.NewReader(input), &cfg) == nil {
			t.Fatalf("ambiguous input accepted: %.80s", input)
		}
	}
}

func TestConfigRequiresTLSAndRecoveryPair(t *testing.T) {
	valid := Config{APIVersion: "knowndevice/v1alpha1", DeviceID: "gateway-1", StateDir: "state", ControlURL: "https://control:9443", ApplicationURL: "https://application:9443", ApplicationID: "worker", MQTTEndpoint: "tls://broker:8883", RootCertificate: "root.crt", ClockTrust: "trusted-system-clock", RequestTimeoutSeconds: 5, PlanTTLSeconds: 600}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){func(c *Config) { c.ControlURL = "http://control" }, func(c *Config) { c.ControlURL = "https://user:password@control" }, func(c *Config) { c.MQTTEndpoint = "tls://broker:8883/?token=secret" }, func(c *Config) { c.RecoveryKey = "recovery.key" }, func(c *Config) { c.RequestTimeoutSeconds = 31 }, func(c *Config) { c.DeviceID = "../escape" }} {
		cfg := valid
		change(&cfg)
		if cfg.Validate() == nil {
			t.Fatalf("invalid config accepted: %+v", cfg)
		}
	}
}

func TestPlanAndProbeBindingsRejectReplays(t *testing.T) {
	now := time.Now().UTC()
	id, _ := RandomID()
	nonce, _ := RandomID()
	p := Plan{APIVersion: "knowndevice/v1alpha1", OperationID: id, DeviceID: "gateway", Mode: "rotate", ExpectedGeneration: 1, TargetGeneration: 2, TargetSlot: "B", ConfigDigest: Hash([]byte("config")), ExpiresAt: now.Add(time.Minute)}
	p.Digest, _ = p.CalculateDigest()
	if err := p.Validate(now); err != nil {
		t.Fatal(err)
	}
	p.TargetGeneration = 3
	if p.Validate(now) == nil {
		t.Fatal("changed generation escaped digest")
	}
	request := Probe{OperationID: id, DeviceID: "gateway", Generation: 2, Endpoint: "tls://broker:8883", Nonce: nonce, Deadline: now.Add(time.Second)}
	wrong := request
	wrong.Generation = 1
	if MatchProbe(request, wrong, now) == nil {
		t.Fatal("wrong generation accepted")
	}
	if MatchProbe(request, request, now.Add(2*time.Second)) == nil {
		t.Fatal("expired probe accepted")
	}
}

func TestP19LegacyRejectsPresentEmptyV2Fields(t *testing.T) {
	for _, suffix := range []string{`,"credentialProfile":null`, `,"deploymentId":""`, `,"limits":null`, `,"trust":null`, `,"profileVersion":0`, `,"digestEncodingVersion":0`} {
		input := `{"apiVersion":"knowndevice/v1alpha1"` + suffix + `}`
		var c Config
		if DecodeStrict(strings.NewReader(input), &c) == nil {
			t.Fatal("v1 config accepted present v2 field")
		}
		var p Plan
		if DecodeStrict(strings.NewReader(input), &p) == nil {
			t.Fatal("v1 plan accepted present v2 field")
		}
	}
	for _, input := range []string{"apiVersion: knowndevice/v1alpha1\ncredentialProfile: null\n", "apiVersion: knowndevice/v1alpha1\nprofileVersion: 0\n", `{"schemaVersion":1,"deviceId":"gateway","operation":{"plan":{"apiVersion":"knowndevice/v1alpha1","profileId":""}}}`, `{"schemaVersion":1,"handle":{"binding":{"deploymentId":""}}}`} {
		if CheckVersionFields([]byte(input)) == nil {
			t.Fatal("empty version-two field accepted in legacy JSON/YAML state")
		}
	}
}
