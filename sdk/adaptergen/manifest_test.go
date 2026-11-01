// SPDX-License-Identifier: Apache-2.0

package adaptergen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/knowndevice/knowndevice/adapters/process"
	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
	"github.com/knowndevice/knowndevice/sdk/device"
)

func manifestSnapshot(t *testing.T, profileID string) *device.PublicSnapshot {
	t.Helper()
	profile, err := credentialprofile.Find(profileID, 1)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &device.PublicSnapshot{
		APIVersion: device.V2, EncodingVersion: 2, DeploymentID: "manifest-test", DeviceID: "gateway", Profile: profile,
		Composition:      device.Composition{ID: "local-http-process-lab", Version: 1, ProcessArtifactDigest: device.Hash([]byte("adapter")), AuthorityTemplateDigest: device.Hash([]byte("template")), AuthorityLifetimeSeconds: 1200, ApplicationID: "worker", SessionPolicy: "new-connection-no-state-transfer", ObservationRoute: "authenticated-application-callback", WithdrawalScope: "whole-service-lab"},
		RecoveryIdentity: device.RecoverySubject("gateway"), RecoveryLeafPin: device.Hash([]byte("recovery-leaf")), RecoverySPKIPin: device.Hash([]byte("recovery-spki")),
		Limits: device.DefaultLimits(), RequestTimeoutSeconds: 5, PlanTTLSeconds: 600, ClockTrust: "trusted-system-clock",
	}
	for _, role := range []string{"application", "authority", "clock", "entitlement", "platform", "transport", "withdrawal"} {
		capability, err := device.RequiredCapability(role)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Composition.Adapters = append(snapshot.Composition.Adapters, device.AdapterSpec{Role: role, ID: "local-http-lab-" + role, Version: "1", ArtifactDigest: device.Hash([]byte(role)), Capabilities: []string{capability}})
	}
	for _, role := range []string{"application", "authority-transport", "control", "issuance", "observer", "operational", "recovery", "transport"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: role}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign, SignatureAlgorithm: x509.ECDSAWithSHA256}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		trust := device.RoleSnapshot{Role: role, Anchors: [][]byte{der}, LeafPins: []string{}, SPKIPins: []string{}, AllowedIssuers: []string{}}
		if role == "operational" {
			trust.AllowedIssuers = []string{device.Hash(der)}
		} else if role != "recovery" {
			trust.PeerName = role + ".invalid"
			trust.Endpoint = "https://" + trust.PeerName + ":9443"
			trust.LeafPins = []string{device.Hash([]byte(role + "-leaf"))}
			trust.SPKIPins = []string{device.Hash([]byte(role + "-spki"))}
		}
		if role == "observer" {
			trust.Endpoint = ""
		}
		if role == "issuance" {
			trust.CallerLeafPins = []string{device.Hash([]byte("authority-caller"))}
		}
		snapshot.Trust = append(snapshot.Trust, trust)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestConcreteManifestBindsExactSelectionAndPermissions(t *testing.T) {
	var schema jsonschema.Schema
	if json.Unmarshal(ManifestSchema, &schema) != nil {
		t.Fatal("manifest schema unavailable")
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{credentialprofile.ReferenceID, credentialprofile.StableID} {
		t.Run(profile, func(t *testing.T) {
			snapshot := manifestSnapshot(t, profile)
			pin := snapshot.Composition.ProcessArtifactDigest
			manifest, err := Bind("sample", snapshot, pin)
			if err != nil {
				t.Fatal(err)
			}
			permissions, err := process.ExpectedPermissions(snapshot)
			if err != nil || !reflect.DeepEqual(manifest.Permissions, permissions) || manifest.ArtifactDigest != pin || manifest.SnapshotDigest != snapshot.Digest() || manifest.CompositionDigest != snapshot.Composition.Digest() || manifest.Profile != snapshot.Profile || manifest.Schemas[0] != process.Schema() || manifest.Limits != process.DefaultLimits() {
				t.Fatal("manifest widened or changed its selected bindings")
			}
			data, err := json.Marshal(manifest)
			var value map[string]any
			if err != nil || json.Unmarshal(data, &value) != nil || resolved.Validate(value) != nil {
				t.Fatal("concrete manifest does not match strict schema")
			}
			value["permissions"].(map[string]any)["filesystemWrite"] = []any{"/tmp"}
			if resolved.Validate(value) == nil {
				t.Fatal("schema accepted widened filesystem permissions")
			}
			if _, err := Bind("sample", snapshot, device.Hash([]byte("different adapter"))); !errors.Is(err, ErrManifest) {
				t.Fatal("manifest accepted another executable pin")
			}
			snapshot.Composition.ID, snapshot.Composition.Version = "local-http-lab", 2
			snapshot.Composition.ProcessArtifactDigest = ""
			if snapshot.Validate() != nil {
				t.Fatal("native test snapshot invalid")
			}
			if _, err := Bind("sample", snapshot, pin); !errors.Is(err, ErrManifest) {
				t.Fatal("manifest accepted native composition for process adapter")
			}
		})
	}
}
