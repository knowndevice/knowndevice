// SPDX-License-Identifier: Apache-2.0

package schemas_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/knowndevice/knowndevice/api/schemas"
	"github.com/knowndevice/knowndevice/internal/controller"
	"github.com/knowndevice/knowndevice/internal/device"
	"github.com/knowndevice/knowndevice/sdk/adaptergen"
)

func resolve(t *testing.T, data []byte) *jsonschema.Resolved {
	t.Helper()
	var schema jsonschema.Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func value(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestPublishedExamplesMatchSchemas(t *testing.T) {
	evidence, err := os.ReadFile("evidence-v1alpha2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"device-config": schemas.DeviceConfig, "transition-receipt": schemas.TransitionReceipt, "device-config-v1alpha2": schemas.DeviceConfigV2, "transition-receipt-v1alpha2": schemas.TransitionReceiptV2, "evidence-v1alpha2": evidence} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile("../examples/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var example any
			if err := json.Unmarshal(b, &example); err != nil {
				t.Fatal(err)
			}
			if err := resolve(t, data).Validate(example); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, data := range map[string][]byte{"device-config-v1alpha2-process": schemas.DeviceConfigV2, "process-error": schemas.Process, "adapter-template": adaptergen.ManifestSchema} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile("../examples/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var example any
			if err := json.Unmarshal(b, &example); err != nil {
				t.Fatal(err)
			}
			if err := resolve(t, data).Validate(example); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestV2EvidenceRejectsMissingBindingsAndSecretFields(t *testing.T) {
	b, err := os.ReadFile("evidence-v1alpha2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	evidenceSchema := resolve(t, b)
	example, err := os.ReadFile("../examples/evidence-v1alpha2.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"deploymentId", "operationId", "planDigest", "snapshotDigest", "profileDigest", "generation", "publicKeyDigest", "certificateFingerprint", "csrDigest"} {
		t.Run(field, func(t *testing.T) {
			var v map[string]any
			if err := json.Unmarshal(example, &v); err != nil {
				t.Fatal(err)
			}
			delete(v["subject"].(map[string]any), field)
			if evidenceSchema.Validate(v) == nil {
				t.Fatalf("evidence permits missing %s", field)
			}
		})
	}
	var v map[string]any
	if err := json.Unmarshal(example, &v); err != nil {
		t.Fatal(err)
	}
	v["subject"].(map[string]any)["privateKey"] = "must never become public evidence"
	if evidenceSchema.Validate(v) == nil {
		t.Fatal("evidence permits secret fields")
	}
}

func TestRuntimePlanAndReceiptsMatchPublishedContracts(t *testing.T) {
	p := device.Plan{APIVersion: "knowndevice/v1alpha1", OperationID: strings.Repeat("a", 32), DeviceID: "gateway-1", Mode: "rotate", ExpectedGeneration: 1, TargetGeneration: 2, TargetSlot: "B", ConfigDigest: strings.Repeat("b", 64), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	p.Digest, _ = p.CalculateDigest()
	if err := resolve(t, schemas.Plan).Validate(value(t, p)); err != nil {
		t.Fatal(err)
	}
	receiptSchema := resolve(t, schemas.TransitionReceipt)
	s := device.State{DeviceID: p.DeviceID}
	if err := receiptSchema.Validate(value(t, controller.Report(s))); err != nil {
		t.Fatal(err)
	}
	s.Operation = &device.Operation{Plan: p, Phase: device.Registered, Outcome: "blocked", Reason: "authorization-or-application-denied"}
	r := controller.Report(s)
	if err := receiptSchema.Validate(value(t, r)); err != nil {
		t.Fatal(err)
	}
	leak := value(t, r).(map[string]any)
	leak["privateKey"] = "must never become a receipt field"
	if receiptSchema.Validate(leak) == nil {
		t.Fatal("receipt contract permits secret fields")
	}
}

func TestV2ExamplesRequireExplicitProfilesAndRoles(t *testing.T) {
	b, e := os.ReadFile("../examples/device-config-v1alpha2.json")
	if e != nil {
		t.Fatal(e)
	}
	var c device.Config
	if e = device.DecodeStrict(strings.NewReader(string(b)), &c); e != nil {
		t.Fatal(e)
	}
	if e = c.Validate(); e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		t.Fatal("decode")
	}
	v["credentialProfile"].(map[string]any)["version"] = 2
	if resolve(t, schemas.DeviceConfigV2).Validate(v) == nil {
		t.Fatal("unknown profile schema version accepted")
	}
	v = value(t, c).(map[string]any)
	delete(v, "trust")
	if resolve(t, schemas.DeviceConfigV2).Validate(v) == nil {
		t.Fatal("missing role trust accepted")
	}
	p := device.Plan{APIVersion: device.V2, DigestEncodingVersion: 2, DeploymentID: "new-deployment", DeviceID: "new-device", OperationID: strings.Repeat("a", 32), Mode: "enroll", TargetGeneration: 1, TargetSlot: "A", ConfigDigest: strings.Repeat("b", 64), ExpiresAt: time.Now().UTC().Add(time.Minute), ProfileID: c.CredentialProfile.ID, ProfileVersion: c.CredentialProfile.Version, ProfileDigest: c.CredentialProfile.PolicyDigest, CompositionDigest: c.Composition.Digest(), SnapshotDigest: strings.Repeat("b", 64), ControlTrustDigest: strings.Repeat("c", 64), ApplicationTrustDigest: strings.Repeat("d", 64), IssuanceTrustDigest: strings.Repeat("e", 64), RecoveryTrustDigest: strings.Repeat("f", 64), TransportTrustDigest: strings.Repeat("0", 64)}
	p.Digest, _ = p.CalculateDigest()
	if e = resolve(t, schemas.PlanV2).Validate(value(t, p)); e != nil {
		t.Fatal(e)
	}
	state := device.State{SchemaVersion: 2, DeploymentID: p.DeploymentID, DeviceID: p.DeviceID, ProfileID: p.ProfileID, ProfileVersion: p.ProfileVersion, ProfileDigest: p.ProfileDigest, Operation: &device.Operation{Plan: p, Phase: device.Planned, Outcome: "running"}}
	if e = resolve(t, schemas.TransitionReceiptV2).Validate(value(t, controller.Report(state))); e != nil {
		t.Fatal(e)
	}
	if resolve(t, schemas.Plan).Validate(value(t, p)) == nil {
		t.Fatal("v1 schema silently accepted v2")
	}
}

func TestV2CompositionRequiresVersionedLifetime(t *testing.T) {
	b, err := os.ReadFile("../examples/device-config-v1alpha2-short-lived.json")
	if err != nil {
		t.Fatal(err)
	}
	var c device.Config
	if err := device.DecodeStrict(strings.NewReader(string(b)), &c); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	schema := resolve(t, schemas.DeviceConfigV2)
	v := value(t, c).(map[string]any)
	if err := schema.Validate(v); err != nil {
		t.Fatal(err)
	}
	delete(v["composition"].(map[string]any), "authorityLifetimeSeconds")
	if schema.Validate(v) == nil {
		t.Fatal("composition 2 permits missing request policy")
	}
	v = value(t, c).(map[string]any)
	v["composition"].(map[string]any)["version"] = 1
	if schema.Validate(v) == nil {
		t.Fatal("composition 1 permits changed fixed request")
	}
}
