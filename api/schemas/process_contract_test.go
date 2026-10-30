// SPDX-License-Identifier: Apache-2.0

package schemas_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/knowndevice/knowndevice/api/schemas"
)

func TestProcessSchemaMessageBoundaries(t *testing.T) {
	schema := resolve(t, schemas.Process)
	b, err := os.ReadFile("../examples/process-error.json")
	if err != nil {
		t.Fatal(err)
	}
	var example map[string]any
	if err := json.Unmarshal(b, &example); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(example); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["result"] = map[string]any{} },
		func(v map[string]any) { v["privateKey"] = "must never become protocol data" },
		func(v map[string]any) { v["id"] = 1 },
		func(v map[string]any) { v["error"].(map[string]any)["code"] = -32016 },
		func(v map[string]any) { delete(v["error"].(map[string]any)["data"].(map[string]any), "scope") },
		func(v map[string]any) { v["error"].(map[string]any)["data"].(map[string]any)["retryable"] = true },
		func(v map[string]any) {
			delete(v["error"].(map[string]any)["data"].(map[string]any)["scope"].(map[string]any), "planDigest")
		},
	} {
		var changed map[string]any
		if err := json.Unmarshal(b, &changed); err != nil {
			t.Fatal(err)
		}
		mutate(changed)
		if schema.Validate(changed) == nil {
			t.Fatal("process schema accepted incomplete, ambiguous or unsafe message")
		}
	}
	health := map[string]any{"jsonrpc": "2.0", "id": "h-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "method": "plugin.health", "params": map[string]any{}}
	if err := schema.Validate(health); err != nil {
		t.Fatal(err)
	}
	health["method"] = "keystore.destroy"
	if schema.Validate(health) == nil {
		t.Fatal("unsolicited mutation has a schema")
	}
}
