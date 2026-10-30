// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/internal/device"
)

func TestAUD02ActiveProbeRequiresOriginalPlan(t *testing.T) {
	activePlan := device.Plan{APIVersion: device.V2, OperationID: strings.Repeat("a", 32), DeviceID: "gateway-1", TargetGeneration: 1, TargetSlot: "A", ExpiresAt: time.Now().UTC().Add(time.Minute)}
	active := device.Handle{Binding: activePlan.Binding(), PublicKeyDigest: device.Hash([]byte("active-key"))}
	pending := activePlan
	pending.OperationID = strings.Repeat("b", 32)
	pending.Mode = "rotate"
	pending.ExpectedGeneration, pending.TargetGeneration = 1, 2
	pending.TargetSlot = "B"
	for _, test := range []struct {
		name string
		plan *device.Plan
	}{{"pending-rotation", &pending}, {"missing-plan", nil}} {
		t.Run(test.name, func(t *testing.T) {
			s := device.State{SchemaVersion: 2, Active: &active}
			if test.plan != nil {
				s.Operation = &device.Operation{Plan: *test.plan, Phase: device.IssueIntent, Outcome: "unknown"}
			}
			before, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			p, err := activeProbePlan(s)
			if err == nil || err.Error() != "active V2 probe unavailable: original active-generation plan is not retained; device health is unknown" || p != (device.Plan{}) {
				t.Fatalf("missing authorization was not reported precisely: %+v, %v", p, err)
			}
			after, marshalErr := json.Marshal(s)
			if marshalErr != nil || !bytes.Equal(after, before) {
				t.Fatal("availability check changed the pending intent or active credential")
			}
		})
	}
	s := device.State{SchemaVersion: 2, Active: &active, Operation: &device.Operation{Plan: activePlan, Phase: device.Retired, Outcome: "succeeded"}}
	p, err := activeProbePlan(s)
	if err != nil || p != activePlan || p.ExpiresAt != activePlan.ExpiresAt {
		t.Fatal("availability check replaced or extended the original active plan")
	}
	if _, err := activeProbePlan(device.State{SchemaVersion: 2}); err == nil {
		t.Fatal("missing active credential was reported as probe availability")
	}
}
