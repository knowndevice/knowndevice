// SPDX-License-Identifier: Apache-2.0

package process

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/sdk/device"
)

func TestAUD02PendingPlanCannotAuthorizePreviousActiveProbe(t *testing.T) {
	c, pending, active, _, signer, _ := startConfiguredFixtureProcess(t, "plain", true)
	if pending.OperationID == active.Handle.Binding.OperationID || pending.ExpectedGeneration != active.Handle.Binding.Generation {
		t.Fatal("fixture does not distinguish active and pending operations")
	}
	if err := c.SetPlan(pending); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	ids := len(c.ids)
	c.mu.Unlock()
	role, _ := c.snapshot.Role("transport")
	probe := device.Probe{OperationID: active.Handle.Binding.OperationID, DeviceID: pending.DeviceID, Generation: active.Handle.Binding.Generation, Endpoint: role.Endpoint, Nonce: strings.Repeat("c", 32), Deadline: time.Now().UTC().Add(time.Second)}
	for _, operationID := range []string{probe.OperationID, pending.OperationID} {
		request := probe
		request.OperationID = operationID
		reply, err := c.Probe(context.Background(), request, active)
		if !errors.Is(err, device.ErrConflict) || reply != (device.Probe{}) {
			t.Fatalf("missing or mismatched target plan was accepted: %+v, %v", reply, err)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.ids) != ids || len(c.pending) != 0 || len(c.plans) != 1 || c.plans[pending.OperationID] != pending || signer.calls.Load() != 0 {
		t.Fatal("unavailable active probe dispatched a request, signed or changed a plan")
	}
}
