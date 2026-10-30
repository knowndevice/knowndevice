// SPDX-License-Identifier: Apache-2.0

package device

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	sdk "knowndevice.local/knowndevice/sdk/device"
)

func TestPublicContractRetainsInternalTypeAndErrorIdentity(t *testing.T) {
	p := Plan{APIVersion: "knowndevice/v1alpha1", OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DeviceID: "gateway", Mode: "rotate", ExpectedGeneration: 1, TargetGeneration: 2, TargetSlot: "B", ConfigDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ExpiresAt: time.Date(2026, 10, 12, 12, 5, 0, 0, time.UTC)}
	var public sdk.Plan = p
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	publicData, err := json.Marshal(public)
	if err != nil || !bytes.Equal(data, publicData) {
		t.Fatal("public and internal plan encoding differs")
	}
	digest, err := p.CalculateDigest()
	publicDigest, publicErr := public.CalculateDigest()
	if err != nil || publicErr != nil || digest != publicDigest {
		t.Fatal("public and internal plan digest differs")
	}
	for _, pair := range [][2]error{{ErrUnknown, sdk.ErrUnknown}, {ErrDenied, sdk.ErrDenied}, {ErrConflict, sdk.ErrConflict}, {ErrUnsupported, sdk.ErrUnsupported}, {ErrPlanExpired, sdk.ErrPlanExpired}, {ErrNotFound, sdk.ErrNotFound}} {
		if !errors.Is(fmt.Errorf("safe context: %w", pair[0]), pair[1]) {
			t.Fatal("compatibility wrapper changed error identity")
		}
	}
	if DecodeStrict(bytes.NewBufferString(`{"apiVersion":"knowndevice/v1alpha1","profileVersion":0}`), &public) == nil {
		t.Fatal("compatibility wrapper relaxed field-presence checks")
	}
}
