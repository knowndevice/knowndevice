// SPDX-License-Identifier: Apache-2.0

package device

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzDecodeStrict(f *testing.F) {
	f.Add([]byte(`{"apiVersion":"knowndevice/v1alpha1","operationId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","deviceId":"gateway","mode":"enroll","expectedGeneration":0,"targetGeneration":1,"targetSlot":"A","configDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expiresAt":"2026-10-13T12:05:00Z","digest":""}`))
	f.Add([]byte(`{"deviceId":"first","deviceId":"second"}`))
	f.Add([]byte(`{"unknown":true}`))
	f.Add([]byte("deviceId: gateway\nmode: enroll\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var first Plan
		if DecodeStrict(bytes.NewReader(data), &first) != nil {
			return
		}
		encoded, err := json.Marshal(first)
		if err != nil || len(data) > MaxInput {
			t.Fatal("accepted input cannot be bounded public JSON")
		}
		var roundTrip Plan
		if DecodeStrict(bytes.NewReader(encoded), &roundTrip) != nil {
			t.Fatal("accepted input failed strict canonical round-trip")
		}
		canonical, err := json.Marshal(roundTrip)
		if err != nil || !bytes.Equal(encoded, canonical) {
			t.Fatal("strict parser produced unstable public contract encoding")
		}
	})
}
