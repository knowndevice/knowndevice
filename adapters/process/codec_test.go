// SPDX-License-Identifier: Apache-2.0

package process

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
)

const testID = "h-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestFramingAndAmbiguousMessagesAreRefused(t *testing.T) {
	good := `{"jsonrpc":"2.0","id":"` + testID + `","method":"plugin.health","params":{}}`
	if _, err := decodeMessage([]byte(good), DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`[]`, `null`, good + `{}`, strings.Replace(good, `"jsonrpc":"2.0"`, `"jsonrpc":"2.0","jsonrpc":"2.0"`, 1),
		strings.Replace(good, `"method"`, `"Method"`, 1), strings.Replace(good, `"params":{}`, `"params":{},"unknown":null`, 1),
		strings.Replace(good, `"params":{}`, `"params":{},"error":null`, 1), strings.Replace(good, `"params":{}`, `"params":{},"result":null`, 1),
		strings.Replace(good, `"params":{}`, `"params":[]`, 1), strings.Replace(good, `"`+testID+`"`, `null`, 1), strings.Replace(good, `"`+testID+`"`, `1`, 1),
		`{"jsonrpc":"2.0","id":"` + testID + `","result":{},"error":null}`, string([]byte{'{', '"', 0xff, '"', ':', '1', '}'}),
	} {
		if _, err := decodeMessage([]byte(bad), DefaultLimits()); err == nil {
			t.Fatalf("accepted ambiguous message %q", bad)
		}
	}
	for _, line := range []string{good + "\n", good + "\r\n"} {
		if _, err := readLine(bufio.NewReader(strings.NewReader(line)), DefaultLimits()); err != nil {
			t.Fatal(err)
		}
	}
	for _, line := range []string{"\n", good, strings.Repeat("x", DefaultLimits().MaxLineBytes+1) + "\n"} {
		if _, err := readLine(bufio.NewReader(strings.NewReader(line)), DefaultLimits()); err == nil {
			t.Fatal("accepted invalid framing")
		}
	}
	response := message{JSONRPC: "2.0", Error: rpcError("parse-error", nil)}
	data, _ := json.Marshal(response)
	if !bytes.Contains(data, []byte(`"id":null`)) || validateDefinition("response", data) != nil {
		t.Fatal("parse refusal lacks the JSON-RPC null ID")
	}
}

func TestStructuralAndTypedBounds(t *testing.T) {
	limits := DefaultLimits()
	for _, value := range []string{
		strings.Repeat("[", limits.MaxDepth+1) + "0" + strings.Repeat("]", limits.MaxDepth+1),
		`[0` + strings.Repeat(",0", limits.MaxArrayItems) + `]`,
		`"` + strings.Repeat("x", limits.MaxStringBytes+1) + `"`,
	} {
		if checkTokens([]byte(value), limits) == nil {
			t.Fatal("accepted excessive structure")
		}
	}
	var health Empty
	for _, value := range []string{`{"Status":"ok"}`, `{"status":"ok","extra":true}`, `{"status":"ok","status":"ok"}`, `{}`} {
		if decodeDefinition("healthResult", []byte(value), &health) == nil {
			t.Fatal("accepted unknown/missing health shape")
		}
	}
	var sign SignResult
	tooLarge, _ := json.Marshal(SignResult{Signature: make([]byte, 513)})
	if decodeDefinition("signResult", tooLarge, &sign) == nil {
		t.Fatal("accepted oversized signature")
	}
	for _, hash := range []string{"SHA256", "SHA384", "SHA512"} {
		size := 32
		if hash == "SHA384" {
			size = 48
		}
		if hash == "SHA512" {
			size = 64
		}
		if _, err := hashAlgorithm(hash, size); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hashAlgorithm("sha256", 32); err == nil {
		t.Fatal("accepted unnegotiated hash spelling")
	}
}

func FuzzDecodeMessage(f *testing.F) {
	for _, seed := range []string{`{"jsonrpc":"2.0","id":"` + testID + `","method":"plugin.health","params":{}}`, `{"jsonrpc":"2.0","id":null,"error":null}`, `{"a":1,"a":2}`, `[[[0]]]`, `{"x":"\ud800"}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := decodeMessage(data, DefaultLimits())
		if err == nil {
			encoded, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeMessage(encoded, DefaultLimits()); err != nil {
				t.Fatal("accepted message cannot round-trip")
			}
		}
	})
}
func FuzzNDJSONFrame(f *testing.F) {
	for _, seed := range []string{"{}\n", "{}\r\n", "{}", "\n", strings.Repeat("x", 1025) + "\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		limits := DefaultLimits()
		limits.MaxLineBytes = 1024
		line, err := readLine(bufio.NewReaderSize(bytes.NewReader(data), 128), limits)
		if err == nil && (len(line) == 0 || len(line) > limits.MaxLineBytes) {
			t.Fatal("framing exceeded bound")
		}
	})
}
func FuzzTypedSignParams(f *testing.F) {
	positive := SignParams{ParentID: testID, SignerRef: strings.Repeat("b", 32), Scope: Scope{OperationID: strings.Repeat("a", 32), DeviceID: "gateway", DeploymentID: "fixture", PlanDigest: strings.Repeat("c", 64), SnapshotDigest: strings.Repeat("c", 64), CompositionDigest: strings.Repeat("c", 64), ProfileID: credentialprofile.StableID, ProfileDigest: strings.Repeat("c", 64), ProfileVersion: 1, TargetGeneration: 1, Deadline: time.Date(2026, 10, 13, 23, 0, 0, 0, time.UTC)}, Hash: "SHA256", Digest: make([]byte, 32)}
	seed, _ := json.Marshal(positive)
	f.Add(seed)
	f.Add([]byte(`{"parentId":"` + testID + `","signerRef":"","scope":{},"hash":"SHA256","digest":"AA=="}`))
	f.Add([]byte(`{"parentId":null,"parentId":"duplicate"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var input SignParams
		_ = decodeDefinition("signParams", data, &input)
	})
}
