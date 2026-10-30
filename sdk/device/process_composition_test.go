// SPDX-License-Identifier: Apache-2.0

package device

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestProcessCompositionPinsWrapperWithoutChangingNativeEncoding(t *testing.T) {
	s := snapshotFixture(t)
	original := s.Bytes()
	process := s.Composition
	process.ID = "local-http-process-lab"
	process.Version = 1
	process.ProcessArtifactDigest = Hash([]byte("process artifact"))
	process.AuthorityLifetimeSeconds = 300
	if err := process.Validate(); err != nil || process.AuthorityLifetime() != 300*time.Second {
		t.Fatal("explicit process composition refused")
	}
	before := process.Digest()
	process.ProcessArtifactDigest = Hash([]byte("different process artifact"))
	if process.Digest() == before {
		t.Fatal("process artifact is not bound to composition")
	}
	for _, change := range []func(*Composition){
		func(c *Composition) { c.ProcessArtifactDigest = "" },
		func(c *Composition) { c.Version = 2 },
		func(c *Composition) { c.AuthorityLifetimeSeconds = 0 },
		func(c *Composition) { c.ID = "local-http-lab" },
	} {
		invalid := process
		change(&invalid)
		if invalid.Validate() == nil {
			t.Fatal("implicit process selection or unpinned composition accepted")
		}
	}
	if !bytes.Equal(original, s.Bytes()) || bytes.Contains(s.Bytes(), []byte("processArtifactDigest")) {
		t.Fatal("native snapshot encoding changed")
	}
}

func TestNativeCompositionRejectsExplicitProcessFieldPresence(t *testing.T) {
	s := snapshotFixture(t)
	b, err := json.Marshal(s.Composition)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{`null`, `""`, `"` + Hash([]byte("process")) + `"`} {
		input := append(append([]byte(nil), b[:len(b)-1]...), []byte(`,"processArtifactDigest":`+value+`}`)...)
		var c Composition
		if DecodeStrict(bytes.NewReader(input), &c) == nil {
			t.Fatal("native composition admitted explicit process field")
		}
	}
}
