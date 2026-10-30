// SPDX-License-Identifier: Apache-2.0

package device

import (
	"bytes"
	"encoding/json"
	"fmt"
)

var v2Fields = map[string]bool{"deploymentId": true, "profileId": true, "profileVersion": true, "profileDigest": true, "compositionDigest": true, "snapshotDigest": true, "controlTrustDigest": true, "applicationTrustDigest": true, "issuanceTrustDigest": true, "recoveryTrustDigest": true, "transportTrustDigest": true, "digestEncodingVersion": true, "credentialProfile": true, "composition": true, "trust": true, "limits": true, "transportEndpoint": true, "snapshot": true, "previousCSR": true, "previousCertificate": true, "evidence": true}

func rejectLegacyFields(value any, legacy bool) error {
	switch v := value.(type) {
	case map[string]any:
		if v["apiVersion"] == "knowndevice/v1alpha1" || fmt.Sprint(v["schemaVersion"]) == "1" {
			legacy = true
		}
		if legacy {
			if v["apiVersion"] == V2 || fmt.Sprint(v["schemaVersion"]) == "2" {
				return fmt.Errorf("version-one input cannot contain version-two state")
			}
			for name := range v {
				if v2Fields[name] {
					return fmt.Errorf("version-one input contains a version-two field")
				}
			}
		}
		for _, child := range v {
			if e := rejectLegacyFields(child, legacy); e != nil {
				return e
			}
		}
	case []any:
		for _, child := range v {
			if e := rejectLegacyFields(child, legacy); e != nil {
				return e
			}
		}
	}
	return nil
}

// CheckVersionFields preserves field presence, including empty, null and zero values.
func CheckVersionFields(data []byte) error {
	var value any
	return DecodeStrict(bytes.NewReader(data), &value)
}
func (c *Config) UnmarshalJSON(data []byte) error {
	type plain Config
	return DecodeStrict(bytes.NewReader(data), (*plain)(c))
}
func (p *Plan) UnmarshalJSON(data []byte) error {
	type plain Plan
	return DecodeStrict(bytes.NewReader(data), (*plain)(p))
}
func (s *State) UnmarshalJSON(data []byte) error {
	type plain State
	return DecodeStrict(bytes.NewReader(data), (*plain)(s))
}

func (c *Composition) UnmarshalJSON(data []byte) error {
	type plain Composition
	var decoded plain
	if err := DecodeStrict(bytes.NewReader(data), &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return ErrDenied
	}
	if _, present := fields["processArtifactDigest"]; present && decoded.ID != "local-http-process-lab" {
		return ErrUnsupported
	}
	*c = Composition(decoded)
	return nil
}
