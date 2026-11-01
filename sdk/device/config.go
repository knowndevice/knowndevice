// SPDX-License-Identifier: Apache-2.0

package device

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/knowndevice/knowndevice/api/schemas"
	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
	"go.yaml.in/yaml/v3"
)

const MaxInput = 1 << 20

type Config struct {
	APIVersion            string                    `json:"apiVersion"`
	DeviceID              string                    `json:"deviceId"`
	StateDir              string                    `json:"stateDir"`
	ControlURL            string                    `json:"controlURL"`
	ApplicationURL        string                    `json:"applicationURL"`
	ApplicationID         string                    `json:"applicationId"`
	MQTTEndpoint          string                    `json:"mqttEndpoint"`
	RootCertificate       string                    `json:"rootCertificate"`
	RecoveryCertificate   string                    `json:"recoveryCertificate,omitempty"`
	RecoveryKey           string                    `json:"recoveryKey,omitempty"`
	ClockTrust            string                    `json:"clockTrust"`
	RequestTimeoutSeconds int                       `json:"requestTimeoutSeconds"`
	PlanTTLSeconds        int                       `json:"planTTLSeconds"`
	DeploymentID          string                    `json:"deploymentId,omitempty"`
	CredentialProfile     *credentialprofile.Policy `json:"credentialProfile,omitempty"`
	Composition           *Composition              `json:"composition,omitempty"`
	Trust                 *TrustConfig              `json:"trust,omitempty"`
	Limits                *Limits                   `json:"limits,omitempty"`
	TransportEndpoint     string                    `json:"transportEndpoint,omitempty"`
}

// DecodeStrict accepts a small JSON/YAML data subset and rejects ambiguity.
func DecodeStrict(r io.Reader, target any) error {
	b, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil || len(b) > MaxInput {
		return fmt.Errorf("input unreadable or exceeds one MiB")
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var node yaml.Node
	if err := dec.Decode(&node); err != nil {
		return fmt.Errorf("invalid JSON/YAML input")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected one input document")
	}
	count := 0
	if err := checkNode(&node, 0, &count); err != nil {
		return err
	}
	var value any
	if err := node.Decode(&value); err != nil {
		return fmt.Errorf("invalid data types")
	}
	if err := rejectLegacyFields(value, false); err != nil {
		return err
	}
	if err := checkFields(value, reflect.TypeOf(target)); err != nil {
		return err
	}
	b, err = json.Marshal(value)
	if err != nil {
		return fmt.Errorf("input is not JSON-compatible")
	}
	j := json.NewDecoder(bytes.NewReader(b))
	j.DisallowUnknownFields()
	if err := j.Decode(target); err != nil {
		return fmt.Errorf("unknown field or invalid data type")
	}
	return nil
}

func checkFields(v any, t reflect.Type) error {
	if t == nil {
		return fmt.Errorf("missing input target")
	}
	unmarshaler := reflect.TypeFor[json.Unmarshaler]()
	if t.Implements(unmarshaler) || (t.Kind() != reflect.Pointer && reflect.PointerTo(t).Implements(unmarshaler)) {
		return nil
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		for name, value := range object {
			field, ok := fields[name]
			if !ok {
				return fmt.Errorf("unknown mapping key")
			}
			if err := checkFields(value, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if items, ok := v.([]any); ok {
			for _, item := range items {
				if err := checkFields(item, t.Elem()); err != nil {
					return err
				}
			}
		}
	case reflect.Map:
		if object, ok := v.(map[string]any); ok {
			for _, value := range object {
				if err := checkFields(value, t.Elem()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkNode(n *yaml.Node, depth int, count *int) error {
	*count++
	if depth > 32 || *count > 10000 || n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("input nesting, aliases or anchors are not allowed")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] {
				return fmt.Errorf("duplicate or non-string mapping key")
			}
			seen[key.Value] = true
		}
	}
	if n.Kind == yaml.ScalarNode {
		switch n.Tag {
		case "!!str", "!!int", "!!float", "!!null", "!!bool":
		default:
			return fmt.Errorf("unsupported scalar type")
		}
	}
	for _, child := range n.Content {
		if err := checkNode(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer f.Close()
	var c Config
	if err := DecodeStrict(f, &c); err != nil {
		return c, err
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return c, err
	}
	for _, p := range []*string{&c.StateDir, &c.RootCertificate, &c.RecoveryCertificate, &c.RecoveryKey} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	if c.Trust != nil {
		for i := range c.Trust.Roles {
			for j := range c.Trust.Roles[i].RootCertificates {
				p := &c.Trust.Roles[i].RootCertificates[j]
				if !filepath.IsAbs(*p) {
					*p = filepath.Join(base, *p)
				}
			}
		}
	}
	return c, nil
}

func (c Config) Validate() error {
	if c.APIVersion == V2 {
		if err := validateConfigSchema(c, schemas.DeviceConfigV2); err != nil {
			return err
		}
		if !ValidDeviceID(c.DeviceID) || !ValidDeviceID(c.DeploymentID) || c.StateDir == "" || c.RootCertificate != "" || c.MQTTEndpoint != "" || c.CredentialProfile == nil || c.Composition == nil || c.Trust == nil || c.Limits == nil || c.ClockTrust != "trusted-system-clock" || c.RecoveryCertificate == "" || c.RecoveryKey == "" || c.RequestTimeoutSeconds < 1 || c.RequestTimeoutSeconds > 60 || c.PlanTTLSeconds < 60 || c.PlanTTLSeconds > 600 || c.Composition.ApplicationID != c.ApplicationID || c.Composition.Validate() != nil || c.Limits.Validate() != nil {
			return fmt.Errorf("invalid v1alpha2 configuration")
		}
		if _, err := credentialprofile.Resolve(c.CredentialProfile.ID, c.CredentialProfile.Version, c.CredentialProfile.PolicyDigest); err != nil {
			return err
		}
		return nil
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(schemas.DeviceConfig, &schema); err != nil {
		return err
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(c)
	var value any
	if err := json.Unmarshal(b, &value); err != nil {
		return err
	}
	if err := resolved.Validate(value); err != nil {
		return fmt.Errorf("configuration does not match device-config v1alpha1")
	}
	for _, endpoint := range []struct{ raw, scheme string }{{c.ControlURL, "https"}, {c.ApplicationURL, "https"}, {c.MQTTEndpoint, "tls"}} {
		u, err := url.Parse(endpoint.raw)
		if err != nil || u.Scheme != endpoint.scheme || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return fmt.Errorf("invalid configured endpoint")
		}
		if endpoint.scheme == "tls" && u.Port() == "" {
			return fmt.Errorf("MQTT endpoint requires an explicit port")
		}
	}
	return nil
}

func (c Config) Timeout() time.Duration { return time.Duration(c.RequestTimeoutSeconds) * time.Second }

func (c Config) Roots() (*x509.CertPool, error) {
	if c.APIVersion == V2 {
		return nil, fmt.Errorf("v1alpha2 requires explicit role roots")
	}
	f, err := os.Open(c.RootCertificate)
	if err != nil {
		return nil, fmt.Errorf("read trust root: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxInput+1))
	if err != nil || len(b) > MaxInput {
		return nil, fmt.Errorf("trust root unreadable or too large")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("trust root contains no certificates")
	}
	return roots, nil
}

func (c Config) Digest() (string, error) {
	if c.APIVersion == V2 {
		s, e := c.ResolveSnapshot()
		if e != nil {
			return "", e
		}
		return s.Digest(), nil
	}
	if _, err := c.Roots(); err != nil {
		return "", err
	}
	b, err := os.ReadFile(c.RootCertificate)
	if err != nil {
		return "", err
	}
	v := struct {
		Config      Config `json:"config"`
		TrustDigest string `json:"trustDigest"`
	}{c, Hash(b)}
	b, err = json.Marshal(v)
	if err != nil {
		return "", err
	}
	return Hash(b), nil
}

func validateConfigSchema(c Config, data []byte) error {
	var schema jsonschema.Schema
	if json.Unmarshal(data, &schema) != nil {
		return fmt.Errorf("configuration schema unavailable")
	}
	resolved, e := schema.Resolve(nil)
	if e != nil {
		return e
	}
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	var v any
	if json.Unmarshal(b, &v) != nil || resolved.Validate(v) != nil {
		return fmt.Errorf("configuration does not match its API version")
	}
	return nil
}
