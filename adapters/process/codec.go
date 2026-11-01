// SPDX-License-Identifier: Apache-2.0

package process

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sync"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/knowndevice/knowndevice/api/schemas"
)

var ErrProtocol = errors.New("adapter process protocol refused")
var messageID = regexp.MustCompile(`^(h|s)-[a-f0-9]{32}$`)
var signerID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var sha256ID = regexp.MustCompile(`^[a-f0-9]{64}$`)

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *string         `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

func (m message) MarshalJSON() ([]byte, error) {
	fields := map[string]any{"jsonrpc": m.JSONRPC}
	if m.Method != "" {
		fields["method"], fields["params"] = m.Method, m.Params
		if m.ID != nil {
			fields["id"] = *m.ID
		}
	} else {
		fields["id"] = m.ID
		if m.Error != nil {
			fields["error"] = m.Error
		} else {
			fields["result"] = m.Result
		}
	}
	return json.Marshal(fields)
}

func readLine(r *bufio.Reader, limits Limits) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		// The optional CR and terminating LF do not consume the content budget.
		if len(line)+len(chunk) > limits.MaxLineBytes+2 {
			return nil, ErrProtocol
		}
		line = append(line, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if err == io.EOF && len(line) == 0 {
				return nil, io.EOF
			}
			return nil, ErrProtocol
		}
		line = line[:len(line)-1]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 || len(line) > limits.MaxLineBytes {
			return nil, ErrProtocol
		}
		return line, nil
	}
}

func checkTokens(data []byte, limits Limits) error {
	if len(data) == 0 || len(data) > limits.MaxLineBytes || !utf8.Valid(data) {
		return ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	values := 0
	var visit func(int) error
	visit = func(depth int) error {
		values++
		if depth > limits.MaxDepth || values > limits.MaxValues {
			return ErrProtocol
		}
		token, err := d.Token()
		if err != nil {
			return ErrProtocol
		}
		if text, ok := token.(string); ok && len(text) > limits.MaxStringBytes {
			return ErrProtocol
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				token, err = d.Token()
				key, ok := token.(string)
				if err != nil || !ok || seen[key] || len(key) > limits.MaxStringBytes || len(seen) >= limits.MaxObjectFields {
					return ErrProtocol
				}
				seen[key] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
			if token, err = d.Token(); err != nil || token != json.Delim('}') {
				return ErrProtocol
			}
		case '[':
			count := 0
			for d.More() {
				count++
				if count > limits.MaxArrayItems {
					return ErrProtocol
				}
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
			if token, err = d.Token(); err != nil || token != json.Delim(']') {
				return ErrProtocol
			}
		default:
			return ErrProtocol
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrProtocol
	}
	return nil
}

func decodeMessage(data []byte, limits Limits) (message, error) {
	var m message
	if err := checkTokens(data, limits); err != nil {
		return m, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return m, ErrProtocol
	}
	for key := range fields {
		switch key {
		case "jsonrpc", "id", "method", "params", "result", "error":
		default:
			return m, ErrProtocol
		}
	}
	if json.Unmarshal(data, &m) != nil || m.JSONRPC != "2.0" {
		return m, ErrProtocol
	}
	if m.Method != "" {
		_, resultPresent := fields["result"]
		_, errorPresent := fields["error"]
		if len(m.Params) == 0 || m.Params[0] != '{' || resultPresent || errorPresent {
			return m, ErrProtocol
		}
		if _, ok := fields["id"]; ok && m.ID == nil {
			return m, ErrProtocol
		}
	} else {
		_, resultPresent := fields["result"]
		_, errorPresent := fields["error"]
		_, methodPresent := fields["method"]
		_, paramsPresent := fields["params"]
		if methodPresent || paramsPresent || resultPresent == errorPresent || (errorPresent && m.Error == nil) {
			return m, ErrProtocol
		}
		if _, ok := fields["id"]; !ok {
			return m, ErrProtocol
		}
		if m.ID == nil && m.Error == nil {
			return m, ErrProtocol
		}
	}
	if m.ID != nil && !messageID.MatchString(*m.ID) {
		return m, ErrProtocol
	}
	return m, nil
}

var schemaOnce sync.Once
var schemaDefs map[string]*jsonschema.Resolved
var schemaSource map[string]*jsonschema.Schema
var schemaMu sync.Mutex
var schemaErr error

func validateDefinition(name string, data []byte) error {
	schemaOnce.Do(func() {
		var source jsonschema.Schema
		if json.Unmarshal(schemas.Process, &source) != nil {
			schemaErr = ErrProtocol
			return
		}
		schemaDefs = map[string]*jsonschema.Resolved{}
		schemaSource = source.Defs
	})
	if schemaErr != nil {
		return schemaErr
	}
	schemaMu.Lock()
	resolved, ok := schemaDefs[name]
	if !ok {
		if _, exists := schemaSource[name]; !exists {
			schemaMu.Unlock()
			return ErrProtocol
		}
		root := jsonschema.Schema{Ref: "#/$defs/" + name, Defs: schemaSource}
		var err error
		resolved, err = root.Resolve(nil)
		if err != nil {
			schemaMu.Unlock()
			return ErrProtocol
		}
		schemaDefs[name] = resolved
	}
	schemaMu.Unlock()
	var value any
	if json.Unmarshal(data, &value) != nil || resolved.Validate(value) != nil {
		return ErrProtocol
	}
	return nil
}

func decodeDefinition(name string, data []byte, out any) error {
	if checkTokens(data, DefaultLimits()) != nil || validateDefinition(name, data) != nil {
		return ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrProtocol
	}
	switch value := out.(type) {
	case *SignResult:
		if len(value.Signature) > DefaultLimits().MaxSignatureBytes {
			return ErrProtocol
		}
	case *SignParams:
		if len(value.Digest) > DefaultLimits().MaxDigestBytes {
			return ErrProtocol
		}
	case *InitializeParams:
		if len(value.Snapshot) > MaxSnapshotBytes {
			return ErrProtocol
		}
	}
	return nil
}

type protocolWriter struct {
	mu  sync.Mutex
	out io.Writer
}

func (w *protocolWriter) write(m message) error {
	data, err := json.Marshal(m)
	if err != nil || checkTokens(data, DefaultLimits()) != nil {
		return ErrProtocol
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	data = append(data, '\n')
	for len(data) > 0 {
		n, err := w.out.Write(data)
		if err != nil || n <= 0 {
			return ErrProtocol
		}
		data = data[n:]
	}
	return nil
}

func request(id, method string, params any) (message, error) {
	data, err := json.Marshal(params)
	if err != nil {
		return message{}, ErrProtocol
	}
	return message{JSONRPC: "2.0", ID: &id, Method: method, Params: data}, nil
}

func success(id *string, value any) (message, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return message{}, ErrProtocol
	}
	return message{JSONRPC: "2.0", ID: id, Result: data}, nil
}
