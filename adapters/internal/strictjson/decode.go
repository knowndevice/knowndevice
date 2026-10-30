// SPDX-License-Identifier: Apache-2.0

// Package strictjson rejects ambiguous or deeply nested reference responses.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func Decode(data []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	count := 0
	if err := value(decoder, 0, &count); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("expected one JSON document")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("invalid JSON response fields")
	}
	return nil
}

func value(decoder *json.Decoder, depth int, count *int) error {
	*count++
	if depth > 32 || *count > 10000 {
		return fmt.Errorf("JSON response exceeds nesting or value limits")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON response")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] {
				return fmt.Errorf("duplicate or invalid JSON key")
			}
			seen[key] = true
			if err := value(decoder, depth+1, count); err != nil {
				return err
			}
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := value(decoder, depth+1, count); err != nil {
				return err
			}
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	return nil
}
