// SPDX-License-Identifier: Apache-2.0

package device

import "fmt"

// MarshalJSON refuses to turn a signer-bearing credential into a wire artifact.
// Process transports must carry bounded public material and a scoped handle.
func (Credential) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("signer-bearing credentials cannot be serialized: %w", ErrUnsupported)
}

// UnmarshalJSON cannot manufacture a signer from supplied private material.
func (*Credential) UnmarshalJSON([]byte) error {
	return fmt.Errorf("signer-bearing credentials cannot be deserialized: %w", ErrUnsupported)
}
