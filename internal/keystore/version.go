// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"knowndevice.local/knowndevice/internal/credentialprofile"
	"knowndevice.local/knowndevice/internal/device"
)

func validDigest(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 32 && hex.EncodeToString(data) == value
}

func (s identity) validate() error {
	if s.SchemaVersion != 2 || !device.ValidDeviceID(s.DeviceID) || !device.ValidDeviceID(s.DeploymentID) {
		return fmt.Errorf("invalid version-two key-store scope")
	}
	if _, err := credentialprofile.Resolve(s.ProfileID, s.ProfileVersion, s.ProfileDigest); err != nil {
		return fmt.Errorf("unsupported key-store credential profile: %w", device.ErrUnsupported)
	}
	return nil
}

func (s identity) matches(stored identity) bool {
	if s.SchemaVersion == 1 {
		return stored.SchemaVersion == 1 && stored.DeploymentID == "" && stored.ProfileID == "" && stored.ProfileVersion == 0 && stored.ProfileDigest == ""
	}
	return s == stored
}

func (s *Store) validateBinding(b device.Binding) error {
	if err := b.Validate(); err != nil {
		return err
	}
	if s.scope.SchemaVersion == 1 {
		if b.DeploymentID != "" || b.ProfileID != "" || b.ProfileVersion != 0 || b.ProfileDigest != "" || b.ConfigDigest != "" || b.PlanDigest != "" || b.SnapshotDigest != "" {
			return fmt.Errorf("legacy key store refuses profile-aware bindings: %w", device.ErrUnsupported)
		}
		return nil
	}
	if b.DeviceID != s.scope.DeviceID || b.DeploymentID != s.scope.DeploymentID || b.ProfileID != s.scope.ProfileID || b.ProfileVersion != s.scope.ProfileVersion || b.ProfileDigest != s.scope.ProfileDigest || len(b.ConfigDigest) != 64 || len(b.PlanDigest) != 64 || len(b.SnapshotDigest) != 64 {
		return fmt.Errorf("key-store immutable scope does not match binding: %w", device.ErrConflict)
	}
	return nil
}

func (s *Store) preflight(readOnly bool) error {
	items, err := entries(s.root)
	if err != nil {
		return err
	}
	hasIdentity := false
	for _, item := range items {
		switch name := item.Name(); {
		case name == ".lock":
			if info, err := s.root.Lstat(name); err != nil {
				return err
			} else if err := owned(info, false); err != nil {
				return err
			}
		case name == ".device.json" || name == ".device.pending":
			data, err := readFile(s.root, name)
			if err != nil {
				return err
			}
			var stored identity
			if err := decodeJSON(data, &stored); err != nil {
				return fmt.Errorf("invalid key-store identity")
			}
			if stored.SchemaVersion != s.scope.SchemaVersion {
				return fmt.Errorf("unsupported key-store schema %d: %w", stored.SchemaVersion, device.ErrUnsupported)
			}
			if !s.scope.matches(stored) || !device.ValidDeviceID(stored.DeviceID) {
				return fmt.Errorf("key-store scope differs from requested identity: %w", device.ErrConflict)
			}
			if name == ".device.json" {
				hasIdentity = true
			}
		case name == "active.json" || name == ".active.pending":
			data, err := readFile(s.root, name)
			if err != nil {
				return err
			}
			var pointer activePointer
			if decodeJSON(data, &pointer) != nil {
				return fmt.Errorf("invalid key-store active pointer")
			}
			if pointer.SchemaVersion != s.scope.SchemaVersion {
				return fmt.Errorf("unsupported active-pointer schema %d: %w", pointer.SchemaVersion, device.ErrUnsupported)
			}
			if err := s.validateBinding(pointer.Handle.Binding); err != nil {
				return err
			}
		case strings.HasPrefix(name, ".retired-"):
			data, err := readFile(s.root, name)
			if err != nil {
				return err
			}
			var record destruction
			if decodeJSON(data, &record) != nil {
				return fmt.Errorf("invalid key-store destruction record")
			}
			if record.SchemaVersion != s.scope.SchemaVersion {
				return fmt.Errorf("unsupported destruction schema %d: %w", record.SchemaVersion, device.ErrUnsupported)
			}
			if err := s.validateBinding(record.Handle.Binding); err != nil {
				return err
			}
		case name == "A" || name == "B" || strings.HasPrefix(name, ".stage-") || strings.HasPrefix(name, ".destroy-"):
			root, err := subdirectory(s.root, name)
			if err != nil {
				return err
			}
			err = s.preflightSlot(root, !strings.HasPrefix(name, ".destroy-"))
			root.Close()
			if err != nil {
				return err
			}
		default:
			if s.scope.SchemaVersion == 2 {
				return fmt.Errorf("unknown key-store artifact requires intervention: %w", device.ErrConflict)
			}
		}
	}
	if s.scope.SchemaVersion == 2 && !hasIdentity {
		for _, item := range items {
			if item.Name() != ".lock" && item.Name() != ".device.pending" {
				return fmt.Errorf("version-two store requires fresh or exactly bound initialization: %w", device.ErrConflict)
			}
		}
		if readOnly {
			return fmt.Errorf("key-store identity is not durably initialized: %w", device.ErrConflict)
		}
	}
	return nil
}

func (s *Store) preflightSlot(root *os.Root, complete bool) error {
	hasManifest := false
	for _, name := range []string{"manifest.json", "binding.json"} {
		data, err := readFile(root, name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		version := 0
		var binding device.Binding
		if name == "manifest.json" {
			hasManifest = true
			var m manifest
			if decodeJSON(data, &m) != nil {
				return fmt.Errorf("invalid slot manifest")
			}
			version, binding = m.SchemaVersion, m.Handle.Binding
		} else {
			var intent bindingIntent
			if decodeJSON(data, &intent) != nil {
				return fmt.Errorf("invalid slot binding")
			}
			version, binding = intent.SchemaVersion, intent.Binding
		}
		if version != s.scope.SchemaVersion {
			return fmt.Errorf("unsupported slot schema %d: %w", version, device.ErrUnsupported)
		}
		if err := s.validateBinding(binding); err != nil {
			return err
		}
	}
	if s.scope.SchemaVersion == 2 && complete && hasManifest {
		_, _, err := s.slotSigner(root)
		return err
	}
	return nil
}
