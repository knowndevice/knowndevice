// SPDX-License-Identifier: Apache-2.0

// Package keystore provides two durable software signer slots, A and B.
package keystore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
)

type manifest struct {
	SchemaVersion int           `json:"schemaVersion"`
	Handle        device.Handle `json:"handle"`
}

type activePointer struct {
	SchemaVersion int           `json:"schemaVersion"`
	Handle        device.Handle `json:"handle"`
}

type destruction struct {
	SchemaVersion int           `json:"schemaVersion"`
	Handle        device.Handle `json:"handle"`
	Complete      bool          `json:"complete"`
}

type bindingIntent struct {
	SchemaVersion int            `json:"schemaVersion"`
	Binding       device.Binding `json:"binding"`
}

type identity struct {
	SchemaVersion  int    `json:"schemaVersion"`
	DeviceID       string `json:"deviceId"`
	DeploymentID   string `json:"deploymentId,omitempty"`
	ProfileID      string `json:"profileId,omitempty"`
	ProfileVersion int    `json:"profileVersion,omitempty"`
	ProfileDigest  string `json:"profileDigest,omitempty"`
}

// Store keeps private keys on disk and returns only handles and signers.
// Its advisory lock serializes local slot mutations across processes.
type Store struct {
	mu          sync.Mutex
	root        *os.Root
	lock        *os.File
	lockInfo    os.FileInfo
	closed      bool
	readOnly    bool
	scope       identity
	writeErr    error
	initialized bool
	// Tests stop an actual helper process at a completed filesystem effect.
	checkpoint func(string)
}

func Open(path string) (_ *Store, err error) {
	return open(path, false, identity{SchemaVersion: 1})
}

// OpenReadOnly never creates artifacts or opens writable file descriptors.
func OpenReadOnly(path string) (*Store, error) {
	return open(path, true, identity{SchemaVersion: 1})
}

// OpenV2 initializes a fresh namespace/device/profile-bound version-two store.
func OpenV2(path, deploymentID, deviceID, profileID string, profileVersion int, profileDigest string) (*Store, error) {
	scope := identity{SchemaVersion: 2, DeploymentID: deploymentID, DeviceID: deviceID, ProfileID: profileID, ProfileVersion: profileVersion, ProfileDigest: profileDigest}
	if err := scope.validate(); err != nil {
		return nil, err
	}
	return open(path, false, scope)
}

// OpenReadOnlyV2 never initializes, migrates or changes a profile-bound store.
func OpenReadOnlyV2(path, deploymentID, deviceID, profileID string, profileVersion int, profileDigest string) (*Store, error) {
	scope := identity{SchemaVersion: 2, DeploymentID: deploymentID, DeviceID: deviceID, ProfileID: profileID, ProfileVersion: profileVersion, ProfileDigest: profileDigest}
	if err := scope.validate(); err != nil {
		return nil, err
	}
	return open(path, true, scope)
}

func open(path string, readOnly bool, scope identity) (_ *Store, err error) {
	root, err := openDirectory(path, !readOnly)
	if err != nil {
		return nil, err
	}
	s := &Store{root: root, readOnly: readOnly, scope: scope}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	// Inspect identity and metadata before creating a lock or any other artifact.
	if err := s.preflight(readOnly); err != nil {
		return nil, err
	}
	flags := os.O_RDWR | os.O_CREATE
	if readOnly {
		flags = os.O_RDONLY
	}
	s.lock, err = openFile(root, ".lock", flags)
	if err != nil {
		return nil, err
	}
	s.lockInfo, err = s.lock.Stat()
	if err != nil {
		return nil, err
	}
	if !readOnly {
		err = syncDir(root)
	}
	if err != nil {
		return nil, err
	}
	if scope.SchemaVersion == 2 {
		err = s.locked(context.Background(), !readOnly, func() error {
			if err := s.preflight(readOnly); err != nil {
				return err
			}
			if !readOnly {
				return s.bindDevice(scope.DeviceID)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		s.initialized = true
	}
	return s, nil
}

func (s *Store) at(checkpoint string) {
	if s.checkpoint != nil {
		s.checkpoint(checkpoint)
	}
}

func (s *Store) locked(ctx context.Context, exclusive bool, effect func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed {
		return fmt.Errorf("key store is closed")
	}
	if exclusive && s.readOnly {
		return fmt.Errorf("read-only key store cannot mutate slots: %w", device.ErrDenied)
	}
	if exclusive && s.writeErr != nil {
		return fmt.Errorf("key-store write failed; reopen before further effects: %w", s.writeErr)
	}
	rootInfo, err := s.root.Stat(".")
	if err != nil {
		return err
	}
	if err := owned(rootInfo, true); err != nil {
		return err
	}
	info, err := s.root.Lstat(".lock")
	if err != nil {
		return err
	}
	if err := owned(info, false); err != nil {
		return err
	}
	if !os.SameFile(info, s.lockInfo) {
		return fmt.Errorf("key-store lock inode changed: %w", device.ErrConflict)
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(s.lock.Fd()), mode|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("key store has a competing operation: %w", device.ErrConflict)
	}
	defer syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	if s.scope.SchemaVersion == 2 && s.initialized {
		data, err := readFile(s.root, ".device.json")
		var stored identity
		if err != nil || decodeJSON(data, &stored) != nil || stored != s.scope {
			return fmt.Errorf("key-store immutable identity requires reconciliation: %w", device.ErrConflict)
		}
	}
	err = effect()
	if exclusive && s.scope.SchemaVersion == 2 && (errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EROFS) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EIO)) {
		s.writeErr = err
	}
	return err
}

func (s *Store) Stage(ctx context.Context, binding device.Binding) (device.Handle, error) {
	if err := binding.Validate(); err != nil {
		return device.Handle{}, err
	}
	var result device.Handle
	err := s.locked(ctx, true, func() error {
		if err := s.validateBinding(binding); err != nil {
			return err
		}
		if err := s.bindDevice(binding.DeviceID); err != nil {
			return err
		}
		items, err := entries(s.root)
		if err != nil {
			return err
		}
		var newest uint64
		for _, item := range items {
			if strings.HasPrefix(item.Name(), ".retired-") && strings.HasSuffix(item.Name(), ".json") {
				data, err := readFile(s.root, item.Name())
				if err != nil {
					return err
				}
				var record destruction
				if decodeJSON(data, &record) != nil || record.SchemaVersion != s.scope.SchemaVersion || record.Handle.Validate() != nil || record.Handle.Binding.DeviceID != binding.DeviceID || s.validateBinding(record.Handle.Binding) != nil {
					return fmt.Errorf("invalid destruction record requires intervention")
				}
				if (record.Handle.Binding.Slot == binding.Slot && !record.Complete) || record.Handle.Binding == binding {
					return fmt.Errorf("unfinished or retired slot binding cannot be staged: %w", device.ErrConflict)
				}
				if record.Handle.Binding.Generation > newest {
					newest = record.Handle.Binding.Generation
				}
			}
			if item.Name() == "A" || item.Name() == "B" {
				slot, err := subdirectory(s.root, item.Name())
				if err != nil {
					return err
				}
				h, _, err := s.slotSigner(slot)
				slot.Close()
				if err != nil {
					return err
				}
				if h.Binding.DeviceID != binding.DeviceID {
					return fmt.Errorf("slot belongs to another device: %w", device.ErrConflict)
				}
				if h.Binding.Generation > newest {
					newest = h.Binding.Generation
				}
			}
		}
		if slot, err := subdirectory(s.root, binding.Slot); err == nil {
			defer slot.Close()
			h, _, err := s.slotSigner(slot)
			if err != nil {
				return err
			}
			if h.Binding != binding {
				return fmt.Errorf("occupied slot requires intervention: %w", device.ErrConflict)
			}
			result = h
			for _, name := range []string{"key.pem", "manifest.json", "binding.json", "csr.pem", "public-snapshot.json", "certificate.pem"} {
				if _, err := slot.Lstat(name); os.IsNotExist(err) && (name == "csr.pem" || name == "public-snapshot.json" || name == "certificate.pem") {
					continue
				}
				if err := syncFile(slot, name); err != nil {
					return err
				}
			}
			if err := syncDir(slot); err != nil {
				return err
			}
			return syncDir(s.root)
		} else if !os.IsNotExist(err) {
			return err
		}
		pending := ".stage-" + binding.Slot + "-" + binding.DeviceID + "-" + binding.OperationID
		for _, item := range items {
			if (strings.HasPrefix(item.Name(), ".stage-"+binding.Slot+"-") && item.Name() != pending) || strings.HasPrefix(item.Name(), ".destroy-"+binding.Slot+"-") {
				return fmt.Errorf("orphan slot work requires intervention: %w", device.ErrConflict)
			}
		}
		if binding.Generation <= newest {
			return fmt.Errorf("new slot must use a fresh generation: %w", device.ErrConflict)
		}
		s.at("stage-precreate")
		if err := s.root.Mkdir(pending, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
		slot, err := subdirectory(s.root, pending)
		if err != nil {
			return err
		}
		defer slot.Close()
		result, err = s.stageSlot(slot, binding)
		if err != nil {
			return err
		}
		s.at("stage-directory")
		if err := s.root.Rename(pending, binding.Slot); err != nil {
			return err
		}
		s.at("stage-rename")
		if err := syncDir(s.root); err != nil {
			return err
		}
		s.at("stage-parent")
		return nil
	})
	return result, err
}

func (s *Store) bindDevice(deviceID string) error {
	data, err := readFile(s.root, ".device.json")
	if err == nil {
		var stored identity
		if decodeJSON(data, &stored) != nil || stored.SchemaVersion != s.scope.SchemaVersion || stored.DeviceID != deviceID || !s.scope.matches(stored) {
			return fmt.Errorf("key store is bound to another device: %w", device.ErrConflict)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	items, err := entries(s.root)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Name() == "A" || item.Name() == "B" || item.Name() == "active.json" || strings.HasPrefix(item.Name(), ".stage-") || strings.HasPrefix(item.Name(), ".destroy-") || strings.HasPrefix(item.Name(), ".retired-") {
			return fmt.Errorf("existing material has no durable device binding: %w", device.ErrConflict)
		}
	}
	stored := s.scope
	stored.DeviceID = deviceID
	data, _ = json.Marshal(stored)
	if err := pendingFile(s.root, ".device.pending", data); err != nil {
		return err
	}
	if err := s.root.Rename(".device.pending", ".device.json"); err != nil {
		return err
	}
	return syncDir(s.root)
}

func (s *Store) stageSlot(root *os.Root, binding device.Binding) (device.Handle, error) {
	data, err := readFile(root, "binding.json")
	if os.IsNotExist(err) {
		items, err := entries(root)
		if err != nil || len(items) != 0 {
			return device.Handle{}, fmt.Errorf("unbound staged material requires intervention: %w", device.ErrConflict)
		}
		data, _ = json.Marshal(bindingIntent{SchemaVersion: s.scope.SchemaVersion, Binding: binding})
		if err := writeFile(root, "binding.json", data); err != nil {
			return device.Handle{}, err
		}
		if err := syncDir(root); err != nil {
			return device.Handle{}, err
		}
		if err := syncDir(s.root); err != nil {
			return device.Handle{}, err
		}
		s.at("stage-binding")
	} else if err != nil {
		return device.Handle{}, err
	}
	var intent bindingIntent
	if decodeJSON(data, &intent) != nil || intent.SchemaVersion != s.scope.SchemaVersion || intent.Binding != binding {
		return device.Handle{}, fmt.Errorf("staged binding requires intervention: %w", device.ErrConflict)
	}
	if _, err := root.Lstat("manifest.json"); err == nil {
		h, _, err := s.slotSigner(root)
		if err != nil || h.Binding != binding {
			return device.Handle{}, fmt.Errorf("staged manifest requires intervention: %w", device.ErrConflict)
		}
		return h, syncDir(root)
	} else if !os.IsNotExist(err) {
		return device.Handle{}, err
	}
	keyData, err := readFile(root, "key.pem")
	if os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return device.Handle{}, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return device.Handle{}, err
		}
		keyData = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		if err := writeFile(root, "key.pem", keyData); err != nil {
			return device.Handle{}, err
		}
		s.at("stage-key")
	} else if err != nil {
		return device.Handle{}, err
	}
	signer, err := parseSigner(keyData)
	if err != nil {
		return device.Handle{}, fmt.Errorf("incomplete staged key requires intervention: %w", device.ErrConflict)
	}
	digest, err := fingerprint(signer)
	if err != nil {
		return device.Handle{}, err
	}
	h := device.Handle{Binding: binding, PublicKeyDigest: digest}
	data, _ = json.Marshal(manifest{SchemaVersion: s.scope.SchemaVersion, Handle: h})
	if err := writeFile(root, "manifest.json", data); err != nil {
		return device.Handle{}, err
	}
	s.at("stage-manifest")
	return h, syncDir(root)
}

func (s *Store) slotSigner(root *os.Root) (device.Handle, crypto.Signer, error) {
	data, err := readFile(root, "manifest.json")
	if err != nil {
		return device.Handle{}, nil, fmt.Errorf("slot manifest requires reconciliation: %w", err)
	}
	var m manifest
	if err := decodeJSON(data, &m); err != nil || m.SchemaVersion != s.scope.SchemaVersion || m.Handle.Validate() != nil || s.validateBinding(m.Handle.Binding) != nil {
		return device.Handle{}, nil, fmt.Errorf("invalid or unsupported slot manifest")
	}
	intentData, err := readFile(root, "binding.json")
	if err != nil {
		return device.Handle{}, nil, err
	}
	var intent bindingIntent
	if decodeJSON(intentData, &intent) != nil || intent.SchemaVersion != s.scope.SchemaVersion || intent.Binding != m.Handle.Binding {
		return device.Handle{}, nil, fmt.Errorf("slot binding intent does not match immutable manifest")
	}
	key, err := readFile(root, "key.pem")
	if err != nil {
		return device.Handle{}, nil, err
	}
	signer, err := parseSigner(key)
	if err != nil {
		return device.Handle{}, nil, err
	}
	digest, err := fingerprint(signer)
	if err != nil || digest != m.Handle.PublicKeyDigest {
		return device.Handle{}, nil, fmt.Errorf("slot key does not match immutable manifest")
	}
	if err := s.validatePublicArtifacts(root, m.Handle, signer); err != nil {
		return device.Handle{}, nil, err
	}
	return m.Handle, signer, nil
}

func (s *Store) slot(h device.Handle) (*os.Root, crypto.Signer, error) {
	if err := h.Validate(); err != nil {
		return nil, nil, err
	}
	data, err := readFile(s.root, ".device.json")
	if err != nil {
		return nil, nil, fmt.Errorf("key-store identity requires reconciliation: %w", err)
	}
	var stored identity
	if decodeJSON(data, &stored) != nil || stored.SchemaVersion != s.scope.SchemaVersion || stored.DeviceID != h.Binding.DeviceID || !s.scope.matches(stored) || s.validateBinding(h.Binding) != nil {
		return nil, nil, fmt.Errorf("key-store identity does not match handle: %w", device.ErrConflict)
	}
	root, err := subdirectory(s.root, h.Binding.Slot)
	if err != nil {
		return nil, nil, err
	}
	actual, signer, err := s.slotSigner(root)
	if err != nil || actual != h {
		root.Close()
		return nil, nil, fmt.Errorf("slot does not match requested immutable handle: %w", device.ErrConflict)
	}
	return root, signer, nil
}

func (s *Store) Signer(ctx context.Context, h device.Handle) (crypto.Signer, error) {
	var signer crypto.Signer
	err := s.locked(ctx, false, func() error {
		root, loaded, err := s.slot(h)
		if err != nil {
			return err
		}
		root.Close()
		signer = loaded
		return nil
	})
	return signer, err
}

func (s *Store) Certificate(ctx context.Context, h device.Handle) ([]byte, error) {
	var data []byte
	err := s.locked(ctx, false, func() error {
		root, signer, err := s.slot(h)
		if err != nil {
			return err
		}
		defer root.Close()
		data, err = readFile(root, "certificate.pem")
		if err != nil {
			return err
		}
		return s.validateCertificate(root, data, h, signer, false)
	})
	return data, err
}

func pendingFile(root *os.Root, name string, data []byte) error {
	existing, err := readFile(root, name)
	if err == nil {
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("incomplete or incompatible pending artifact requires intervention: %w", device.ErrConflict)
		}
		f, err := openFile(root, name, os.O_RDONLY)
		if err != nil {
			return err
		}
		return errorsWithClose(f.Sync(), f.Close())
	}
	if !os.IsNotExist(err) {
		return err
	}
	return writeFile(root, name, data)
}

func (s *Store) StoreCertificate(ctx context.Context, h device.Handle, data []byte) error {
	if len(data) == 0 || len(data) > credentialprofile.MaxChainSize {
		return fmt.Errorf("invalid public certificate chain size")
	}
	data = append([]byte(nil), data...)
	return s.locked(ctx, true, func() error {
		root, signer, err := s.slot(h)
		if err != nil {
			return err
		}
		defer root.Close()
		if err := s.validateCertificate(root, data, h, signer, false); err != nil {
			return err
		}
		if err := s.checkCertificateRecord(root, h, data); err != nil {
			return err
		}
		if existing, err := readFile(root, "certificate.pem"); err == nil {
			if !bytes.Equal(existing, data) {
				return fmt.Errorf("slot certificate is immutable: %w", device.ErrConflict)
			}
			if err := syncFile(root, "certificate.pem"); err != nil {
				return err
			}
			return syncDir(root)
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := pendingFile(root, ".certificate.pending", data); err != nil {
			return err
		}
		s.at("cert-file")
		if err := s.recordCertificate(root, h, data); err != nil {
			return err
		}
		if err := root.Rename(".certificate.pending", "certificate.pem"); err != nil {
			return err
		}
		s.at("cert-rename")
		if err := syncDir(root); err != nil {
			return err
		}
		s.at("cert-parent")
		return nil
	})
}

func (s *Store) active() (*device.Handle, error) {
	data, err := readFile(s.root, "active.json")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pointer activePointer
	if err := decodeJSON(data, &pointer); err != nil || pointer.SchemaVersion != s.scope.SchemaVersion || pointer.Handle.Validate() != nil {
		return nil, fmt.Errorf("invalid or unsupported active pointer")
	}
	root, signer, err := s.slot(pointer.Handle)
	if err != nil {
		return nil, fmt.Errorf("active pointer requires reconciliation: %w", err)
	}
	defer root.Close()
	chain, err := readFile(root, "certificate.pem")
	if err != nil {
		return nil, fmt.Errorf("active certificate requires reconciliation: %w", err)
	}
	if err := s.validateCertificate(root, chain, pointer.Handle, signer, false); err != nil {
		return nil, err
	}
	return &pointer.Handle, nil
}

func (s *Store) Active(ctx context.Context) (*device.Handle, error) {
	var h *device.Handle
	err := s.locked(ctx, false, func() error {
		var err error
		h, err = s.active()
		return err
	})
	return h, err
}

func (s *Store) Activate(ctx context.Context, h device.Handle) error {
	if s.scope.SchemaVersion == 2 {
		return fmt.Errorf("version-two activation requires a fresh clock assessment: %w", device.ErrDenied)
	}
	return s.activate(ctx, h, time.Time{}, time.Time{})
}

// ActivateV2 checks the complete assessed interval and activation lifetime margin.
func (s *Store) ActivateV2(ctx context.Context, h device.Handle, earliest, latest time.Time) error {
	if s.scope.SchemaVersion != 2 {
		return fmt.Errorf("version-two activation requires a version-two store: %w", device.ErrUnsupported)
	}
	return s.activate(ctx, h, earliest, latest)
}

func (s *Store) activate(ctx context.Context, h device.Handle, earliest, latest time.Time) error {
	return s.locked(ctx, true, func() error {
		root, signer, err := s.slot(h)
		if err != nil {
			return err
		}
		defer root.Close()
		chain, err := readFile(root, "certificate.pem")
		if err != nil {
			return err
		}
		if s.scope.SchemaVersion == 2 {
			err = s.validateCertificateAt(root, chain, h, signer, earliest, latest, false)
		} else {
			err = s.validateCertificate(root, chain, h, signer, true)
		}
		if err != nil {
			return err
		}
		active, err := s.active()
		if err != nil {
			return err
		}
		if active != nil {
			if *active == h {
				if err := syncFile(s.root, "active.json"); err != nil {
					return err
				}
				return syncDir(s.root)
			}
			if active.Binding.DeviceID != h.Binding.DeviceID || active.Binding.Generation >= h.Binding.Generation {
				return fmt.Errorf("active pointer cannot regress or change device: %w", device.ErrConflict)
			}
		}
		data, _ := json.Marshal(activePointer{SchemaVersion: s.scope.SchemaVersion, Handle: h})
		if err := pendingFile(s.root, ".active.pending", data); err != nil {
			return err
		}
		s.at("active-file")
		if err := s.root.Rename(".active.pending", "active.json"); err != nil {
			return err
		}
		s.at("active-rename")
		if err := syncDir(s.root); err != nil {
			return err
		}
		s.at("active-parent")
		return nil
	})
}

func (s *Store) Destroy(ctx context.Context, h device.Handle) error {
	if err := h.Validate(); err != nil {
		return err
	}
	return s.locked(ctx, true, func() error {
		active, err := s.active()
		if err != nil {
			return err
		}
		if active != nil && *active == h {
			return fmt.Errorf("active signer cannot be destroyed: %w", device.ErrDenied)
		}
		name := ".destroy-" + h.Binding.Slot + "-" + h.Binding.OperationID + "-" + h.PublicKeyDigest
		receiptName := ".retired-" + h.Binding.Slot + "-" + h.Binding.OperationID + "-" + h.PublicKeyDigest + ".json"
		record := destruction{SchemaVersion: s.scope.SchemaVersion, Handle: h}
		data, receiptErr := readFile(s.root, receiptName)
		if receiptErr == nil {
			if decodeJSON(data, &record) != nil || record.SchemaVersion != s.scope.SchemaVersion || record.Handle != h || s.validateBinding(h.Binding) != nil {
				return fmt.Errorf("destruction record does not match handle: %w", device.ErrConflict)
			}
			if record.Complete {
				if err := syncFile(s.root, receiptName); err != nil {
					return err
				}
				return syncDir(s.root)
			}
		} else if !os.IsNotExist(receiptErr) {
			return receiptErr
		}
		if root, _, err := s.slot(h); err == nil {
			root.Close()
			if os.IsNotExist(receiptErr) {
				data, _ := json.Marshal(record)
				if err := writeFile(s.root, receiptName, data); err != nil {
					return err
				}
				if err := syncDir(s.root); err != nil {
					return err
				}
				s.at("destroy-intent")
			}
			if _, err := s.root.Lstat(name); err == nil {
				return fmt.Errorf("slot and destruction record both exist: %w", device.ErrConflict)
			} else if !os.IsNotExist(err) {
				return err
			}
			if err := s.root.Rename(h.Binding.Slot, name); err != nil {
				return err
			}
			s.at("destroy-rename")
			if err := syncDir(s.root); err != nil {
				return err
			}
			s.at("destroy-parent")
		} else if !os.IsNotExist(err) {
			return err
		} else if os.IsNotExist(receiptErr) {
			return fmt.Errorf("missing slot has no durable destruction binding: %w", device.ErrConflict)
		}
		root, err := subdirectory(s.root, name)
		if os.IsNotExist(err) {
			return s.completeDestruction(receiptName, record)
		}
		if err != nil {
			return err
		}
		defer root.Close()
		items, err := entries(root)
		if err != nil {
			return err
		}
		for _, item := range items {
			if item.Name() != "key.pem" && item.Name() != "certificate.pem" && item.Name() != "manifest.json" && item.Name() != "binding.json" && item.Name() != ".certificate.pending" && item.Name() != "csr.pem" && item.Name() != ".csr.pending" && item.Name() != "public-snapshot.json" && item.Name() != ".snapshot.pending" && item.Name() != "csr-binding.json" && item.Name() != "certificate-binding.json" {
				return fmt.Errorf("unknown destruction artifact requires intervention")
			}
			info, err := root.Lstat(item.Name())
			if err != nil {
				return err
			}
			if err := owned(info, false); err != nil {
				return err
			}
		}
		if data, err := readFile(root, "manifest.json"); err == nil {
			var m manifest
			if decodeJSON(data, &m) != nil || m.SchemaVersion != s.scope.SchemaVersion || m.Handle != h {
				return fmt.Errorf("destruction manifest does not match handle: %w", device.ErrConflict)
			}
		} else if !os.IsNotExist(err) || len(items) != 0 {
			return fmt.Errorf("destruction record requires intervention: %w", device.ErrConflict)
		}
		// Keep the immutable binding until private/public artifacts are gone.
		for _, file := range []string{"key.pem", "certificate.pem", ".certificate.pending", "csr.pem", ".csr.pending", "public-snapshot.json", ".snapshot.pending", "csr-binding.json", "certificate-binding.json", "binding.json"} {
			if err := root.Remove(file); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if err := syncDir(root); err != nil {
			return err
		}
		s.at("destroy-key")
		if err := root.Remove("manifest.json"); err != nil && !os.IsNotExist(err) {
			return err
		}
		s.at("destroy-manifest")
		if err := s.root.Remove(name); err != nil {
			return err
		}
		if err := syncDir(s.root); err != nil {
			return err
		}
		return s.completeDestruction(receiptName, record)
	})
}

func (s *Store) completeDestruction(name string, record destruction) error {
	record.Complete = true
	data, _ := json.Marshal(record)
	if err := pendingFile(s.root, name+".pending", data); err != nil {
		return err
	}
	if err := s.root.Rename(name+".pending", name); err != nil {
		return err
	}
	if err := syncDir(s.root); err != nil {
		return err
	}
	s.at("destroy-complete")
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	if s.lock != nil {
		errs = append(errs, s.lock.Close())
	}
	if s.root != nil {
		errs = append(errs, s.root.Close())
	}
	return errors.Join(errs...)
}

var _ device.KeyStore = (*Store)(nil)
