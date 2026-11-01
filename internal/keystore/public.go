// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
)

type csrBinding struct {
	SchemaVersion int           `json:"schemaVersion"`
	Handle        device.Handle `json:"handle"`
	CSRDigest     string        `json:"csrDigest"`
}

type certificateBinding struct {
	SchemaVersion          int           `json:"schemaVersion"`
	Handle                 device.Handle `json:"handle"`
	CSRDigest              string        `json:"csrDigest"`
	CertificateFingerprint string        `json:"certificateFingerprint"`
	ChainDigest            string        `json:"chainDigest"`
}

func publicArtifact(root *os.Root, name, pending string, limit int) ([]byte, error) {
	data, err := readFileLimit(root, name, limit)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	incomplete, pendingErr := readFileLimit(root, pending, limit)
	if pendingErr != nil && !os.IsNotExist(pendingErr) {
		return nil, pendingErr
	}
	if err == nil {
		if pendingErr == nil && !bytes.Equal(data, incomplete) {
			return nil, fmt.Errorf("public artifact conflicts with pending data: %w", device.ErrConflict)
		}
		return data, nil
	}
	if pendingErr == nil {
		return incomplete, nil
	}
	return nil, err
}

func (s *Store) policy(h device.Handle) (credentialprofile.Policy, error) {
	return credentialprofile.Resolve(h.Binding.ProfileID, h.Binding.ProfileVersion, h.Binding.ProfileDigest)
}

func (s *Store) validateCSR(data []byte, h device.Handle, signer crypto.Signer) (*x509.CertificateRequest, error) {
	p, err := s.policy(h)
	if err != nil {
		return nil, err
	}
	csr, err := p.ValidateCSR(data, h.Binding.DeviceID, h.Binding.Generation)
	if err != nil {
		return nil, err
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, csr.RawSubjectPublicKeyInfo) || device.Hash(csr.RawSubjectPublicKeyInfo) != h.PublicKeyDigest {
		return nil, fmt.Errorf("original CSR does not match signer/handle SPKI: %w", device.ErrConflict)
	}
	return csr, nil
}

func (s *Store) snapshot(root *os.Root, h device.Handle) (*device.PublicSnapshot, error) {
	data, err := publicArtifact(root, "public-snapshot.json", ".snapshot.pending", device.MaxInput)
	if err != nil {
		return nil, err
	}
	if device.Hash(data) != h.Binding.SnapshotDigest {
		return nil, fmt.Errorf("public snapshot does not match immutable handle: %w", device.ErrConflict)
	}
	snapshot, err := device.DecodeSnapshot(data)
	if err != nil {
		return nil, err
	}
	if err := snapshot.ValidateBinding(h.Binding); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (s *Store) validatePublicArtifacts(root *os.Root, h device.Handle, signer crypto.Signer) error {
	if s.scope.SchemaVersion != 2 {
		return nil
	}
	_, snapshotErr := s.snapshot(root, h)
	if snapshotErr != nil && !os.IsNotExist(snapshotErr) {
		return snapshotErr
	}
	csrData, csrErr := publicArtifact(root, "csr.pem", ".csr.pending", credentialprofile.MaxCSRSize)
	if csrErr != nil && !os.IsNotExist(csrErr) {
		return csrErr
	}
	var csr *x509.CertificateRequest
	if csrErr == nil {
		var err error
		csr, err = s.validateCSR(csrData, h, signer)
		if err != nil {
			return err
		}
	}
	data, recordErr := readFile(root, "csr-binding.json")
	if recordErr == nil {
		var record csrBinding
		if decodeJSON(data, &record) != nil || record.SchemaVersion != 2 || record.Handle != h || !validDigest(record.CSRDigest) || (csr != nil && record.CSRDigest != device.Hash(csr.Raw)) {
			return fmt.Errorf("original CSR differs from durable public binding: %w", device.ErrConflict)
		}
	} else if !os.IsNotExist(recordErr) {
		return recordErr
	} else if _, err := root.Lstat("csr.pem"); err == nil {
		return fmt.Errorf("original CSR has no durable digest binding: %w", device.ErrConflict)
	} else if !os.IsNotExist(err) {
		return err
	}
	chain, chainErr := publicArtifact(root, "certificate.pem", ".certificate.pending", credentialprofile.MaxChainSize)
	if chainErr != nil && !os.IsNotExist(chainErr) {
		return chainErr
	}
	if chainErr == nil {
		if csrErr != nil || snapshotErr != nil || recordErr != nil {
			return fmt.Errorf("certificate requires original CSR and public snapshot: %w", device.ErrConflict)
		}
		if err := s.validateCertificate(root, chain, h, signer, false); err != nil {
			return err
		}
	}
	data, err := readFile(root, "certificate-binding.json")
	if err == nil {
		var record certificateBinding
		if decodeJSON(data, &record) != nil || record.SchemaVersion != 2 || record.Handle != h || csr == nil || record.CSRDigest != device.Hash(csr.Raw) || !validDigest(record.CertificateFingerprint) || !validDigest(record.ChainDigest) {
			return fmt.Errorf("certificate record differs from original CSR/handle: %w", device.ErrConflict)
		}
		if chainErr == nil {
			certs, err := credentialprofile.ParseChain(chain)
			if err != nil || record.CertificateFingerprint != device.Hash(certs[0].Raw) || record.ChainDigest != device.Hash(chain) {
				return fmt.Errorf("certificate differs from immutable leaf binding: %w", device.ErrConflict)
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	} else if _, err := root.Lstat("certificate.pem"); err == nil {
		return fmt.Errorf("certificate has no durable fingerprint binding: %w", device.ErrConflict)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// StoreCSR preserves the original signed CSR, including an interrupted sync/rename.
func (s *Store) StoreCSR(ctx context.Context, h device.Handle, data []byte) error {
	if len(data) == 0 || len(data) > credentialprofile.MaxCSRSize {
		return fmt.Errorf("invalid original CSR size")
	}
	data = append([]byte(nil), data...)
	if s.scope.SchemaVersion != 2 {
		return fmt.Errorf("legacy slots do not persist profile-aware CSR artifacts: %w", device.ErrUnsupported)
	}
	return s.locked(ctx, true, func() error {
		root, signer, err := s.slot(h)
		if err != nil {
			return err
		}
		defer root.Close()
		csr, err := s.validateCSR(data, h, signer)
		if err != nil {
			return err
		}
		record, _ := json.Marshal(csrBinding{SchemaVersion: 2, Handle: h, CSRDigest: device.Hash(csr.Raw)})
		if err := checkImmutableRecord(root, "csr-binding.json", record); err != nil {
			return err
		}
		if existing, err := publicArtifact(root, "csr.pem", ".csr.pending", credentialprofile.MaxCSRSize); err == nil {
			if !bytes.Equal(existing, data) {
				return fmt.Errorf("original CSR is immutable: %w", device.ErrConflict)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := pendingFile(root, ".csr.pending", data); err != nil {
			return err
		}
		s.at("csr-file")
		if err := pendingFile(root, "csr-binding.json", record); err != nil {
			return err
		}
		s.at("csr-binding")
		if err := root.Rename(".csr.pending", "csr.pem"); err != nil {
			return err
		}
		s.at("csr-rename")
		if err := syncDir(root); err != nil {
			return err
		}
		s.at("csr-parent")
		return nil
	})
}

// CSR returns persisted original bytes; an uncertain pending CSR is never re-signed.
func (s *Store) CSR(ctx context.Context, h device.Handle) ([]byte, error) {
	if s.scope.SchemaVersion != 2 {
		return nil, fmt.Errorf("legacy slots have no profile-aware CSR artifact: %w", device.ErrUnsupported)
	}
	var data []byte
	err := s.locked(ctx, false, func() error {
		root, _, err := s.slot(h)
		if err != nil {
			return err
		}
		defer root.Close()
		data, err = publicArtifact(root, "csr.pem", ".csr.pending", credentialprofile.MaxCSRSize)
		if os.IsNotExist(err) {
			if _, recordErr := root.Lstat("csr-binding.json"); recordErr == nil {
				return fmt.Errorf("original CSR is missing but remains reserved: %w", device.ErrConflict)
			} else if !os.IsNotExist(recordErr) {
				return recordErr
			}
		}
		return err
	})
	return data, err
}

// StoreSnapshot persists the exact public trust bytes named by the plan/handle.
func (s *Store) StoreSnapshot(ctx context.Context, h device.Handle, data []byte) error {
	if len(data) == 0 || len(data) > device.MaxInput {
		return fmt.Errorf("invalid public snapshot size")
	}
	data = append([]byte(nil), data...)
	if s.scope.SchemaVersion != 2 {
		return fmt.Errorf("legacy slots do not persist profile-aware trust snapshots: %w", device.ErrUnsupported)
	}
	return s.locked(ctx, true, func() error {
		root, _, err := s.slot(h)
		if err != nil {
			return err
		}
		defer root.Close()
		if device.Hash(data) != h.Binding.SnapshotDigest {
			return fmt.Errorf("snapshot digest does not match slot binding: %w", device.ErrConflict)
		}
		snapshot, err := device.DecodeSnapshot(data)
		if err != nil {
			return err
		}
		if err := snapshot.ValidateBinding(h.Binding); err != nil {
			return err
		}
		if existing, err := publicArtifact(root, "public-snapshot.json", ".snapshot.pending", device.MaxInput); err == nil {
			if !bytes.Equal(existing, data) {
				return fmt.Errorf("public snapshot is immutable: %w", device.ErrConflict)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := pendingFile(root, ".snapshot.pending", data); err != nil {
			return err
		}
		s.at("snapshot-file")
		if err := root.Rename(".snapshot.pending", "public-snapshot.json"); err != nil {
			return err
		}
		s.at("snapshot-rename")
		if err := syncDir(root); err != nil {
			return err
		}
		s.at("snapshot-parent")
		return nil
	})
}

func (s *Store) validateCertificate(root *os.Root, data []byte, h device.Handle, signer crypto.Signer, current bool) error {
	if s.scope.SchemaVersion != 2 {
		return validateCertificate(data, h, signer, current)
	}
	return s.validateCertificateAt(root, data, h, signer, time.Time{}, time.Time{}, true)
}

func (s *Store) validateCertificateAt(root *os.Root, data []byte, h device.Handle, signer crypto.Signer, earliest, latest time.Time, historical bool) error {
	snapshot, err := s.snapshot(root, h)
	if err != nil {
		return err
	}
	csrData, err := publicArtifact(root, "csr.pem", ".csr.pending", credentialprofile.MaxCSRSize)
	if err != nil {
		return err
	}
	if _, err := s.validateCSR(csrData, h, signer); err != nil {
		return err
	}
	csrRecord, err := readFile(root, "csr-binding.json")
	if err != nil {
		return fmt.Errorf("certificate requires a durable original CSR record: %w", err)
	}
	var recorded csrBinding
	csr, err := snapshot.Profile.ValidateCSR(csrData, h.Binding.DeviceID, h.Binding.Generation)
	if err != nil || decodeJSON(csrRecord, &recorded) != nil || recorded.SchemaVersion != 2 || recorded.Handle != h || recorded.CSRDigest != device.Hash(csr.Raw) {
		return fmt.Errorf("certificate original CSR record does not match handle: %w", device.ErrConflict)
	}
	certs, err := credentialprofile.ParseChain(data)
	if err != nil {
		return err
	}
	if historical {
		// Historical path validation grants artifact binding only. It does not
		// make an expired previous generation usable for any protected action.
		earliest = certs[0].NotBefore.Add(certs[0].NotAfter.Sub(certs[0].NotBefore) / 2)
		latest = earliest
	} else if earliest.IsZero() || latest.Before(earliest) || latest.Sub(earliest) > 2*time.Duration(snapshot.Limits.MaximumUncertaintyMillis)*time.Millisecond {
		return fmt.Errorf("activation requires a bounded trusted time interval: %w", device.ErrDenied)
	}
	v, err := snapshot.Validation(earliest, latest, !historical, historical)
	if err != nil {
		return err
	}
	return snapshot.Profile.ValidateChain(data, csrData, h.PublicKeyDigest, h.Binding.DeviceID, h.Binding.Generation, v)
}

func checkImmutableRecord(root *os.Root, name string, data []byte) error {
	stored, err := readFile(root, name)
	if err == nil {
		if !bytes.Equal(stored, data) {
			return fmt.Errorf("public artifact differs from immutable digest record: %w", device.ErrConflict)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (s *Store) certificateRecord(root *os.Root, h device.Handle, data []byte) ([]byte, error) {
	if s.scope.SchemaVersion != 2 {
		return nil, nil
	}
	csrData, err := publicArtifact(root, "csr.pem", ".csr.pending", credentialprofile.MaxCSRSize)
	if err != nil {
		return nil, err
	}
	p, err := s.policy(h)
	if err != nil {
		return nil, err
	}
	csr, err := p.ValidateCSR(csrData, h.Binding.DeviceID, h.Binding.Generation)
	if err != nil {
		return nil, err
	}
	certs, err := credentialprofile.ParseChain(data)
	if err != nil {
		return nil, err
	}
	record, _ := json.Marshal(certificateBinding{SchemaVersion: 2, Handle: h, CSRDigest: device.Hash(csr.Raw), CertificateFingerprint: device.Hash(certs[0].Raw), ChainDigest: device.Hash(data)})
	return record, nil
}

func (s *Store) checkCertificateRecord(root *os.Root, h device.Handle, data []byte) error {
	record, err := s.certificateRecord(root, h, data)
	if err != nil || record == nil {
		return err
	}
	return checkImmutableRecord(root, "certificate-binding.json", record)
}

func (s *Store) recordCertificate(root *os.Root, h device.Handle, data []byte) error {
	record, err := s.certificateRecord(root, h, data)
	if err != nil || record == nil {
		return err
	}
	if err := pendingFile(root, "certificate-binding.json", record); err != nil {
		return err
	}
	s.at("cert-binding")
	return nil
}
