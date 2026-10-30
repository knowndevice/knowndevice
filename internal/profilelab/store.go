// SPDX-License-Identifier: Apache-2.0

// Package profilelab runs the generated-data credential-profile services.
package profilelab

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
	_ "modernc.org/sqlite"
)

type reservation struct {
	Plan           device.Plan                 `json:"plan"`
	CSR            []byte                      `json:"csr"`
	SPKI           []byte                      `json:"spki"`
	Candidate      device.CredentialBinding    `json:"candidate"`
	Expected       *device.CredentialBinding   `json:"expected,omitempty"`
	Revision       uint64                      `json:"revision"`
	IssueSent      bool                        `json:"issueSent"`
	IssueEarliest  time.Time                   `json:"issueEarliest"`
	IssueLatest    time.Time                   `json:"issueLatest"`
	Certificate    []byte                      `json:"certificate,omitempty"`
	Issuer         string                      `json:"issuer,omitempty"`
	Serial         string                      `json:"serial,omitempty"`
	NotBefore      time.Time                   `json:"notBefore,omitempty"`
	NotAfter       time.Time                   `json:"notAfter,omitempty"`
	Registered     bool                        `json:"registered"`
	Activated      bool                        `json:"activated"`
	Application    *device.ApplicationEvidence `json:"application,omitempty"`
	Withdrawal     *device.WithdrawalEvidence  `json:"withdrawal,omitempty"`
	RevocationSent bool                        `json:"revocationSent"`
	Revoked        bool                        `json:"revoked"`
	Finished       bool                        `json:"finished"`
}

type registry struct {
	DeploymentID            string                    `json:"deploymentId"`
	DeviceID                string                    `json:"deviceId"`
	Status                  string                    `json:"status"`
	Revision                uint64                    `json:"revision"`
	Counter                 uint64                    `json:"counter"`
	RecoveryFingerprint     string                    `json:"recoveryFingerprint"`
	RecoveryPublicKeyDigest string                    `json:"recoveryPublicKeyDigest"`
	SnapshotDigest          string                    `json:"snapshotDigest"`
	Active                  *device.CredentialBinding `json:"active,omitempty"`
	ClockFloor              time.Time                 `json:"clockFloor"`
}

type store struct {
	db       *sql.DB
	root     *os.Root
	lock     *os.File
	lockInfo os.FileInfo
	scope    registry
}

func openStore(path string, initial registry) (_ *store, err error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("profile registry requires a private owned directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	s := &store{root: root, scope: initial}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	for _, name := range []string{"writer.lock", "registry.db", "registry.db-wal", "registry.db-shm"} {
		if i, e := root.Lstat(name); e == nil {
			if !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0077 != 0 {
				return nil, fmt.Errorf("unsafe profile registry artifact")
			}
		} else if !os.IsNotExist(e) {
			return nil, e
		}
	}
	if _, e := root.Lstat("registry.db-wal"); e == nil {
		if _, e := root.Lstat("registry.db-shm"); e != nil {
			return nil, fmt.Errorf("registry WAL without shared-memory sidecar requires intervention")
		}
	}
	s.lock, err = root.OpenFile("writer.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, device.ErrConflict
	}
	s.lockInfo, err = s.lock.Stat()
	if err != nil {
		return nil, err
	}
	_, statErr := root.Lstat("registry.db")
	fresh := os.IsNotExist(statErr)
	if statErr != nil && !fresh {
		return nil, statErr
	}
	if fresh {
		f, e := root.OpenFile("registry.db", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if e != nil {
			return nil, e
		}
		if e = f.Sync(); e != nil {
			f.Close()
			return nil, e
		}
		if e = f.Close(); e != nil {
			return nil, e
		}
		if e = syncDirectory(root); e != nil {
			return nil, e
		}
	}
	databasePath, err := filepath.Abs(filepath.Join(path, "registry.db"))
	if err != nil {
		return nil, err
	}
	databaseURL := url.URL{Scheme: "file", Path: filepath.ToSlash(databasePath), RawQuery: "mode=rw"}
	s.db, err = sql.Open("sqlite", databaseURL.String())
	if err != nil {
		return nil, err
	}
	s.db.SetMaxOpenConns(1)
	var version int
	if err = s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if (fresh && version != 0) || (!fresh && version != 2) {
		return nil, fmt.Errorf("profile registry storage version refused without migration")
	}
	if _, err = s.db.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;"); err != nil {
		return nil, err
	}
	if fresh {
		body, e := json.Marshal(initial)
		if e != nil {
			return nil, e
		}
		tx, e := s.db.Begin()
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		if _, e = tx.Exec("CREATE TABLE registry(id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL); CREATE TABLE operations(deployment TEXT NOT NULL,device TEXT NOT NULL,id TEXT NOT NULL,target INTEGER NOT NULL,spki TEXT NOT NULL,finished INTEGER NOT NULL,revision INTEGER NOT NULL,body BLOB NOT NULL,PRIMARY KEY(deployment,device,id),UNIQUE(deployment,device,target),UNIQUE(deployment,device,spki)); CREATE UNIQUE INDEX one_unfinished ON operations(deployment,device) WHERE finished=0; CREATE TABLE challenges(nonce TEXT PRIMARY KEY,deadline TEXT NOT NULL); CREATE TABLE peer_observations(id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,spki TEXT NOT NULL,generation INTEGER NOT NULL,status TEXT NOT NULL); PRAGMA user_version=2;"); e != nil {
			return nil, e
		}
		if _, e = tx.Exec("INSERT INTO registry(id,body) VALUES(1,?)", body); e != nil {
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
	}
	current, e := s.registry(context.Background())
	if e != nil {
		return nil, e
	}
	if current.DeploymentID != initial.DeploymentID || current.DeviceID != initial.DeviceID || current.SnapshotDigest != initial.SnapshotDigest || current.RecoveryFingerprint != initial.RecoveryFingerprint || current.RecoveryPublicKeyDigest != initial.RecoveryPublicKeyDigest {
		return nil, fmt.Errorf("profile registry identity or trust differs; migration refused")
	}
	return s, nil
}

func (s *store) close() {
	if s.db != nil {
		s.db.Close()
	}
	if s.lock != nil {
		syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		s.lock.Close()
	}
	if s.root != nil {
		s.root.Close()
	}
}
func syncDirectory(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (s *store) fence() error {
	i, e := s.root.Lstat("writer.lock")
	if e != nil || !os.SameFile(i, s.lockInfo) {
		return device.ErrConflict
	}
	return nil
}
func decodeBody(b []byte, v any) error { return device.DecodeStrict(bytes.NewReader(b), v) }
func (s *store) registry(ctx context.Context) (registry, error) {
	var r registry
	var b []byte
	e := s.db.QueryRowContext(ctx, "SELECT body FROM registry WHERE id=1").Scan(&b)
	if e == nil {
		e = decodeBody(b, &r)
	}
	return r, e
}
func (s *store) operation(ctx context.Context, p device.Plan) (*reservation, error) {
	var b []byte
	e := s.db.QueryRowContext(ctx, "SELECT body FROM operations WHERE deployment=? AND device=? AND id=?", p.DeploymentID, p.DeviceID, p.OperationID).Scan(&b)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var r reservation
	if e = decodeBody(b, &r); e != nil {
		return nil, e
	}
	if e = s.validateReservation(&r); e != nil {
		return nil, e
	}
	if r.Plan != p {
		return nil, device.ErrConflict
	}
	return &r, nil
}
func (s *store) generation(ctx context.Context, g uint64) (*reservation, error) {
	var b []byte
	e := s.db.QueryRowContext(ctx, "SELECT body FROM operations WHERE target=?", g).Scan(&b)
	if e != nil {
		return nil, e
	}
	var r reservation
	e = decodeBody(b, &r)
	if e == nil {
		e = s.validateReservation(&r)
	}
	return &r, e
}

func (s *store) validateReservation(r *reservation) error {
	p := r.Plan
	if p.Validate(p.ExpiresAt.Add(-time.Nanosecond)) != nil || p.DeploymentID != s.scope.DeploymentID || p.DeviceID != s.scope.DeviceID || p.SnapshotDigest != s.scope.SnapshotDigest || r.Revision == 0 || !r.IssueSent || r.IssueEarliest.IsZero() || r.IssueLatest.Before(r.IssueEarliest) || r.IssueLatest.Sub(r.IssueEarliest) > 2*time.Second || !r.IssueLatest.Before(p.ExpiresAt) {
		return device.ErrConflict
	}
	profile, e := credentialprofile.Resolve(p.ProfileID, p.ProfileVersion, p.ProfileDigest)
	if e != nil {
		return device.ErrConflict
	}
	csr, e := profile.ValidateCSR(r.CSR, p.DeviceID, p.TargetGeneration)
	if e != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, r.SPKI) {
		return device.ErrConflict
	}
	candidate := bound(p, csr)
	candidate.CertificateFingerprint = r.Candidate.CertificateFingerprint
	if candidate != r.Candidate {
		return device.ErrConflict
	}
	if len(r.Certificate) > 0 {
		certs, e := credentialprofile.ParseChain(r.Certificate)
		if e != nil || profile.ValidateLeaf(certs[0], p.DeviceID, p.TargetGeneration) != nil || !bytes.Equal(certs[0].RawSubjectPublicKeyInfo, r.SPKI) || device.Hash(certs[0].Raw) != r.Candidate.CertificateFingerprint || r.Issuer != device.Hash(certs[0].RawIssuer) || r.Serial != certs[0].SerialNumber.String() || r.NotBefore != certs[0].NotBefore || r.NotAfter != certs[0].NotAfter {
			return device.ErrConflict
		}
	} else if r.Candidate.CertificateFingerprint != "" || r.Registered || r.Activated {
		return device.ErrConflict
	}
	return nil
}

func (s *store) challenge(ctx context.Context, nonce string, deadline time.Time) error {
	if e := s.fence(); e != nil {
		return e
	}
	var count int
	if e := s.db.QueryRowContext(ctx, "SELECT count(*) FROM challenges").Scan(&count); e != nil {
		return e
	}
	if count >= 10000 {
		return device.ErrUnsupported
	}
	if _, e := s.db.ExecContext(ctx, "INSERT INTO challenges(nonce,deadline) VALUES(?,?)", nonce, deadline.UTC().Format(time.RFC3339Nano)); e != nil {
		return device.ErrDenied
	}
	return nil
}
func (s *store) observePeer(ctx context.Context, id, fp, spki string, generation uint64, status string) error {
	if e := s.fence(); e != nil {
		return e
	}
	_, e := s.db.ExecContext(ctx, "INSERT INTO peer_observations(id,fingerprint,spki,generation,status) VALUES(?,?,?,?,?)", id, fp, spki, generation, status)
	return e
}

func (s *store) reserve(ctx context.Context, r reservation) (*reservation, error) {
	if e := s.fence(); e != nil {
		return nil, e
	}
	if existing, e := s.operation(ctx, r.Plan); e != nil {
		return nil, e
	} else if existing != nil {
		if !bytes.Equal(existing.CSR, r.CSR) || !bytes.Equal(existing.SPKI, r.SPKI) {
			return nil, device.ErrConflict
		}
		return existing, nil
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var body []byte
	if e = tx.QueryRowContext(ctx, "SELECT body FROM registry WHERE id=1").Scan(&body); e != nil {
		return nil, e
	}
	var reg registry
	if e = decodeBody(body, &reg); e != nil {
		return nil, e
	}
	if reg.Status != "authorized" || reg.DeploymentID != r.Plan.DeploymentID || reg.DeviceID != r.Plan.DeviceID || reg.SnapshotDigest != r.Plan.SnapshotDigest || r.Plan.TargetGeneration <= reg.Counter {
		return nil, device.ErrConflict
	}
	if (reg.Active == nil && r.Plan.ExpectedGeneration != 0) || (reg.Active != nil && reg.Active.Generation != r.Plan.ExpectedGeneration) {
		return nil, device.ErrConflict
	}
	if r.Candidate.PublicKeyDigest == reg.RecoveryPublicKeyDigest {
		return nil, device.ErrDenied
	}
	r.Expected = reg.Active
	r.Revision = 1
	r.IssueSent = true
	now := time.Now().UTC()
	r.IssueEarliest = now.Add(-time.Second)
	r.IssueLatest = now.Add(time.Second)
	if !r.IssueLatest.Before(r.Plan.ExpiresAt) {
		return nil, device.ErrPlanExpired
	}
	body, e = json.Marshal(r)
	if e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO operations(deployment,device,id,target,spki,finished,revision,body) VALUES(?,?,?,?,?,0,1,?)", r.Plan.DeploymentID, r.Plan.DeviceID, r.Plan.OperationID, r.Plan.TargetGeneration, r.Candidate.PublicKeyDigest, body); e != nil {
		return nil, device.ErrConflict
	}
	reg.Counter = r.Plan.TargetGeneration
	reg.Revision++
	body, e = json.Marshal(reg)
	if e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE registry SET body=? WHERE id=1", body); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return &r, nil
}

func (s *store) save(ctx context.Context, r *reservation) error {
	if e := s.fence(); e != nil {
		return e
	}
	revision := r.Revision
	r.Revision++
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	result, e := s.db.ExecContext(ctx, "UPDATE operations SET body=?,revision=?,finished=? WHERE deployment=? AND device=? AND id=? AND revision=?", b, r.Revision, r.Finished, r.Plan.DeploymentID, r.Plan.DeviceID, r.Plan.OperationID, revision)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return device.ErrConflict
	}
	return nil
}

func (s *store) activate(ctx context.Context, r *reservation, a device.ApplicationEvidence) error {
	if e := s.fence(); e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var body []byte
	if e = tx.QueryRowContext(ctx, "SELECT body FROM registry WHERE id=1").Scan(&body); e != nil {
		return e
	}
	var reg registry
	if e = decodeBody(body, &reg); e != nil {
		return e
	}
	if reg.Status != "authorized" {
		return device.ErrDenied
	}
	if r.Activated {
		if reg.Active == nil || *reg.Active != r.Candidate {
			return device.ErrConflict
		}
		return nil
	}
	if (reg.Active == nil) != (r.Expected == nil) || (reg.Active != nil && *reg.Active != *r.Expected) {
		return device.ErrConflict
	}
	revision := r.Revision
	r.Revision++
	r.Activated = true
	r.Application = &a
	if r.Plan.ExpectedGeneration == 0 {
		r.Finished = true
	}
	reg.Active = &r.Candidate
	reg.Revision++
	body, e = json.Marshal(r)
	if e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, "UPDATE operations SET body=?,revision=?,finished=? WHERE deployment=? AND device=? AND id=? AND revision=?", body, r.Revision, r.Finished, r.Plan.DeploymentID, r.Plan.DeviceID, r.Plan.OperationID, revision)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return device.ErrConflict
	}
	body, e = json.Marshal(reg)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE registry SET body=? WHERE id=1", body); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *store) clock(ctx context.Context, earliest time.Time) error {
	if e := s.fence(); e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var old []byte
	if e = tx.QueryRowContext(ctx, "SELECT body FROM registry WHERE id=1").Scan(&old); e != nil {
		return e
	}
	var reg registry
	if e = decodeBody(old, &reg); e != nil {
		return e
	}
	if earliest.Before(reg.ClockFloor) {
		return device.ErrDenied
	}
	reg.ClockFloor = earliest
	reg.Revision++
	b, e := json.Marshal(reg)
	if e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, "UPDATE registry SET body=? WHERE id=1 AND body=?", b, old)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return device.ErrConflict
	}
	return tx.Commit()
}
