// SPDX-License-Identifier: Apache-2.0

// Package journal persists one device snapshot with a process lock and writer fence.
package journal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/knowndevice/knowndevice/internal/device"
	_ "modernc.org/sqlite"
)

const schemaVersion = 1
const profileSchemaVersion = 2
const maxCounter = uint64(1<<53 - 1)

// Store owns a stable-inode lock until Close. All snapshots carry its durable fence.
type Store struct {
	mu       sync.Mutex
	db       *sql.DB
	root     *os.Root
	lock     *os.File
	lockInfo os.FileInfo
	dbInfo   os.FileInfo
	name     string
	deviceID string
	scope    storageScope
	fence    uint64
	closed   bool
	writeErr error
}

// Open creates or reconciles a version-one journal and reserves a new writer fence.
func Open(ctx context.Context, path, deviceID string) (_ *Store, err error) {
	return open(ctx, path, storageScope{SchemaVersion: schemaVersion, DeviceID: deviceID})
}

// OpenV2 creates or reconciles an explicitly profile-bound version-two journal.
// Existing legacy identities require a separately reviewed migration.
func OpenV2(ctx context.Context, path, deploymentID, deviceID, profileID string, profileVersion int, profileDigest string) (*Store, error) {
	scope := storageScope{SchemaVersion: profileSchemaVersion, DeploymentID: deploymentID, DeviceID: deviceID, ProfileID: profileID, ProfileVersion: profileVersion, ProfileDigest: profileDigest}
	if err := scope.validate(); err != nil {
		return nil, err
	}
	return open(ctx, path, scope)
}

func open(ctx context.Context, path string, scope storageScope) (_ *Store, err error) {
	deviceID := scope.DeviceID
	if !device.ValidDeviceID(deviceID) || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return nil, fmt.Errorf("invalid journal device or path")
	}
	parent, root, err := directory(filepath.Dir(path), true)
	if err != nil {
		return nil, err
	}
	s := &Store{root: root, name: filepath.Base(path), deviceID: deviceID, scope: scope}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	// Reject a newer header before creating the lock or opening SQLite. A WAL
	// may carry a later header, so the SQL version is checked again below.
	if err = checkHeaderVersion(root, s.name, scope.SchemaVersion); err != nil {
		return nil, err
	}
	if err = preflightScope(ctx, root, filepath.Join(parent, s.name), s.name, scope); err != nil {
		return nil, err
	}
	s.lock, err = regular(root, s.name+".lock", os.O_RDWR, true)
	if err != nil {
		return nil, fmt.Errorf("open journal lock: %w", err)
	}
	if err = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("journal already has a writer: %w", device.ErrConflict)
	}
	s.lockInfo, err = s.lock.Stat()
	if err != nil {
		return nil, err
	}
	f, err := regular(root, s.name, os.O_RDWR, true)
	if err != nil {
		return nil, fmt.Errorf("open journal file: %w", err)
	}
	s.dbInfo, err = f.Stat()
	f.Close()
	if err != nil {
		return nil, err
	}
	if err = checkSidecars(root, s.name); err != nil {
		return nil, err
	}
	if err = preflightScope(ctx, root, filepath.Join(parent, s.name), s.name, scope); err != nil {
		return nil, err
	}
	s.db, err = connect(filepath.Join(parent, s.name), false, false)
	if err != nil {
		return nil, err
	}
	var version int
	if err = s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version != 0 && version != scope.SchemaVersion {
		return nil, fmt.Errorf("unsupported journal schema %d: %w", version, device.ErrUnsupported)
	}
	if version == 0 {
		var tables int
		if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
			return nil, err
		}
		if tables != 0 {
			return nil, fmt.Errorf("unversioned journal contains unknown tables: %w", device.ErrUnsupported)
		}
	} else {
		state, e := load(ctx, s.db)
		if e != nil {
			return nil, e
		}
		if e = validateScopedState(state, scope); e != nil {
			return nil, e
		}
	}
	var mode string
	if err = s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		return nil, err
	}
	if mode != "wal" {
		return nil, fmt.Errorf("journal requires WAL")
	}
	if _, err = s.db.ExecContext(ctx, "PRAGMA synchronous=FULL; PRAGMA busy_timeout=0"); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var state device.State
	if version == 0 {
		if _, err = tx.ExecContext(ctx, fmt.Sprintf("CREATE TABLE snapshot (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, fence INTEGER NOT NULL, payload TEXT NOT NULL); PRAGMA user_version=%d", scope.SchemaVersion)); err != nil {
			return nil, err
		}
		state = scope.initial()
		payload, _ := json.Marshal(state)
		_, err = tx.ExecContext(ctx, "INSERT INTO snapshot(id,revision,fence,payload) VALUES(1,?,?,?)", state.Revision, state.Fence, string(payload))
	} else {
		state, err = load(ctx, tx)
		if err != nil {
			return nil, err
		}
		if state.Fence == maxCounter || state.Revision == maxCounter {
			return nil, fmt.Errorf("journal fence or revision exhausted")
		}
		state.Fence++
		state.Revision++
		payload, _ := json.Marshal(state)
		_, err = tx.ExecContext(ctx, "UPDATE snapshot SET revision=?,fence=?,payload=? WHERE id=1", state.Revision, state.Fence, string(payload))
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	s.fence = state.Fence
	if err = checkSidecars(root, s.name); err != nil {
		return nil, err
	}
	if err = syncDirectory(root); err != nil {
		return nil, fmt.Errorf("sync journal directory: %w", err)
	}
	return s, nil
}

func connect(path string, readOnly, immutable bool) (*sql.DB, error) {
	u := url.URL{Scheme: "file", Path: path}
	query := u.Query()
	if readOnly {
		query.Set("mode", "ro")
		query.Add("_pragma", "query_only(1)")
	} else {
		query.Set("mode", "rw")
	}
	if immutable {
		query.Set("immutable", "1")
	}
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err == nil {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	}
	return db, err
}

func preflight(ctx context.Context, root *os.Root, path, name, deviceID string) error {
	return preflightScope(ctx, root, path, name, storageScope{SchemaVersion: schemaVersion, DeviceID: deviceID})
}

func preflightScope(ctx context.Context, root *os.Root, path, name string, scope storageScope) error {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || info.Size() == 0 {
		return err
	}
	if err := checkSidecars(root, name); err != nil {
		return err
	}
	_, walErr := root.Lstat(name + "-wal")
	immutable := os.IsNotExist(walErr)
	if walErr != nil && !immutable {
		return walErr
	}
	if !immutable {
		if _, err := root.Lstat(name + "-shm"); err != nil {
			return fmt.Errorf("journal WAL needs operator reconciliation before version inspection: %w", device.ErrConflict)
		}
	}
	db, err := connect(path, true, immutable)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version == 0 {
		var tables int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
			return err
		}
		if tables != 0 {
			return fmt.Errorf("unversioned journal contains unknown tables: %w", device.ErrUnsupported)
		}
		return nil
	}
	if version != scope.SchemaVersion {
		return fmt.Errorf("unsupported journal schema %d: %w", version, device.ErrUnsupported)
	}
	state, err := load(ctx, tx)
	if err != nil {
		return err
	}
	return validateScopedState(state, scope)
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func load(ctx context.Context, q queryer) (device.State, error) {
	var state device.State
	var revision, fence uint64
	var payload string
	if err := q.QueryRowContext(ctx, "SELECT revision,fence,payload FROM snapshot WHERE id=1").Scan(&revision, &fence, &payload); err != nil {
		return state, fmt.Errorf("read journal snapshot: %w", err)
	}
	if len(payload) > 1<<20 {
		return state, fmt.Errorf("journal snapshot exceeds limit")
	}
	if err := device.CheckVersionFields([]byte(payload)); err != nil {
		return state, fmt.Errorf("decode journal snapshot: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewBufferString(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, fmt.Errorf("decode journal snapshot: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return state, fmt.Errorf("journal snapshot contains trailing data")
	}
	if state.Revision != revision || state.Fence != fence {
		return state, fmt.Errorf("journal fence or revision does not match its snapshot")
	}
	return state, nil
}

func (s *Store) guard() error {
	if s.closed {
		return fmt.Errorf("journal is closed: %w", device.ErrConflict)
	}
	for name, expected := range map[string]os.FileInfo{s.name: s.dbInfo, s.name + ".lock": s.lockInfo} {
		info, err := s.root.Lstat(name)
		if err != nil {
			return err
		}
		if err := owned(info, false); err != nil {
			return err
		}
		if !os.SameFile(info, expected) {
			return fmt.Errorf("journal storage inode changed: %w", device.ErrConflict)
		}
	}
	return checkSidecars(s.root, s.name)
}

func (s *Store) Load(ctx context.Context) (device.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return device.State{}, err
	}
	state, err := load(ctx, s.db)
	if err == nil {
		err = validateScopedState(state, s.scope)
	}
	if err == nil && state.Fence != s.fence {
		err = fmt.Errorf("journal writer fence changed: %w", device.ErrConflict)
	}
	return state, err
}

func (s *Store) Save(ctx context.Context, state device.State, expectedRevision uint64) (device.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return device.State{}, err
	}
	if s.writeErr != nil {
		return device.State{}, fmt.Errorf("journal write failed; reopen before further effects: %w", s.writeErr)
	}
	if state.Fence != s.fence || state.Revision != expectedRevision || expectedRevision >= maxCounter {
		return device.State{}, fmt.Errorf("stale journal revision or fence: %w", device.ErrConflict)
	}
	if err := validateScopedState(state, s.scope); err != nil {
		return device.State{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.writeErr = err
		return device.State{}, err
	}
	defer tx.Rollback()
	old, err := load(ctx, tx)
	if err != nil {
		s.writeErr = err
		return device.State{}, err
	}
	if old.Revision != expectedRevision || old.Fence != s.fence {
		return device.State{}, fmt.Errorf("stale journal revision or fence: %w", device.ErrConflict)
	}
	if err := validateUpdate(old, state); err != nil {
		return device.State{}, err
	}
	state.Revision++
	payload, err := json.Marshal(state)
	if err != nil || len(payload) > 1<<20 {
		return device.State{}, fmt.Errorf("journal snapshot encoding exceeds limit")
	}
	result, err := tx.ExecContext(ctx, "UPDATE snapshot SET revision=?,payload=? WHERE id=1 AND revision=? AND fence=?", state.Revision, string(payload), expectedRevision, s.fence)
	if err != nil {
		s.writeErr = err
		return device.State{}, fmt.Errorf("write journal snapshot: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return device.State{}, fmt.Errorf("journal compare-and-swap failed: %w", device.ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		s.writeErr = err
		return device.State{}, fmt.Errorf("commit journal snapshot: %w", err)
	}
	return state, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	if s.db != nil {
		errs = append(errs, s.db.Close())
	}
	if s.lock != nil {
		errs = append(errs, syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN), s.lock.Close())
	}
	if s.root != nil {
		errs = append(errs, s.root.Close())
	}
	return errors.Join(errs...)
}

// Read returns a snapshot without creating a database, lock or WAL sidecar.
// A WAL without its shared-memory file requires a writer to reconcile first.
func Read(ctx context.Context, path, deviceID string) (device.State, error) {
	return read(ctx, path, storageScope{SchemaVersion: schemaVersion, DeviceID: deviceID})
}

// ReadV2 inspects a profile-bound journal without reserving a writer fence.
func ReadV2(ctx context.Context, path, deploymentID, deviceID, profileID string, profileVersion int, profileDigest string) (device.State, error) {
	scope := storageScope{SchemaVersion: profileSchemaVersion, DeploymentID: deploymentID, DeviceID: deviceID, ProfileID: profileID, ProfileVersion: profileVersion, ProfileDigest: profileDigest}
	if err := scope.validate(); err != nil {
		return device.State{}, err
	}
	return read(ctx, path, scope)
}

func read(ctx context.Context, path string, scope storageScope) (device.State, error) {
	deviceID := scope.DeviceID
	if !device.ValidDeviceID(deviceID) {
		return device.State{}, fmt.Errorf("invalid journal device")
	}
	parent, root, err := directory(filepath.Dir(path), false)
	if err != nil {
		return device.State{}, err
	}
	defer root.Close()
	name := filepath.Base(path)
	f, err := regular(root, name, os.O_RDONLY, false)
	if err != nil {
		return device.State{}, err
	}
	f.Close()
	if err := checkHeaderVersion(root, name, scope.SchemaVersion); err != nil {
		return device.State{}, err
	}
	if err := checkSidecars(root, name); err != nil {
		return device.State{}, err
	}
	lock, err := regular(root, name+".lock", os.O_RDONLY, false)
	if err != nil {
		return device.State{}, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return device.State{}, fmt.Errorf("journal has an active writer: %w", device.ErrConflict)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_, walErr := root.Lstat(name + "-wal")
	immutable := os.IsNotExist(walErr)
	if walErr != nil && !immutable {
		return device.State{}, walErr
	}
	if !immutable {
		if _, err := root.Lstat(name + "-shm"); err != nil {
			return device.State{}, fmt.Errorf("journal WAL needs writer reconciliation: %w", device.ErrConflict)
		}
	}
	// The shared process lock prevents a writer from creating/removing WAL
	// files between inspection and the read-only SQLite snapshot.
	if immutable {
		if _, err := root.Lstat(name + "-wal"); !os.IsNotExist(err) {
			return device.State{}, fmt.Errorf("journal read raced with WAL creation: %w", device.ErrConflict)
		}
	}
	db, err := connect(filepath.Join(parent, name), true, immutable)
	if err != nil {
		return device.State{}, err
	}
	defer db.Close()
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return device.State{}, err
	}
	if version != scope.SchemaVersion {
		return device.State{}, fmt.Errorf("unsupported journal schema %d: %w", version, device.ErrUnsupported)
	}
	state, err := load(ctx, db)
	if err == nil {
		err = validateScopedState(state, scope)
	}
	return state, err
}

func checkSidecars(root *os.Root, name string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if info, err := root.Lstat(name + suffix); err == nil {
			if err := owned(info, false); err != nil {
				return fmt.Errorf("unsafe journal sidecar: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func checkHeader(root *os.Root, name string) error {
	return checkHeaderVersion(root, name, schemaVersion)
}

func checkHeaderVersion(root *os.Root, name string, expectedVersion int) error {
	f, err := regular(root, name, os.O_RDONLY, false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	header := make([]byte, 100)
	n, err := io.ReadFull(f, header)
	if n == 0 && err == io.EOF {
		return nil
	}
	if err != nil || string(header[:16]) != "SQLite format 3\x00" {
		return fmt.Errorf("journal is not a valid SQLite database")
	}
	version := binary.BigEndian.Uint32(header[60:64])
	if version != 0 && version != uint32(expectedVersion) {
		return fmt.Errorf("unsupported journal schema %d: %w", version, device.ErrUnsupported)
	}
	return nil
}
