// SPDX-License-Identifier: Apache-2.0

package reference

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"knowndevice.local/knowndevice/adapters/controlhttp"
	"knowndevice.local/knowndevice/adapters/credentials"
	"knowndevice.local/knowndevice/adapters/stepca"
	"knowndevice.local/knowndevice/internal/device"
	"knowndevice.local/knowndevice/internal/keystore"
	_ "modernc.org/sqlite"
)

type reservation struct {
	Plan        device.Plan        `json:"plan"`
	CSR         []byte             `json:"csr"`
	Certificate []byte             `json:"certificate,omitempty"`
	IssueSent   bool               `json:"issueSent"`
	Registering bool               `json:"registering"`
	Registered  bool               `json:"registered"`
	Activated   bool               `json:"activated"`
	Retiring    bool               `json:"retiring"`
	Retirement  *device.Retirement `json:"retirement,omitempty"`
	Revoking    bool               `json:"revoking"`
	Revoked     bool               `json:"revoked"`
}

type control struct {
	mu     sync.Mutex
	dir    string
	db     *sql.DB
	lock   *os.File
	ca     *stepca.Client
	roots  *x509.CertPool
	config device.Config
	broker *exec.Cmd
}

func rootsAt(dir string) (*x509.CertPool, error) {
	b, err := os.ReadFile(filepath.Join(dir, "root.crt"))
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("lab root invalid")
	}
	return p, nil
}
func serverTLS(dir, role string) (*tls.Config, error) {
	c, err := keystore.LoadServiceCredential(filepath.Join(dir, role, "cert.pem"), filepath.Join(dir, role, "key.pem"), x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	roots, err := rootsAt(dir)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{c}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}, nil
}

func (s *control) number(ctx context.Context, name string) (uint64, error) {
	var n uint64
	err := s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE name=?", name).Scan(&n)
	return n, err
}
func (s *control) get(ctx context.Context, id string) (*reservation, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, "SELECT body FROM operations WHERE id=?", id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r reservation
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
func (s *control) save(ctx context.Context, r *reservation) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, "UPDATE operations SET body=? WHERE id=? AND digest=?", b, r.Plan.OperationID, r.Plan.Digest)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return device.ErrConflict
	}
	return nil
}

func openControl(dir string) (*control, error) {
	s := &control{dir: dir}
	var err error
	s.roots, err = rootsAt(dir)
	if err != nil {
		return nil, err
	}
	s.config, err = device.LoadConfig(filepath.Join(dir, "device.json"))
	if err != nil {
		return nil, err
	}
	s.lock, err = os.OpenFile(filepath.Join(dir, "control", "writer.lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		s.lock.Close()
		return nil, device.ErrConflict
	}
	path := filepath.Join(dir, "control", "registry.db")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	databasePath, err := filepath.Abs(path)
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
	if err = s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || (version != 0 && version != 1) {
		return nil, fmt.Errorf("reference registry schema unsupported")
	}
	if _, err = s.db.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;"); err != nil {
		return nil, err
	}
	if version == 0 {
		if _, err = s.db.Exec("BEGIN IMMEDIATE; CREATE TABLE metadata(name TEXT PRIMARY KEY,value INTEGER NOT NULL); INSERT INTO metadata VALUES('active',0),('counter',0); CREATE TABLE operations(id TEXT PRIMARY KEY,target INTEGER UNIQUE NOT NULL,digest TEXT NOT NULL,body BLOB NOT NULL); PRAGMA user_version=1; COMMIT;"); err != nil {
			return nil, err
		}
	}
	s.ca, err = stepca.New(stepca.Options{URL: "https://broker-control:9444", Roots: s.roots, Timeout: 5 * time.Second, TokenProvider: s.token})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *control) token(ctx context.Context, req stepca.TokenRequest) (string, error) {
	r, err := s.get(ctx, req.Plan.OperationID)
	if err != nil || r == nil || r.Plan != req.Plan || !r.IssueSent {
		return "", device.ErrDenied
	}
	var allowed entitlement
	if err := readJSON(filepath.Join(s.dir, "fixtures", "entitlement.json"), &allowed); err != nil || allowed.Status != "authorized" || allowed.DeviceID != req.Plan.DeviceID {
		return "", device.ErrDenied
	}
	if req.Purpose == "sign" && string(req.CSR) != string(r.CSR) {
		return "", device.ErrDenied
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "control", "provisioner.key"))
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return "", device.ErrDenied
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", device.ErrDenied
	}
	var meta struct {
		Kid string `json:"kid"`
	}
	if err := readJSON(filepath.Join(s.dir, "control", "provisioner.json"), &meta); err != nil {
		return "", err
	}
	subject := device.Subject(req.Plan.DeviceID, req.Plan.TargetGeneration)
	path := "sign"
	if req.Purpose == "revoke" {
		path = "revoke"
		subject = req.Serial
	}
	now := time.Now()
	jti, err := device.RandomID()
	if err != nil {
		return "", err
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": meta.Kid})
	claims := map[string]any{"iss": "known-device-lab", "sub": subject, "aud": "https://step-ca:9000/1.0/" + path, "iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "exp": now.Add(time.Minute).Unix(), "jti": jti}
	if path == "sign" {
		claims["sans"] = []string{subject}
	}
	payload, _ := json.Marshal(claims)
	encoded := b64(header) + "." + b64(payload)
	hash := sha256.Sum256([]byte(encoded))
	a, bigS, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}
	signature := make([]byte, 64)
	a.FillBytes(signature[:32])
	bigS.FillBytes(signature[32:])
	return encoded + "." + b64(signature), nil
}

func (s *control) writeACL(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT body FROM operations ORDER BY target")
	if err != nil {
		return err
	}
	defer rows.Close()
	var records []reservation
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return err
		}
		var r reservation
		if err := json.Unmarshal(b, &r); err != nil {
			return err
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	retired := map[uint64]bool{}
	for _, r := range records {
		if r.Retiring {
			retired[r.Plan.ExpectedGeneration] = true
		}
	}
	var out strings.Builder
	out.WriteString("user responder\ntopic read kd/+/+/request\ntopic write kd/+/+/response\n")
	var p policy
	if err := readJSON(filepath.Join(s.dir, "fixtures", "policy.json"), &p); err != nil {
		return err
	}
	for _, r := range records {
		if !r.Registered && !r.Registering {
			continue
		}
		if retired[r.Plan.TargetGeneration] {
			continue
		}
		fmt.Fprintf(&out, "user %s\n", device.Subject(r.Plan.DeviceID, r.Plan.TargetGeneration))
		if !p.DenyProbe || p.DenyGeneration != r.Plan.TargetGeneration {
			fmt.Fprintf(&out, "topic write kd/%s/g%d/request\ntopic read kd/%s/g%d/response\n", r.Plan.DeviceID, r.Plan.TargetGeneration, r.Plan.DeviceID, r.Plan.TargetGeneration)
		}
	}
	return atomic(filepath.Join(s.dir, "broker", "acl"), []byte(out.String()))
}

func (s *control) restartBroker(ctx context.Context) error {
	if s.broker != nil && s.broker.Process != nil {
		if err := s.broker.Process.Kill(); err != nil {
			return err
		}
		_ = s.broker.Wait()
		s.broker = nil
	}
	s.broker = exec.Command("/usr/sbin/mosquitto", "-c", filepath.Join(s.dir, "broker", "mosquitto.conf"))
	s.broker.Stdout = os.Stdout
	s.broker.Stderr = os.Stderr
	if err := s.broker.Start(); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:8883", 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return device.ErrUnknown
}

func (s *control) request(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "method denied", 405)
		return
	}
	var input controlhttp.Request
	if err := device.DecodeStrict(http.MaxBytesReader(w, req.Body, 128<<10), &input); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	response := controlhttp.Response{OperationID: input.Plan.OperationID, PlanDigest: input.Plan.Digest, DeviceID: input.Plan.DeviceID, Generation: input.Plan.TargetGeneration, Status: "denied"}
	if strings.Contains(req.URL.Path, "retir") || strings.Contains(req.URL.Path, "revok") || req.URL.Path == "/v1/revocation" {
		response.Generation = input.Plan.ExpectedGeneration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.handle(req, input, &response); err != nil {
		response.Status = "unknown"
		if errors.Is(err, device.ErrDenied) {
			response.Status = "denied"
		}
		if errors.Is(err, device.ErrConflict) {
			response.Status = "conflict"
		}
		if errors.Is(err, device.ErrNotFound) {
			response.Status = "not-found"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *control) handle(req *http.Request, in controlhttp.Request, out *controlhttp.Response) error {
	ctx := req.Context()
	p := in.Plan
	status := req.URL.Path == "/v1/issue/status" || req.URL.Path == "/v1/registration" || req.URL.Path == "/v1/activation-status" || req.URL.Path == "/v1/retirement" || req.URL.Path == "/v1/revocation"
	now := time.Now()
	if status {
		now = p.ExpiresAt.Add(-time.Nanosecond)
	}
	if p.Validate(now) != nil {
		return device.ErrDenied
	}
	configDigest, err := s.config.Digest()
	if err != nil || p.ConfigDigest != configDigest {
		return device.ErrDenied
	}
	var ent entitlement
	if err := readJSON(filepath.Join(s.dir, "fixtures", "entitlement.json"), &ent); err != nil || ent.Status != "authorized" || ent.DeviceID != p.DeviceID || req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return device.ErrDenied
	}
	peer := req.TLS.PeerCertificates[0]
	recovery := peer.Subject.CommonName == device.RecoverySubject(p.DeviceID)
	if recovery {
		if device.Hash(peer.Raw) != ent.RecoveryFingerprint || (p.Mode != "enroll" && p.Mode != "recover") || (req.URL.Path != "/v1/authorize" && req.URL.Path != "/v1/issue" && req.URL.Path != "/v1/issue/status" && req.URL.Path != "/v1/issue/import") {
			return device.ErrDenied
		}
	} else if peer.Subject.CommonName != device.Subject(p.DeviceID, p.ExpectedGeneration) && peer.Subject.CommonName != device.Subject(p.DeviceID, p.TargetGeneration) {
		return device.ErrDenied
	}
	active, err := s.number(ctx, "active")
	if err != nil {
		return err
	}
	r, err := s.get(ctx, p.OperationID)
	if err != nil {
		return err
	}
	if r != nil && r.Plan != p {
		return device.ErrConflict
	}
	issuance := req.URL.Path == "/v1/authorize" || strings.HasPrefix(req.URL.Path, "/v1/issue")
	if issuance {
		if (p.Mode == "enroll" || p.Mode == "recover") && !recovery {
			return device.ErrDenied
		}
		if p.Mode == "rotate" {
			if recovery || active != p.ExpectedGeneration || peer.Subject.CommonName != device.Subject(p.DeviceID, active) {
				return device.ErrDenied
			}
			var body []byte
			if err := s.db.QueryRowContext(ctx, "SELECT body FROM operations WHERE target=?", active).Scan(&body); err != nil {
				return device.ErrDenied
			}
			var current reservation
			if json.Unmarshal(body, &current) != nil {
				return device.ErrUnknown
			}
			fingerprint, err := credentials.CertificateFingerprint(current.Certificate)
			if err != nil || fingerprint != device.Hash(peer.Raw) {
				return device.ErrDenied
			}
		}
	}
	if req.URL.Path == "/v1/authorize" {
		if active != p.ExpectedGeneration || (!recovery && peer.Subject.CommonName != device.Subject(p.DeviceID, active)) {
			return device.ErrConflict
		}
		out.Status = "ok"
		return nil
	}
	if strings.HasPrefix(req.URL.Path, "/v1/issue") {
		if _, err := credentials.ValidateCSR(in.CSR, device.Subject(p.DeviceID, p.TargetGeneration)); err != nil {
			return device.ErrDenied
		}
		if r == nil {
			if status {
				return device.ErrNotFound
			}
			if req.URL.Path != "/v1/issue" || active != p.ExpectedGeneration {
				return device.ErrConflict
			}
			counter, err := s.number(ctx, "counter")
			if err != nil {
				return err
			}
			if p.TargetGeneration <= counter {
				return device.ErrConflict
			}
			r = &reservation{Plan: p, CSR: in.CSR, IssueSent: true}
			b, _ := json.Marshal(r)
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			if _, err = tx.ExecContext(ctx, "INSERT INTO operations(id,target,digest,body) VALUES(?,?,?,?)", p.OperationID, p.TargetGeneration, p.Digest, b); err != nil {
				return device.ErrConflict
			}
			if _, err = tx.ExecContext(ctx, "UPDATE metadata SET value=? WHERE name='counter'", p.TargetGeneration); err != nil {
				return err
			}
			if err = tx.Commit(); err != nil {
				return err
			}
			chain, err := s.ca.Issue(ctx, device.IssueRequest{Plan: p, CSR: in.CSR})
			if err != nil {
				return err
			}
			r.Certificate = chain
			if err := s.save(ctx, r); err != nil {
				return err
			}
		} else if string(r.CSR) != string(in.CSR) {
			return device.ErrConflict
		}
		if req.URL.Path == "/v1/issue/import" {
			if len(r.Certificate) != 0 || active != p.ExpectedGeneration {
				return device.ErrConflict
			}
			if err := credentials.ValidateCertificate(in.Certificate, r.CSR, device.Subject(p.DeviceID, p.TargetGeneration), s.roots, time.Now()); err != nil {
				return device.ErrDenied
			}
			r.Certificate = in.Certificate
			if err := s.save(ctx, r); err != nil {
				return err
			}
		}
		if len(r.Certificate) == 0 {
			return device.ErrUnknown
		}
		out.Certificate = r.Certificate
		out.Status = "ok"
		return nil
	}
	if r == nil {
		return device.ErrNotFound
	}
	previous := req.URL.Path == "/v1/retire" || req.URL.Path == "/v1/retirement" || req.URL.Path == "/v1/revoke" || req.URL.Path == "/v1/revocation"
	if in.Handle == nil || recovery {
		return device.ErrDenied
	}
	if previous {
		if in.Handle.Binding.DeviceID != p.DeviceID || in.Handle.Binding.Generation != p.ExpectedGeneration || peer.Subject.CommonName != device.Subject(p.DeviceID, p.TargetGeneration) || active != p.TargetGeneration || !r.Activated {
			return device.ErrConflict
		}
		fingerprint, err := credentials.CertificateFingerprint(r.Certificate)
		if err != nil || fingerprint != device.Hash(peer.Raw) {
			return device.ErrDenied
		}
		var previousBody []byte
		if err := s.db.QueryRowContext(ctx, "SELECT body FROM operations WHERE target=?", p.ExpectedGeneration).Scan(&previousBody); err != nil {
			return device.ErrDenied
		}
		var old reservation
		if json.Unmarshal(previousBody, &old) != nil {
			return device.ErrUnknown
		}
		expected, err := credentials.CertificateFingerprint(old.Certificate)
		actual, actualErr := credentials.CertificateFingerprint(in.Certificate)
		if err != nil || actualErr != nil || expected != actual {
			return device.ErrDenied
		}
	} else {
		if in.Handle.Binding != p.Binding() || len(r.Certificate) == 0 || peer.Subject.CommonName != device.Subject(p.DeviceID, p.TargetGeneration) {
			return device.ErrConflict
		}
		fingerprint, err := credentials.CertificateFingerprint(r.Certificate)
		if err != nil || fingerprint != device.Hash(peer.Raw) {
			return device.ErrDenied
		}
	}
	switch req.URL.Path {
	case "/v1/register":
		if active != p.ExpectedGeneration && active != p.TargetGeneration {
			return device.ErrConflict
		}
		if !r.Registered {
			r.Registering = true
			if err := s.save(ctx, r); err != nil {
				return err
			}
		}
		if err := s.writeACL(ctx); err != nil {
			return err
		}
		if err := s.restartBroker(ctx); err != nil {
			return err
		}
		r.Registered = true
		if err := s.save(ctx, r); err != nil {
			return err
		}
	case "/v1/registration":
		if !r.Registered {
			return device.ErrNotFound
		}
	case "/v1/activated":
		a := in.Activation
		if a == nil || a.OperationID != p.OperationID || a.PlanDigest != p.Digest || a.DeviceID != p.DeviceID || a.Generation != p.TargetGeneration || a.ApplicationID != s.config.ApplicationID || a.CertificateFingerprint != device.Hash(peer.Raw) || a.Probe.Endpoint != s.config.MQTTEndpoint || a.Probe.OperationID != p.OperationID || a.Probe.DeviceID != p.DeviceID || a.Probe.Generation != p.TargetGeneration || device.MatchProbe(a.Probe, a.Probe, time.Now()) != nil || !r.Registered {
			return device.ErrDenied
		}
		if active != p.ExpectedGeneration && active != p.TargetGeneration {
			return device.ErrConflict
		}
		if _, err := s.observeApplication(ctx, in); err != nil {
			if errors.Is(err, device.ErrNotFound) || errors.Is(err, device.ErrDenied) {
				return device.ErrDenied
			}
			return device.ErrUnknown
		}
		r.Activated = true
		b, _ := json.Marshal(r)
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, "UPDATE operations SET body=? WHERE id=?", b, p.OperationID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE metadata SET value=? WHERE name='active' AND value IN (?,?)", p.TargetGeneration, p.ExpectedGeneration, p.TargetGeneration); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	case "/v1/activation-status":
		if !r.Activated || active != p.TargetGeneration {
			return device.ErrNotFound
		}
		if _, err := s.observeApplication(ctx, in); err != nil {
			return device.ErrUnknown
		}
	case "/v1/retire", "/v1/retirement":
		if r.Retirement == nil && status {
			return device.ErrNotFound
		}
		if r.Retirement == nil {
			targetRequest := in
			targetRequest.Handle = &device.Handle{Binding: p.Binding()}
			targetRequest.Certificate = r.Certificate
			certs, err := credentials.ParseCertificateChain(r.Certificate)
			if err != nil {
				return device.ErrDenied
			}
			public, err := x509.MarshalPKIXPublicKey(certs[0].PublicKey)
			if err != nil {
				return device.ErrDenied
			}
			targetRequest.Handle.PublicKeyDigest = device.Hash(public)
			if _, err := s.observeApplication(ctx, targetRequest); err != nil {
				return device.ErrDenied
			}
			r.Retiring = true
			if err := s.save(ctx, r); err != nil {
				return err
			}
			if err := s.writeACL(ctx); err != nil {
				return err
			}
			if err := s.restartBroker(ctx); err != nil {
				return err
			}
			r.Retirement = &device.Retirement{OperationID: p.OperationID, PlanDigest: p.Digest, Generation: p.ExpectedGeneration, PolicyDurable: true, SessionsTerminated: true}
			if err := s.save(ctx, r); err != nil {
				return err
			}
		}
		out.Retirement = r.Retirement
	case "/v1/revoke", "/v1/revocation":
		if !r.Revoked {
			if status {
				if r.Revoking {
					return device.ErrUnknown
				}
				return device.ErrNotFound
			}
			if r.Revoking || r.Retirement == nil {
				return device.ErrUnknown
			}
			r.Revoking = true
			if err := s.save(ctx, r); err != nil {
				return err
			}
			certs, err := credentials.ParseCertificateChain(in.Certificate)
			if err != nil || len(certs) == 0 || certs[0].Subject.CommonName != device.Subject(p.DeviceID, p.ExpectedGeneration) {
				return device.ErrDenied
			}
			if err := s.ca.RevokeCertificate(ctx, p, in.Certificate); err != nil {
				return err
			}
			r.Revoked = true
			if err := s.save(ctx, r); err != nil {
				return err
			}
		}
	default:
		return device.ErrDenied
	}
	out.Status = "ok"
	return nil
}

func (s *control) observeApplication(ctx context.Context, in controlhttp.Request) (device.Activation, error) {
	cert, err := keystore.LoadServiceCredential(filepath.Join(s.dir, "control", "cert.pem"), filepath.Join(s.dir, "control", "key.pem"), x509.ExtKeyUsageClientAuth)
	if err != nil {
		return device.Activation{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout())
	defer cancel()
	in.Activation = nil
	data, err := json.Marshal(in)
	if err != nil {
		return device.Activation{}, err
	}
	endpoint, err := url.Parse(s.config.ApplicationURL)
	if err != nil {
		return device.Activation{}, device.ErrDenied
	}
	endpoint.Path = "/v1/observed"
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint.String(), strings.NewReader(string(data)))
	if err != nil {
		return device.Activation{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: s.config.Timeout(), Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return device.Activation{}, device.ErrUnknown
	}
	defer response.Body.Close()
	var result controlhttp.Response
	if response.StatusCode != 200 || device.DecodeStrict(io.LimitReader(response.Body, 128<<10), &result) != nil || result.OperationID != in.Plan.OperationID || result.PlanDigest != in.Plan.Digest || result.DeviceID != in.Plan.DeviceID || result.Generation != in.Plan.TargetGeneration {
		return device.Activation{}, device.ErrUnknown
	}
	if result.Status == "not-found" {
		return device.Activation{}, device.ErrNotFound
	}
	if result.Status == "denied" {
		return device.Activation{}, device.ErrDenied
	}
	if result.Status != "ok" || result.Activation == nil {
		return device.Activation{}, device.ErrUnknown
	}
	a := *result.Activation
	fingerprint, err := credentials.CertificateFingerprint(in.Certificate)
	if err != nil || a.OperationID != in.Plan.OperationID || a.PlanDigest != in.Plan.Digest || a.DeviceID != in.Plan.DeviceID || a.Generation != in.Plan.TargetGeneration || a.ApplicationID != s.config.ApplicationID || a.CertificateFingerprint != fingerprint || len(a.SessionID) != 32 || a.Probe.OperationID != in.Plan.OperationID || a.Probe.DeviceID != in.Plan.DeviceID || a.Probe.Generation != in.Plan.TargetGeneration || a.Probe.Endpoint != s.config.MQTTEndpoint || device.MatchProbe(a.Probe, a.Probe, time.Now()) != nil {
		return device.Activation{}, device.ErrDenied
	}
	return a, nil
}

func runControl(dir string) error {
	s, err := openControl(dir)
	if err != nil {
		return err
	}
	defer s.db.Close()
	defer s.lock.Close()
	if err := s.writeACL(context.Background()); err != nil {
		return err
	}
	if err := s.restartBroker(context.Background()); err != nil {
		return err
	}
	defer func() {
		if s.broker != nil {
			s.broker.Process.Kill()
			s.broker.Wait()
		}
	}()
	tlsConfig, err := serverTLS(dir, "control")
	if err != nil {
		return err
	}
	go s.proxy(tlsConfig)
	server := &http.Server{Addr: ":9443", Handler: http.HandlerFunc(s.request), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	return server.ListenAndServeTLS("", "")
}

func (s *control) proxy(config *tls.Config) {
	u, _ := url.Parse("https://step-ca:9000")
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.roots, MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 5 * time.Second}
	proxy.ModifyResponse = func(res *http.Response) error {
		var p policy
		if readJSON(filepath.Join(s.dir, "fixtures", "policy.json"), &p) == nil && p.LoseCAResponse && strings.HasSuffix(res.Request.URL.Path, "/sign") && res.StatusCode == 201 {
			b, err := io.ReadAll(io.LimitReader(res.Body, 128<<10))
			res.Body.Close()
			if err != nil {
				return err
			}
			if err := atomic(filepath.Join(s.dir, "control", "recovered-sign-response.json"), b); err != nil {
				return err
			}
			return device.ErrUnknown
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if h, ok := w.(http.Hijacker); ok {
			conn, _, e := h.Hijack()
			if e == nil {
				conn.Close()
				return
			}
		}
		http.Error(w, "upstream outcome unknown", 502)
	}
	config = config.Clone()
	config.ClientAuth = tls.VerifyClientCertIfGiven
	var counterMu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/sign") {
			var fixture policy
			if readJSON(filepath.Join(s.dir, "fixtures", "policy.json"), &fixture) != nil {
				http.Error(w, "fixture policy unavailable", 503)
				return
			}
			if fixture.ShortCertificate {
				body, err := io.ReadAll(io.LimitReader(r.Body, 128<<10))
				r.Body.Close()
				var request map[string]json.RawMessage
				if err != nil || json.Unmarshal(body, &request) != nil {
					http.Error(w, "invalid issuance request", 400)
					return
				}
				request["notAfter"], _ = json.Marshal(time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339))
				body, err = json.Marshal(request)
				if err != nil {
					http.Error(w, "invalid issuance request", 400)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				r.ContentLength = int64(len(body))
			}
			counterMu.Lock()
			path := filepath.Join(s.dir, "control", "ca-sign-count.json")
			var count struct {
				Requests uint64 `json:"requests"`
			}
			readErr := readJSON(path, &count)
			if readErr != nil && !os.IsNotExist(readErr) {
				counterMu.Unlock()
				http.Error(w, "counter unavailable", 503)
				return
			}
			count.Requests++
			err := writeJSON(path, count)
			counterMu.Unlock()
			if err != nil {
				http.Error(w, "counter unavailable", 503)
				return
			}
		}
		proxy.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: ":9444", Handler: handler, TLSConfig: config, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	_ = server.ListenAndServeTLS("", "")
}
