// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/knowndevice/knowndevice/internal/credentialprofile"
	"github.com/knowndevice/knowndevice/internal/device"
)

func TestAuditRegistryPathPreservesReservedCharacters(t *testing.T) {
	for _, suffix := range []string{"?audit", "#audit", "%audit"} {
		t.Run(suffix, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(base, "fresh"+suffix)
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			if err = seed(dir, credentialprofile.StableID, executable, executable); err != nil {
				t.Fatal(err)
			}
			cfg, snapshot, err := loadServices(dir)
			if err != nil {
				t.Fatal(err)
			}
			initial := testRegistry(cfg, snapshot)
			s, err := openStore(filepath.Join(dir, "control"), initial)
			if err != nil {
				t.Fatal(err)
			}
			r := testReservation(t, snapshot, testPlan(t, snapshot, 0, 1))
			if _, err = s.reserve(context.Background(), r); err != nil {
				s.close()
				t.Fatal(err)
			}
			s.close()
			s, err = openStore(filepath.Join(dir, "control"), initial)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			reg, err := s.registry(context.Background())
			if err != nil || reg.Counter != 1 {
				t.Fatalf("registry counter did not survive reopen: %v, %d", err, reg.Counter)
			}
			stored, err := s.operation(context.Background(), r.Plan)
			if err != nil || stored == nil || !stored.IssueSent || string(stored.CSR) != string(r.CSR) {
				t.Fatal("registry lost its original unknown reservation")
			}
			entries, err := os.ReadDir(base)
			if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(dir) {
				t.Fatal("SQLite created a sibling outside the selected registry directory")
			}
		})
	}
}

type auditRoundTripper func(*http.Request) (*http.Response, error)

func (f auditRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAuditAuthorityProxyCountsLostResponse(t *testing.T) {
	dir, cfg, snapshot := testLab(t)
	s := &control{dir: dir, config: cfg, snapshot: snapshot}
	proxy, err := s.caProxy()
	if err != nil {
		t.Fatal(err)
	}
	var effects atomic.Uint64
	transport, ok := proxy.Transport.(*countingCATransport)
	if !ok {
		t.Fatal("authority proxy bypasses the attempted-send counter")
	}
	transport.next = auditRoundTripper(func(*http.Request) (*http.Response, error) {
		effects.Add(1)
		return nil, io.EOF
	})
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://proxy.invalid/sign", nil))
	var counts struct {
		Sign         uint64 `json:"sign"`
		SignAttempts uint64 `json:"signAttempts"`
	}
	if err = readJSON(filepath.Join(dir, "control", "ca-counts.json"), &counts); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusBadGateway || effects.Load() != 1 || counts.SignAttempts != 1 || counts.Sign != 0 {
		t.Fatalf("lost response hid an issuance attempt: status=%d effects=%d attempts=%d responses=%d", response.Code, effects.Load(), counts.SignAttempts, counts.Sign)
	}
}

func TestAuditAuthorityAttemptCounterRefusesUnavailableState(t *testing.T) {
	for _, failure := range []string{"absent", "missing-sign", "missing-attempts", "null-attempts", "malformed", "directory", "pending", "overflow"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "control"), 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "control", "ca-counts.json")
			switch failure {
			case "absent":
			case "missing-sign", "missing-attempts", "null-attempts":
				body := map[string]any{"sign": uint64(1), "signAttempts": uint64(1)}
				if failure == "missing-sign" {
					delete(body, "sign")
				} else if failure == "missing-attempts" {
					delete(body, "signAttempts")
				} else {
					body["signAttempts"] = nil
				}
				if err := writeJSON(path, body); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(path, []byte("{invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.WriteFile(path+".pending", []byte("retained interrupted counter"), 0600); err != nil {
					t.Fatal(err)
				}
			case "overflow":
				if err := writeJSON(path, caCounts{SignAttempts: ^uint64(0)}); err != nil {
					t.Fatal(err)
				}
			}
			var effects atomic.Uint64
			transport := countingCATransport{control: &control{dir: dir}, next: auditRoundTripper(func(*http.Request) (*http.Response, error) {
				effects.Add(1)
				return nil, io.EOF
			})}
			_, err := transport.RoundTrip(httptest.NewRequest(http.MethodPost, "https://proxy.invalid/sign", nil))
			if !errors.Is(err, device.ErrUnknown) || effects.Load() != 0 {
				t.Fatal("an unavailable counter permitted an issuance dispatch")
			}
		})
	}
}

func TestAuditAuthorityConcurrentAttemptsRemainCounted(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "control"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "control", "ca-counts.json"), caCounts{}); err != nil {
		t.Fatal(err)
	}
	var effects atomic.Uint64
	transport := countingCATransport{control: &control{dir: dir}, next: auditRoundTripper(func(*http.Request) (*http.Response, error) {
		effects.Add(1)
		return nil, io.EOF
	})}
	var workers sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		workers.Go(func() {
			_, err := transport.RoundTrip(httptest.NewRequest(http.MethodPost, "https://proxy.invalid/sign", nil))
			results <- err
		})
	}
	workers.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	}
	var counts caCounts
	if err := readJSON(filepath.Join(dir, "control", "ca-counts.json"), &counts); err != nil {
		t.Fatal(err)
	}
	if effects.Load() != 2 || counts.SignAttempts != 2 || counts.Sign != 0 {
		t.Fatalf("concurrent sends lost an attempt: effects=%d attempts=%d responses=%d", effects.Load(), counts.SignAttempts, counts.Sign)
	}
}

func TestAuditAuthorityResponseCountRemainsDistinct(t *testing.T) {
	dir, cfg, snapshot := testLab(t)
	root, server, _ := testLocalRoleCertificate(t)
	for i := range snapshot.Trust {
		if snapshot.Trust[i].Role == "authority-transport" {
			snapshot.Trust[i].Endpoint = "https://localhost"
			snapshot.Trust[i].PeerName = "localhost"
			snapshot.Trust[i].Anchors = [][]byte{root.Raw}
			snapshot.Trust[i].AllowedIssuers = []string{device.Hash(root.Raw)}
		}
	}
	cfg.CAURL = "https://localhost"
	proxy, err := (&control{dir: dir, config: cfg, snapshot: snapshot}).caProxy()
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := proxy.Transport.(*countingCATransport)
	if !ok {
		t.Fatal("authority proxy bypasses the attempted-send counter")
	}
	transport.next = auditRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: req, TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{server, root}}}, nil
	})
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://proxy.invalid/sign", nil))
	var counts caCounts
	if err = readJSON(filepath.Join(dir, "control", "ca-counts.json"), &counts); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusCreated || counts.SignAttempts != 1 || counts.Sign != 1 {
		t.Fatalf("response count lost its distinct meaning: status=%d attempts=%d responses=%d", response.Code, counts.SignAttempts, counts.Sign)
	}
}
