// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/internal/device"
)

func assertRecoveryScopeResult(t *testing.T, c *checks, err error, denied bool) {
	t.Helper()
	path := filepath.Join(c.dir, "profile-check-report.json")
	if !denied {
		if !errors.Is(err, device.ErrUnknown) || len(c.report.Passed) != 0 {
			t.Fatalf("uncertain recovery scope received denial credit: error=%v passed=%v", err, c.report.Passed)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("uncertain recovery scope wrote a PASS report")
		}
		return
	}
	if err != nil || len(c.report.Passed) != 1 || c.report.Passed[0] != "P4-P9-recovery-cannot-authorize-application" {
		t.Fatalf("authenticated recovery refusal was not credited: error=%v passed=%v", err, c.report.Passed)
	}
	var report checkReport
	if err := readJSON(path, &report); err != nil || len(report.Passed) != 1 || report.Passed[0] != c.report.Passed[0] {
		t.Fatal("authenticated recovery refusal did not persist its exact PASS")
	}
}

func TestRecoveryScopeUnavailableEndpointNeverPasses(t *testing.T) {
	for _, failure := range []error{syscall.ECONNREFUSED, context.DeadlineExceeded, io.EOF, device.ErrDenied, &net.DNSError{IsNotFound: true}} {
		t.Run(failure.Error(), func(t *testing.T) {
			dir, _, snapshot := testLab(t)
			c := &checks{dir: dir, snapshot: snapshot}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			err := c.checkRecoveryScope(ctx, testPlan(t, snapshot, 0, 1), func(context.Context, string, string) (net.Conn, error) {
				calls++
				return nil, failure
			})
			assertRecoveryScopeResult(t, c, err, false)
			if calls != 1 {
				t.Fatal("recovery diagnostic did not attempt exactly one connection")
			}
		})
	}
}

// These generated peers use real TLS over net.Pipe. They establish the local
// checker contract, not TCP availability, container acceptance or hardware.
func TestRecoveryScopeGeneratedTLSPeers(t *testing.T) {
	for _, behavior := range []string{"role-refusal", "authenticated-denial", "bare-denial", "wrong-request", "wrong-plan", "wrong-subject", "wrong-role", "wrong-action", "wrong-source", "stale-denial", "wrong-status", "conflicting-application", "conflicting-certificate", "conflicting-withdrawal", "conflicting-inventory", "accepted", "timeout", "closed", "untrusted-server", "wrong-server-name", "wrong-server-pin", "wrong-server-issuer", "tls12"} {
		t.Run(behavior, func(t *testing.T) {
			dir, _, snapshot := testLab(t)
			serverConfig, err := serviceTLS(dir, "application", snapshot, []string{"operational", "observer"})
			if err != nil {
				t.Fatal(err)
			}
			if behavior != "role-refusal" {
				// Only this synthetic peer accepts the recovery issuer at TLS, so
				// the HTTP denial and uncertainty paths can be exercised.
				roots, err := snapshot.Roots("recovery")
				if err != nil {
					t.Fatal(err)
				}
				serverConfig.ClientCAs = roots
			}
			if behavior == "untrusted-server" {
				_, _, other := testLocalRoleCertificate(t)
				serverConfig.Certificates = []tls.Certificate{other}
			}
			if behavior == "tls12" {
				serverConfig.MinVersion, serverConfig.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
			}
			for i := range snapshot.Trust {
				role := &snapshot.Trust[i]
				if role.Role != "application" {
					continue
				}
				switch behavior {
				case "wrong-server-name":
					role.PeerName = "wrong.known-device.invalid"
					role.Endpoint = "https://wrong.known-device.invalid"
				case "wrong-server-pin":
					role.LeafPins = []string{device.Hash([]byte("another server"))}
				case "wrong-server-issuer":
					role.AllowedIssuers = []string{device.Hash([]byte("another issuer"))}
				}
			}
			if err := snapshot.Validate(); err != nil {
				t.Fatalf("generated TLS peer snapshot is invalid: %v", err)
			}
			p := testPlan(t, snapshot, 0, 1)
			c := &checks{dir: dir, snapshot: snapshot}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			dial := func(context.Context, string, string) (net.Conn, error) {
				client, raw := net.Pipe()
				go func() {
					defer raw.Close()
					_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
					server := tls.Server(raw, serverConfig)
					if err := server.Handshake(); err != nil {
						done <- err
						return
					}
					if behavior == "timeout" {
						<-ctx.Done()
						done <- nil
						return
					}
					if behavior == "closed" {
						done <- nil
						return
					}
					req, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil {
						done <- err
						return
					}
					defer req.Body.Close()
					var in device.RoleRequest
					if err := device.DecodeStrict(req.Body, &in); err != nil {
						done <- err
						return
					}
					if req.URL.Path != "/activate" || in.Plan != p || in.RequestID == "" {
						done <- fmt.Errorf("request lost its recovery diagnostic binding")
						return
					}
					state := server.ConnectionState()
					req.TLS = &state
					if verifyPeerRole(req, snapshot, "recovery") != nil || verifyPeerRole(req, snapshot, "operational") == nil {
						done <- fmt.Errorf("synthetic peer did not authenticate the separate recovery role")
						return
					}
					v := evidence(p, device.CredentialBinding{}, "application", "activate", in.RequestID, 1, source(snapshot, "application"), "denied")
					result := device.RoleResponse{Status: "denied", Evidence: &v}
					switch behavior {
					case "bare-denial":
						result.Evidence = nil
					case "wrong-request":
						v.RequestID = "another-request"
					case "wrong-plan":
						v.Plan.TargetGeneration++
					case "wrong-subject":
						v.Subject = device.CredentialBinding{DeploymentID: p.DeploymentID, DeviceID: p.DeviceID, Generation: p.TargetGeneration}
					case "wrong-role":
						v.Role = "control"
					case "wrong-action":
						v.Action = "status"
					case "wrong-source":
						v.Source = "another-application"
					case "stale-denial":
						v.ObservedAt = time.Now().Add(-time.Minute)
					case "wrong-status":
						v.Status = "ok"
					case "conflicting-application":
						result.Application = &device.ApplicationEvidence{Phase: "activated"}
					case "conflicting-certificate":
						result.Certificate = []byte("conflicting certificate")
					case "conflicting-withdrawal":
						result.Withdrawal = &device.WithdrawalEvidence{}
					case "conflicting-inventory":
						result.Inventory = &device.SessionInventory{}
					case "accepted":
						result.Status = "ok"
					}
					// Use the shipped response encoder and bounded HTTP framing.
					encoded := httptest.NewRecorder()
					reply(encoded, result, nil)
					_, err = fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", encoded.Body.Len(), encoded.Body.String())
					done <- err
				}()
				return client, nil
			}
			err = c.checkRecoveryScope(ctx, p, dial)
			assertRecoveryScopeResult(t, c, err, behavior == "role-refusal" || behavior == "authenticated-denial")
			select {
			case peerErr := <-done:
				if behavior == "role-refusal" {
					var unknown x509.UnknownAuthorityError
					if !errors.As(peerErr, &unknown) {
						t.Fatalf("shipped Application TLS did not refuse the recovery issuer: %v", peerErr)
					}
				} else if behavior == "authenticated-denial" && peerErr != nil {
					t.Fatalf("authenticated peer failed: %v", peerErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("in-memory TLS peer did not finish")
			}
		})
	}
}

func TestRecoveryScopeAlertRejectsUncertainErrors(t *testing.T) {
	for _, err := range []error{
		device.ErrDenied,
		context.DeadlineExceeded,
		io.EOF,
		fmt.Errorf("remote error: tls: unknown certificate authority"),
		&net.OpError{Op: "remote error", Err: fmt.Errorf("tls: unknown certificate authority")},
		&net.OpError{Op: "local error", Err: tls.AlertError(48)},
		&net.OpError{Op: "remote error", Err: tls.AlertError(42)},
		&net.OpError{Op: "remote error", Err: tls.AlertError(45)},
		&net.OpError{Op: "remote error", Err: tls.AlertError(80)},
		&net.OpError{Op: "remote error", Err: tls.AlertError(116)},
	} {
		if recoveryRoleAlert(err) {
			t.Fatalf("uncertain or unrelated error supplied role-refusal evidence: %v", err)
		}
	}
}
