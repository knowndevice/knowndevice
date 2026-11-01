// SPDX-License-Identifier: Apache-2.0

package profilehttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knowndevice/knowndevice/adapters/internal/testtls"
	"github.com/knowndevice/knowndevice/sdk/device"
)

func TestP7RevocationAbsenceAndSuccessRequireExactPreviousBinding(t *testing.T) {
	cases := []string{"not-started", "ok", "wrong-role", "wrong-namespace", "wrong-device", "wrong-operation", "wrong-plan", "wrong-config", "wrong-snapshot", "wrong-profile", "wrong-profile-version", "wrong-profile-digest", "wrong-generation", "wrong-SPKI", "wrong-leaf", "wrong-CSR", "wrong-status", "unbound-not-found", "missing-original-CSR"}
	for _, variant := range cases {
		t.Run(variant, func(t *testing.T) {
			c, p, _, server := clientFixture(t)
			issuer := testtls.New(t)
			for i := range c.snapshot.Trust {
				if c.snapshot.Trust[i].Role == "operational" {
					c.snapshot.Trust[i].Anchors = [][]byte{issuer.Root.Raw}
					c.snapshot.Trust[i].AllowedIssuers = []string{device.Hash(issuer.Root.Raw)}
				}
			}
			p.SnapshotDigest, p.ConfigDigest = c.snapshot.Digest(), c.snapshot.Digest()
			p.Mode, p.ExpectedGeneration, p.TargetGeneration, p.TargetSlot = "rotate", 1, 2, "B"
			p.Digest, _ = p.CalculateDigest()
			oldPlan := p
			oldPlan.OperationID = strings.Repeat("b", 32)
			oldPlan.Mode, oldPlan.ExpectedGeneration, oldPlan.TargetGeneration, oldPlan.TargetSlot = "enroll", 0, 1, "A"
			oldPlan.Digest, _ = oldPlan.CalculateDigest()
			credential := func(plan device.Plan) device.Credential {
				key := testtls.Key(t)
				csr, err := c.snapshot.Profile.CreateCSR(key, plan.DeviceID, plan.TargetGeneration)
				if err != nil {
					t.Fatal(err)
				}
				leaf, _ := issuer.Sign(t, plan.DeviceID, key.Public(), func(cert *x509.Certificate) {
					cert.DNSNames = nil
					cert.NotBefore, cert.NotAfter = time.Now().Add(-30*time.Second), time.Now().Add(1170*time.Second)
				})
				return device.Credential{Handle: device.Handle{Binding: plan.Binding(), PublicKeyDigest: device.Hash(leaf.RawSubjectPublicKeyInfo)}, TLS: tls.Certificate{Certificate: [][]byte{leaf.Raw, issuer.Root.Raw}, PrivateKey: key, Leaf: leaf}, CSR: csr}
			}
			previous, target := credential(oldPlan), credential(p)
			csr, err := c.snapshot.Profile.ValidateCSR(previous.CSR, oldPlan.DeviceID, oldPlan.TargetGeneration)
			if err != nil {
				t.Fatal(err)
			}
			subject := device.CredentialBinding{DeploymentID: oldPlan.DeploymentID, DeviceID: oldPlan.DeviceID, OperationID: oldPlan.OperationID, PlanDigest: oldPlan.Digest, ConfigDigest: oldPlan.ConfigDigest, SnapshotDigest: oldPlan.SnapshotDigest, ProfileID: oldPlan.ProfileID, ProfileVersion: oldPlan.ProfileVersion, ProfileDigest: oldPlan.ProfileDigest, Generation: oldPlan.TargetGeneration, PublicKeyDigest: previous.Handle.PublicKeyDigest, CertificateFingerprint: device.Hash(previous.TLS.Certificate[0]), CSRDigest: device.Hash(csr.Raw)}
			if variant == "missing-original-CSR" {
				previous.CSR = nil
			}
			var requests atomic.Int64
			listener := testtls.HTTPWithClientAuth(t, server, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				var in device.RoleRequest
				_ = json.NewDecoder(r.Body).Decode(&in)
				role, _ := c.snapshot.Role("control")
				v := device.Evidence{APIVersion: device.V2, Role: "authority", Action: "revocation-status", RequestID: in.RequestID, Plan: in.Plan, Subject: subject, Revision: 1, Reference: in.Plan.OperationID, Source: role.LeafPins[0], ObservedAt: time.Now().UTC(), Deadline: in.Plan.ExpiresAt, Status: "not-started"}
				status := "not-started"
				switch variant {
				case "ok":
					status, v.Status = "ok", "ok"
				case "wrong-role":
					v.Role = "platform"
				case "wrong-namespace":
					v.Subject.DeploymentID = "another-deployment"
				case "wrong-device":
					v.Subject.DeviceID = "another-device"
				case "wrong-operation":
					v.Subject.OperationID = p.OperationID
				case "wrong-plan":
					v.Subject.PlanDigest = p.Digest
				case "wrong-config":
					v.Subject.ConfigDigest = device.Hash([]byte("another config"))
				case "wrong-snapshot":
					v.Subject.SnapshotDigest = device.Hash([]byte("another snapshot"))
				case "wrong-profile":
					v.Subject.ProfileID = "reference-generation-cn"
				case "wrong-profile-version":
					v.Subject.ProfileVersion = 2
				case "wrong-profile-digest":
					v.Subject.ProfileDigest = device.Hash([]byte("another policy"))
				case "wrong-generation":
					v.Subject.Generation = p.TargetGeneration
				case "wrong-SPKI":
					v.Subject.PublicKeyDigest = target.Handle.PublicKeyDigest
				case "wrong-leaf":
					v.Subject.CertificateFingerprint = device.Hash(target.TLS.Certificate[0])
				case "wrong-CSR":
					v.Subject.CSRDigest = device.Hash([]byte("another CSR"))
				case "wrong-status":
					v.Status = "ok"
				case "unbound-not-found":
					status, v.Status = "not-found", "not-found"
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(device.RoleResponse{Status: status, Evidence: &v})
			}), tls.NoClientCert)
			c.dial = listener.DialContext
			err = c.RevocationStatus(context.Background(), p, previous, target)
			switch variant {
			case "not-started":
				if !errors.Is(err, device.ErrNotFound) {
					t.Fatalf("exact authoritative absence rejected: %v", err)
				}
			case "ok":
				if err != nil {
					t.Fatalf("exact authoritative success rejected: %v", err)
				}
			case "missing-original-CSR":
				if !errors.Is(err, device.ErrDenied) || requests.Load() != 0 {
					t.Fatalf("missing original CSR reached authority: err=%v requests=%d", err, requests.Load())
				}
			default:
				if !errors.Is(err, device.ErrUnknown) {
					t.Fatalf("incorrect previous binding established absence/success: %v", err)
				}
			}
			if variant != "missing-original-CSR" && requests.Load() != 1 {
				t.Fatalf("requests=%d; want one status call and no retry", requests.Load())
			}
		})
	}
}
