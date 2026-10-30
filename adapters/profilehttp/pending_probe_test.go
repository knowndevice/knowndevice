// SPDX-License-Identifier: Apache-2.0

package profilehttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"knowndevice.local/knowndevice/adapters/internal/testtls"
	"knowndevice.local/knowndevice/sdk/device"
)

func TestAUD02PendingPlanCannotAuthorizePreviousActiveProbe(t *testing.T) {
	c, activePlan, _, _ := clientFixture(t)
	issuer := testtls.New(t)
	for i := range c.snapshot.Trust {
		if c.snapshot.Trust[i].Role == "operational" {
			c.snapshot.Trust[i].Anchors = [][]byte{issuer.Root.Raw}
			c.snapshot.Trust[i].AllowedIssuers = []string{device.Hash(issuer.Root.Raw)}
		}
	}
	activePlan.ConfigDigest, activePlan.SnapshotDigest = c.snapshot.Digest(), c.snapshot.Digest()
	activePlan.Digest, _ = activePlan.CalculateDigest()
	key := testtls.Key(t)
	csr, err := c.snapshot.Profile.CreateCSR(key, activePlan.DeviceID, 1)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := issuer.Sign(t, activePlan.DeviceID, key.Public(), func(cert *x509.Certificate) {
		cert.DNSNames = nil
		cert.NotBefore = time.Now().Add(-30 * time.Second)
		cert.NotAfter = time.Now().Add(1170 * time.Second)
	})
	active := device.Credential{Handle: device.Handle{Binding: activePlan.Binding(), PublicKeyDigest: device.Hash(leaf.RawSubjectPublicKeyInfo)}, CSR: csr, TLS: tls.Certificate{Certificate: [][]byte{leaf.Raw, issuer.Root.Raw}, PrivateKey: key, Leaf: leaf}}
	if err := c.validateCaller(context.Background(), &active, false); err != nil {
		t.Fatalf("invalid active credential fixture: %v", err)
	}
	pending := activePlan
	pending.OperationID = strings.Repeat("b", 32)
	pending.Mode = "rotate"
	pending.ExpectedGeneration, pending.TargetGeneration = 1, 2
	pending.TargetSlot = "B"
	pending.Digest, _ = pending.CalculateDigest()
	if err := c.SetPlan(pending); err != nil {
		t.Fatal(err)
	}
	dials := 0
	c.dial = func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, device.ErrUnknown
	}
	role, _ := c.snapshot.Role("transport")
	probe := device.Probe{OperationID: activePlan.OperationID, DeviceID: activePlan.DeviceID, Generation: 1, Endpoint: role.Endpoint, Nonce: strings.Repeat("c", 32), Deadline: time.Now().UTC().Add(time.Second)}
	reply, err := c.Probe(context.Background(), probe, active)
	if !errors.Is(err, device.ErrConflict) || reply != (device.Probe{}) || dials != 0 {
		t.Fatalf("missing active plan reached transport or claimed health: %+v, %v, dials=%d", reply, err, dials)
	}
	if len(c.plans) != 1 || c.plans[pending.OperationID] != pending || active.Handle.Binding != activePlan.Binding() || probe.OperationID != activePlan.OperationID {
		t.Fatal("probe rewrote a plan or rebound the previous credential")
	}
}
