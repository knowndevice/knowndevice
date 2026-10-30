// SPDX-License-Identifier: Apache-2.0

package profilelab

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"knowndevice.local/knowndevice/internal/device"
)

func TestInventoryTracksActualPeerWithoutRelabeling(t *testing.T) {
	rootKey, _ := newKey()
	_, root, err := cert("inventory root", nil, rootKey, nil, nil, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, _ := newKey()
	_, serverLeaf, err := cert("localhost", []string{"localhost"}, serverKey, root, rootKey, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		t.Fatal(err)
	}
	clientKey, _ := newKey()
	_, clientLeaf, err := cert("old", nil, clientKey, root, rootKey, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	server := tls.Server(a, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{serverLeaf.Raw}, PrivateKey: serverKey}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, SessionTicketsDisabled: true})
	client := tls.Client(b, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{{Certificate: [][]byte{clientLeaf.Raw}, PrivateKey: clientKey}}})
	connections := newConnections()
	ctx := connections.context(context.Background(), server)
	before, err := connections.inventory()
	if err != nil || len(before) != 1 || before[0].Authenticated || before[0].Binding != nil {
		t.Fatal("uncompleted TLS socket classified as authenticated")
	}
	deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.HandshakeContext(deadline) }()
	if err := client.HandshakeContext(deadline); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	binding := device.CredentialBinding{Generation: 1, PublicKeyDigest: device.Hash(clientLeaf.RawSubjectPublicKeyInfo), CertificateFingerprint: device.Hash(clientLeaf.Raw)}
	id, err := connections.bind(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	current, err := connections.inventory()
	if err != nil || len(current) != 1 || !current[0].Authenticated || current[0].ConnectionID != id || *current[0].Binding != binding {
		t.Fatal("inventory lost actual authenticated peer binding")
	}
	current[0].Binding.Generation = 2
	again, err := connections.inventory()
	if err != nil || again[0].Binding.Generation != 1 {
		t.Fatal("inventory exposes mutable binding")
	}
	relabel := binding
	relabel.Generation = 2
	if _, err := connections.bind(ctx, relabel); !errors.Is(err, device.ErrDenied) {
		t.Fatal("old connection relabeled target")
	}
	connections.state(server, http.StateClosed)
	after, err := connections.inventory()
	if err != nil || len(after) != 0 {
		t.Fatal("closed socket remains live inventory")
	}
}

func TestInventoryRefusesIncompleteOversizedSnapshot(t *testing.T) {
	c := newConnections()
	for i := 0; i < 257; i++ {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		c.context(context.Background(), a)
	}
	if _, err := c.inventory(); !errors.Is(err, device.ErrUnknown) {
		t.Fatal("partial oversized inventory reported complete")
	}
}
