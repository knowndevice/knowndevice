// SPDX-License-Identifier: Apache-2.0

package mqttprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"knowndevice.local/knowndevice/adapters/internal/testtls"
	"knowndevice.local/knowndevice/sdk/device"
)

func expiredCredential(t *testing.T, profile *testtls.Profile) device.Credential {
	t.Helper()
	key := testtls.Key(t)
	leaf, _ := profile.Sign(t, device.Subject("device-a", 1), key.Public(), func(c *x509.Certificate) {
		c.NotBefore = profile.Now.Add(-5 * time.Minute)
		c.NotAfter = profile.Now.Add(-4 * time.Minute)
	})
	public, _ := x509.MarshalPKIXPublicKey(key.Public())
	return device.Credential{Handle: device.Handle{Binding: device.Binding{DeviceID: "device-a", OperationID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Generation: 1, Slot: "A"}, PublicKeyDigest: device.Hash(public)}, TLS: tls.Certificate{Certificate: [][]byte{leaf.Raw, profile.Root.Raw}, PrivateKey: key, Leaf: leaf}}
}

func TestExpiredDenialRequiresProtectedPeerTLSAlert(t *testing.T) {
	for _, behavior := range []string{"expired-denied", "accepts-expired", "silent", "untrusted", "tls12"} {
		t.Run(behavior, func(t *testing.T) {
			profile := testtls.New(t)
			old := expiredCredential(t, profile)
			listener := testtls.NewListener(t)
			var peerCheckedExpiry atomic.Bool
			done := make(chan struct{})
			go func() {
				defer close(done)
				raw, err := listener.Accept()
				if err != nil {
					return
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(time.Second))
				if behavior == "silent" {
					var data [1]byte
					_, _ = raw.Read(data[:])
					return
				}
				serverCertificate := profile.Server
				if behavior == "untrusted" {
					serverCertificate = testtls.New(t).Server
				}
				configuration := &tls.Config{Certificates: []tls.Certificate{serverCertificate}, ClientCAs: profile.Roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
				if behavior == "accepts-expired" {
					configuration.ClientAuth = tls.RequireAnyClientCert
				}
				if behavior == "tls12" {
					configuration.MinVersion = tls.VersionTLS12
					configuration.MaxVersion = tls.VersionTLS12
				}
				server := tls.Server(raw, configuration)
				err = server.Handshake()
				if behavior == "expired-denied" {
					var expired x509.CertificateInvalidError
					if errors.As(err, &expired) && expired.Reason == x509.Expired {
						peerCheckedExpiry.Store(true)
					} else {
						t.Errorf("peer did not reject the actual expired certificate: %v", err)
					}
					return
				}
				if err == nil {
					var data [1]byte
					_, _ = server.Read(data[:])
				}
			}()
			t.Cleanup(func() {
				listener.Close()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("TLS peer did not finish")
				}
			})
			client, err := New(Options{Endpoint: "tls://lab.known-device.invalid:8883", Roots: profile.Roots, Timeout: 500 * time.Millisecond, Now: func() time.Time { return profile.Now }, dialContext: listener.DialContext})
			if err != nil {
				t.Fatal(err)
			}
			observation, err := client.ObserveDenial(context.Background(), old)
			if behavior == "expired-denied" {
				if err != nil || observation.TLSObservation != "denied" || !observation.ApplicationAccessDenied {
					t.Fatalf("expired observation = %+v, %v", observation, err)
				}
				<-done
				if !peerCheckedExpiry.Load() {
					t.Fatal("denial lacked a real peer certificate validity check")
				}
			} else if !errors.Is(err, device.ErrUnknown) || observation.ApplicationAccessDenied {
				t.Fatalf("%s supplied denial evidence: %+v, %v", behavior, observation, err)
			}
		})
	}
}

func TestUsableOldDenialStillRequiresExplicitMQTTACL(t *testing.T) {
	for _, behavior := range []string{"subscribe-denied", "success", "lost-response"} {
		t.Run(behavior, func(t *testing.T) {
			profile := testtls.New(t)
			old := profile.Credential(t, device.Binding{DeviceID: "device-a", OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Generation: 2, Slot: "B"})
			listener := broker(t, profile, behavior)
			client, err := New(Options{Endpoint: "tls://lab.known-device.invalid:8883", Roots: profile.Roots, Timeout: time.Second, Now: func() time.Time { return profile.Now }, dialContext: listener.DialContext})
			if err != nil {
				t.Fatal(err)
			}
			observation, err := client.ObserveDenial(context.Background(), old)
			if behavior == "subscribe-denied" {
				if err != nil || observation.TLSObservation != "accepted" || !observation.ApplicationAccessDenied {
					t.Fatalf("MQTT denial = %+v, %v", observation, err)
				}
			} else if !errors.Is(err, device.ErrUnknown) || observation.ApplicationAccessDenied {
				t.Fatalf("%s supplied denial: %+v, %v", behavior, observation, err)
			}
		})
	}
}

func TestAlertClassificationRejectsLocalAndTextualErrors(t *testing.T) {
	for _, err := range []error{
		context.DeadlineExceeded,
		fmt.Errorf("remote error: tls: expired certificate"),
		&net.OpError{Op: "remote error", Err: fmt.Errorf("tls: expired certificate")},
		&net.OpError{Op: "local error", Err: tls.AlertError(45)},
		&net.OpError{Op: "remote error", Err: tls.AlertError(80)},
	} {
		if certificateAlert(err) {
			t.Fatalf("unconfirmed error supplied TLS denial: %v", err)
		}
	}
}
