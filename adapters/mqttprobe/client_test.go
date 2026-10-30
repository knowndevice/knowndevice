// SPDX-License-Identifier: Apache-2.0

package mqttprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/packets"
	"knowndevice.local/knowndevice/adapters/internal/testtls"
	"knowndevice.local/knowndevice/sdk/device"
)

func packet(t *testing.T, connection net.Conn, kind byte, content packets.Packet) bool {
	t.Helper()
	message := packets.NewControlPacket(kind)
	message.Content = content
	_, err := message.WriteTo(connection)
	return err == nil
}

func readPeer(t *testing.T, connection net.Conn) (*packets.ControlPacket, error) {
	t.Helper()
	for {
		incoming, err := packets.ReadPacket(connection)
		if err != nil || incoming.Type != packets.PINGREQ {
			return incoming, err
		}
		if !packet(t, connection, packets.PINGRESP, &packets.Pingresp{}) {
			return nil, io.ErrClosedPipe
		}
	}
}

// This is a TLS protocol peer for failure tests, not Mosquitto evidence.
func broker(t *testing.T, profile *testtls.Profile, behavior string) *testtls.Listener {
	t.Helper()
	listener := testtls.NewListener(t)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		connection := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{profile.Server}, MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: profile.Roots})
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		if err := connection.Handshake(); err != nil {
			return
		}
		if got := connection.ConnectionState().PeerCertificates[0].Subject.CommonName; got != device.Subject("device-a", 2) {
			t.Errorf("actual target certificate = %s", got)
		}
		incoming, err := packets.ReadPacket(connection)
		if err != nil || incoming.Type != packets.CONNECT {
			return
		}
		connect := incoming.Content.(*packets.Connect)
		if !connect.CleanStart || connect.UsernameFlag || connect.PasswordFlag || connect.Properties == nil || connect.Properties.SessionExpiryInterval == nil || *connect.Properties.SessionExpiryInterval != 0 {
			t.Error("probe did not use a clean mTLS-only session")
		}
		reason := byte(0)
		if behavior == "connect-denied" {
			reason = 0x87
		}
		if !packet(t, connection, packets.CONNACK, &packets.Connack{ReasonCode: reason, Properties: &packets.Properties{}}) || reason != 0 {
			return
		}
		incoming, err = readPeer(t, connection)
		if err != nil || incoming.Type != packets.SUBSCRIBE {
			t.Logf("peer subscribe read: %v", err)
			return
		}
		subscribe := incoming.Content.(*packets.Subscribe)
		if len(subscribe.Subscriptions) != 1 || subscribe.Subscriptions[0].Topic != "kd/device-a/g2/response" || !subscribe.Subscriptions[0].NoLocal || !subscribe.Subscriptions[0].RetainAsPublished || subscribe.Subscriptions[0].RetainHandling != 2 {
			t.Error("subscription scope or retention settings wrong")
		}
		reason = 1
		if behavior == "subscribe-denied" {
			reason = 0x87
		}
		if !packet(t, connection, packets.SUBACK, &packets.Suback{PacketID: subscribe.PacketID, Reasons: []byte{reason}, Properties: &packets.Properties{}}) {
			t.Log("peer suback write failed")
			return
		}
		if reason >= 0x80 {
			_, _ = readPeer(t, connection)
			return
		}
		incoming, err = readPeer(t, connection)
		if err != nil || incoming.Type != packets.PUBLISH {
			t.Logf("peer publish read: %v", err)
			return
		}
		publish := incoming.Content.(*packets.Publish)
		if publish.Topic != "kd/device-a/g2/request" || publish.Retain || publish.QoS != 1 {
			t.Error("publish scope, retention or QoS wrong")
		}
		reason = 0
		if behavior == "publish-denied" {
			reason = 0x87
		}
		if !packet(t, connection, packets.PUBACK, &packets.Puback{PacketID: publish.PacketID, ReasonCode: reason, Properties: &packets.Properties{}}) {
			t.Log("peer puback write failed")
			return
		}
		if reason >= 0x80 {
			_, _ = readPeer(t, connection)
			return
		}
		if behavior == "lost-response" {
			return
		}
		var probe device.Probe
		if err := json.Unmarshal(publish.Payload, &probe); err != nil {
			t.Error(err)
			return
		}
		topic := "kd/device-a/g2/response"
		if behavior == "wrong-topic" {
			topic = "kd/device-a/g1/response"
		}
		if behavior == "replay" {
			probe.Nonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}
		if behavior == "oversized" {
			// Remaining length 16385 is rejected before Paho allocates a body.
			_, _ = connection.Write([]byte{0x30, 0x81, 0x80, 0x01})
			return
		}
		payload, _ := json.Marshal(probe)
		if !packet(t, connection, packets.PUBLISH, &packets.Publish{Topic: topic, Payload: payload, Retain: behavior == "retained", QoS: 0, Properties: &packets.Properties{}}) {
			return
		}
		for {
			incoming, err = packets.ReadPacket(connection)
			if err != nil || incoming.Type == packets.DISCONNECT {
				return
			}
			if incoming.Type == packets.PINGREQ {
				if !packet(t, connection, packets.PINGRESP, &packets.Pingresp{}) {
					return
				}
			}
		}
	}()
	return listener
}

func TestProbeUsesTargetSignerAndRejectsUnsafeResponses(t *testing.T) {
	for _, test := range []struct {
		behavior string
		want     error
		acl      bool
	}{
		{behavior: "success"},
		{behavior: "subscribe-denied", want: device.ErrDenied, acl: true},
		{behavior: "publish-denied", want: device.ErrDenied, acl: true},
		{behavior: "connect-denied", want: device.ErrDenied},
		{behavior: "lost-response", want: device.ErrUnknown},
		{behavior: "retained", want: device.ErrDenied},
		{behavior: "wrong-topic", want: device.ErrDenied},
		{behavior: "replay", want: device.ErrDenied},
		{behavior: "oversized", want: device.ErrUnknown},
	} {
		t.Run(test.behavior, func(t *testing.T) {
			profile := testtls.New(t)
			credential := profile.Credential(t, device.Binding{DeviceID: "device-a", OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Generation: 2, Slot: "B"})
			server := broker(t, profile, test.behavior)
			client, err := New(Options{Endpoint: "tls://lab.known-device.invalid:8883", Roots: profile.Roots, Timeout: time.Second, Now: func() time.Time { return profile.Now }, dialContext: server.DialContext})
			if err != nil {
				t.Fatal(err)
			}
			request := device.Probe{OperationID: credential.Handle.Binding.OperationID, DeviceID: "device-a", Generation: 2, Endpoint: "tls://lab.known-device.invalid:8883", Nonce: "cccccccccccccccccccccccccccccccc", Deadline: profile.Now.Add(30 * time.Second)}
			response, err := client.Probe(context.Background(), request, credential)
			if test.want == nil {
				if err != nil || response != request {
					t.Fatalf("probe = %+v, %v", response, err)
				}
				if _, err := client.Probe(context.Background(), request, credential); !errors.Is(err, device.ErrDenied) {
					t.Fatalf("nonce reused: %v", err)
				}
			} else if !errors.Is(err, test.want) {
				t.Fatalf("probe = %v, want %v", err, test.want)
			}
			if errors.Is(err, ErrACL) != test.acl {
				t.Fatalf("ACL observation = %v, want %t", err, test.acl)
			}
		})
	}
}

func TestTLSValidationAndRecoveryDenial(t *testing.T) {
	profile := testtls.New(t)
	credential := profile.Credential(t, device.Binding{DeviceID: "device-a", OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Generation: 2, Slot: "B"})
	server := broker(t, profile, "success")
	options := Options{Endpoint: "tls://lab.known-device.invalid:8883", Roots: testtls.New(t).Roots, Timeout: time.Second, dialContext: server.DialContext}
	if _, err := Open(context.Background(), options, credential); !errors.Is(err, device.ErrUnknown) {
		t.Fatalf("untrusted TLS = %v", err)
	}
	options.Roots = profile.Roots
	if _, err := Open(context.Background(), options, profile.Recovery(t, "device-a")); !errors.Is(err, device.ErrDenied) || errors.Is(err, ErrACL) {
		t.Fatalf("recovery MQTT scope = %v", err)
	}
	for _, endpoint := range []string{"tcp://lab.known-device.invalid:1883", "tls://lab.known-device.invalid", "tls://user:secret@lab.known-device.invalid:8883", "tls://lab.known-device.invalid:8883/path"} {
		options.Endpoint = endpoint
		if _, err := New(options); err == nil {
			t.Fatalf("unsafe endpoint = %s", endpoint)
		}
	}
}

type memoryConn struct{ *bytes.Reader }

func (*memoryConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return nil }
func (*memoryConn) RemoteAddr() net.Addr             { return nil }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

func TestFrameBoundsBeforeDecoderAllocation(t *testing.T) {
	for _, header := range [][]byte{{0x30, 0x81, 0x80, 0x01}, {0x30, 0xff, 0xff, 0xff, 0x7f}, {0x30, 0x80, 0x80, 0x80, 0x80}} {
		connection := &packetConn{Conn: &memoryConn{bytes.NewReader(header)}}
		if _, err := packets.ReadPacket(connection); err == nil {
			t.Fatal("oversized or invalid frame accepted")
		}
	}
	connection := &packetConn{Conn: &memoryConn{bytes.NewReader([]byte{0xc0, 0x00, 0xd0, 0x00})}}
	if _, err := packets.ReadPacket(connection); err != nil {
		t.Fatal(err)
	}
	if _, err := packets.ReadPacket(connection); err != nil {
		t.Fatal(err)
	}
}

func TestResponseBoundsAndExactBinding(t *testing.T) {
	now := time.Now().UTC()
	request := device.Probe{OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DeviceID: "device-a", Generation: 2, Endpoint: "tls://broker.invalid:8883", Nonce: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Deadline: now.Add(time.Second)}
	payload, _ := json.Marshal(request)
	for _, message := range []Message{
		{Topic: "kd/device-a/g2/response", Payload: append(payload, []byte("{}")...)},
		{Topic: "kd/device-a/g2/response", Payload: []byte(strings.Repeat("x", MaxPayload+1))},
		{Topic: "kd/device-a/g2/request", Payload: payload},
		{Topic: "kd/device-a/g2/response", Payload: payload, Retained: true},
		{Topic: "kd/device-a/g2/response", Payload: []byte("{\"privateKey\":\"private-key-secret-token\"}")},
	} {
		if _, err := MatchResponse(request, "kd/device-a/g2/response", message, now); !errors.Is(err, device.ErrDenied) || strings.Contains(err.Error(), "private-key-secret-token") {
			t.Fatalf("unsafe response = %v", err)
		}
	}
}
