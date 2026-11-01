// SPDX-License-Identifier: Apache-2.0

// Package mqttprobe verifies the target signer through MQTT 5 and an external responder.
package mqttprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/eclipse/paho.golang/packets"
	"github.com/eclipse/paho.golang/paho"
	"github.com/knowndevice/knowndevice/adapters/credentials"
	"github.com/knowndevice/knowndevice/adapters/internal/strictjson"
	"github.com/knowndevice/knowndevice/sdk/device"
)

const MaxPayload = 4096
const MaxPacketSize = 16 << 10

// ErrACL identifies an explicit SUBACK/PUBACK denial after verified mutual TLS.
// Local validation, TLS errors, CONNECT failures and timeouts never set it.
var ErrACL = errors.New("broker explicitly denied MQTT application access")

type Options struct {
	Endpoint    string
	Roots       *x509.CertPool
	Timeout     time.Duration
	Now         func() time.Time
	dialContext func(context.Context, string, string) (net.Conn, error)
}

type Client struct {
	options Options
	mu      sync.Mutex
	seen    map[string]time.Time
}

func New(options Options) (*Client, error) {
	if _, err := validateOptions(options); err != nil {
		return nil, err
	}
	options.Roots = options.Roots.Clone()
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Client{options: options, seen: make(map[string]time.Time)}, nil
}

func validateOptions(options Options) (*url.URL, error) {
	endpoint, err := url.Parse(options.Endpoint)
	if err != nil || endpoint.Scheme != "tls" || endpoint.Hostname() == "" || endpoint.Port() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("MQTT requires a TLS endpoint with an explicit port and no credentials or path")
	}
	if options.Roots == nil || len(options.Roots.Subjects()) == 0 || options.Timeout <= 0 || options.Timeout > time.Minute {
		return nil, fmt.Errorf("MQTT requires explicit trust roots and a timeout of at most one minute")
	}
	return endpoint, nil
}

func Topics(deviceID string, generation uint64) (string, string, error) {
	if !device.ValidDeviceID(deviceID) || generation == 0 || generation > 1<<53-1 {
		return "", "", fmt.Errorf("invalid MQTT device or generation")
	}
	base := fmt.Sprintf("kd/%s/g%d", deviceID, generation)
	return base + "/request", base + "/response", nil
}

func (c *Client) Probe(ctx context.Context, request device.Probe, credential device.Credential) (device.Probe, error) {
	if credential.Recovery || request.Endpoint != c.options.Endpoint || request.DeviceID != credential.Handle.Binding.DeviceID || request.OperationID != credential.Handle.Binding.OperationID || request.Generation != credential.Handle.Binding.Generation {
		return device.Probe{}, fmt.Errorf("MQTT probe credential or endpoint binding mismatch: %w", device.ErrDenied)
	}
	if err := device.MatchProbe(request, request, c.options.Now()); err != nil {
		return device.Probe{}, err
	}
	c.mu.Lock()
	for nonce, expiry := range c.seen {
		if !expiry.After(c.options.Now()) {
			delete(c.seen, nonce)
		}
	}
	_, replay := c.seen[request.Nonce]
	if !replay && len(c.seen) < 1024 {
		c.seen[request.Nonce] = request.Deadline
	} else {
		replay = true
	}
	c.mu.Unlock()
	if replay {
		return device.Probe{}, fmt.Errorf("MQTT probe nonce was already used: %w", device.ErrDenied)
	}
	if err := credentials.ValidateCredential(credential); err != nil {
		return device.Probe{}, err
	}
	leaf, _ := x509.ParseCertificate(credential.TLS.Certificate[0])
	subject := device.Subject(request.DeviceID, request.Generation)
	if leaf.Subject.CommonName != subject || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != subject {
		return device.Probe{}, fmt.Errorf("MQTT target certificate identity mismatch: %w", device.ErrDenied)
	}
	requestTopic, responseTopic, err := Topics(request.DeviceID, request.Generation)
	if err != nil {
		return device.Probe{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, request.Deadline)
	defer cancel()
	connection, err := Open(ctx, c.options, credential)
	if err != nil {
		return device.Probe{}, err
	}
	defer connection.Close(context.Background())
	if err := connection.Subscribe(ctx, responseTopic); err != nil {
		return device.Probe{}, err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return device.Probe{}, fmt.Errorf("invalid MQTT probe request")
	}
	if err := connection.Publish(ctx, requestTopic, payload); err != nil {
		return device.Probe{}, err
	}
	select {
	case <-ctx.Done():
		return device.Probe{}, fmt.Errorf("MQTT application response unavailable: %w", device.ErrUnknown)
	case err := <-connection.Errors():
		return device.Probe{}, err
	case message, ok := <-connection.Messages():
		if !ok {
			return device.Probe{}, fmt.Errorf("MQTT connection ended before application verification: %w", device.ErrUnknown)
		}
		return MatchResponse(request, responseTopic, message, c.options.Now())
	}
}

// MatchResponse rejects retained, malformed and differently scoped messages.
func MatchResponse(request device.Probe, topic string, message Message, now time.Time) (device.Probe, error) {
	_, expected, err := Topics(request.DeviceID, request.Generation)
	if err != nil || topic != expected || message.Retained || message.Topic != topic || len(message.Payload) == 0 || len(message.Payload) > MaxPayload {
		return device.Probe{}, fmt.Errorf("MQTT response scope or retention mismatch: %w", device.ErrDenied)
	}
	var response device.Probe
	if err := strictjson.Decode(message.Payload, &response); err != nil {
		return device.Probe{}, fmt.Errorf("invalid MQTT application response: %w", device.ErrDenied)
	}
	if err := device.MatchProbe(request, response, now); err != nil {
		return device.Probe{}, err
	}
	return response, nil
}

type Message struct {
	Topic    string
	Payload  []byte
	Retained bool
}

type Connection struct {
	client   *paho.Client
	network  net.Conn
	timeout  time.Duration
	messages chan Message
	errors   chan error
}

func Open(ctx context.Context, options Options, credential device.Credential) (*Connection, error) {
	if credential.Recovery {
		return nil, fmt.Errorf("recovery credentials have no MQTT permission: %w", device.ErrDenied)
	}
	if err := credentials.ValidateCredential(credential); err != nil {
		return nil, err
	}
	return OpenTLS(ctx, options, credential.TLS)
}

// OpenTLS serves independent lab applications and responders, whose service
// certificates have no operational slot or credential generation.
func OpenTLS(ctx context.Context, options Options, certificate tls.Certificate) (*Connection, error) {
	endpoint, err := validateOptions(options)
	if err != nil {
		return nil, err
	}
	leaf, err := credentials.ValidateTLSCertificate(certificate)
	if err != nil {
		return nil, err
	}
	certificate.Leaf = leaf
	now := time.Now()
	if options.Now != nil {
		now = options.Now()
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny {
			return nil, fmt.Errorf("MQTT certificate has unrestricted usage: %w", device.ErrDenied)
		}
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !clientAuth || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || strings.HasPrefix(leaf.Subject.CommonName, "recovery.") {
		return nil, fmt.Errorf("MQTT certificate is not a usable operational or application credential: %w", device.ErrDenied)
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	dial := options.dialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: options.Timeout}).DialContext
	}
	raw, err := dial(ctx, "tcp", endpoint.Host)
	if err != nil {
		return nil, fmt.Errorf("MQTT network unavailable: %w", device.ErrUnknown)
	}
	network := tls.Client(raw, &tls.Config{RootCAs: options.Roots.Clone(), ServerName: endpoint.Hostname(), Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err := network.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("MQTT mutual TLS could not be established: %w", device.ErrUnknown)
	}
	id, err := device.RandomID()
	if err != nil {
		network.Close()
		return nil, err
	}
	connection := &Connection{network: network, timeout: options.Timeout, messages: make(chan Message, 16), errors: make(chan error, 1)}
	bounded := &packetConn{Conn: network, writeTimeout: options.Timeout}
	connection.client = paho.NewClient(paho.ClientConfig{
		Conn: packets.NewThreadSafeConn(bounded), PacketTimeout: options.Timeout,
		OnClientError: func(error) { connection.fail(fmt.Errorf("MQTT connection ended: %w", device.ErrUnknown)) },
		OnServerDisconnect: func(disconnect *paho.Disconnect) {
			if disconnect != nil && (disconnect.ReasonCode == 0x87 || disconnect.ReasonCode == 0x86) {
				connection.fail(fmt.Errorf("MQTT server denied access: %w", device.ErrDenied))
			} else {
				connection.fail(fmt.Errorf("MQTT server ended the session: %w", device.ErrUnknown))
			}
		},
		OnPublishReceived: []func(paho.PublishReceived) (bool, error){func(received paho.PublishReceived) (bool, error) {
			if received.Packet == nil || len(received.Packet.Payload) > MaxPayload || len(received.Packet.Topic) > 256 {
				connection.fail(fmt.Errorf("MQTT application message exceeds limits: %w", device.ErrDenied))
				return true, nil
			}
			message := Message{Topic: received.Packet.Topic, Payload: bytes.Clone(received.Packet.Payload), Retained: received.Packet.Retain}
			select {
			case connection.messages <- message:
			default:
				connection.fail(fmt.Errorf("MQTT application queue full: %w", device.ErrUnknown))
			}
			return true, nil
		}},
	})
	maximum := uint32(MaxPacketSize)
	zero := uint32(0)
	receiveMaximum := uint16(16)
	connack, connectErr := connection.client.Connect(ctx, &paho.Connect{ClientID: "kd-" + id, CleanStart: true, KeepAlive: 15, Properties: &paho.ConnectProperties{MaximumPacketSize: &maximum, SessionExpiryInterval: &zero, ReceiveMaximum: &receiveMaximum, RequestProblemInfo: false}})
	if connack != nil && connack.ReasonCode >= 0x80 {
		network.Close()
		return nil, reasonFailure("CONNECT", connack.ReasonCode)
	}
	if connectErr != nil || connack == nil || connack.ReasonCode != 0 {
		network.Close()
		return nil, fmt.Errorf("MQTT CONNECT result unavailable: %w", device.ErrUnknown)
	}
	go func() { <-connection.client.Done(); close(connection.messages) }()
	return connection, nil
}

func (c *Connection) fail(err error) {
	select {
	case c.errors <- err:
	default:
	}
}

func (c *Connection) Messages() <-chan Message { return c.messages }
func (c *Connection) Errors() <-chan error     { return c.errors }
func (c *Connection) Done() <-chan struct{}    { return c.client.Done() }

func validTopic(topic string, subscription bool) bool {
	if topic == "" || len(topic) > 256 || !utf8.ValidString(topic) || strings.ContainsRune(topic, 0) || strings.HasPrefix(topic, "$share/") {
		return false
	}
	if !subscription && strings.ContainsAny(topic, "+#") {
		return false
	}
	return true
}

func reasonFailure(operation string, reason byte) error {
	if reason == 0x87 || reason == 0x86 {
		if reason == 0x87 && (operation == "SUBSCRIBE" || operation == "PUBLISH") {
			return fmt.Errorf("MQTT %s explicitly denied (0x%02x): %w: %w", operation, reason, device.ErrDenied, ErrACL)
		}
		return fmt.Errorf("MQTT %s explicitly denied (0x%02x): %w", operation, reason, device.ErrDenied)
	}
	if reason == 0x9e || reason == 0xa1 || reason == 0xa2 {
		return fmt.Errorf("MQTT %s capability unavailable (0x%02x): %w", operation, reason, device.ErrUnsupported)
	}
	return fmt.Errorf("MQTT %s failed (0x%02x): %w", operation, reason, device.ErrUnknown)
}

func (c *Connection) Subscribe(ctx context.Context, topic string) error {
	if !validTopic(topic, true) {
		return fmt.Errorf("invalid MQTT subscription topic")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	response, err := c.client.Subscribe(ctx, &paho.Subscribe{Subscriptions: []paho.SubscribeOptions{{Topic: topic, QoS: 1, NoLocal: true, RetainHandling: 2, RetainAsPublished: true}}})
	if response != nil && len(response.Reasons) == 1 && response.Reasons[0] >= 0x80 {
		return reasonFailure("SUBSCRIBE", response.Reasons[0])
	}
	if err != nil || response == nil || len(response.Reasons) != 1 || response.Reasons[0] > 1 {
		return fmt.Errorf("MQTT subscription result unavailable: %w", device.ErrUnknown)
	}
	return nil
}

func (c *Connection) Publish(ctx context.Context, topic string, payload []byte) error {
	if !validTopic(topic, false) || len(payload) == 0 || len(payload) > MaxPayload {
		return fmt.Errorf("invalid MQTT publish topic or payload size")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	expiry := uint32(c.timeout.Seconds()) + 1
	response, err := c.client.Publish(ctx, &paho.Publish{Topic: topic, Payload: bytes.Clone(payload), QoS: 1, Retain: false, Properties: &paho.PublishProperties{ContentType: "application/json", MessageExpiry: &expiry}})
	if response != nil && response.ReasonCode >= 0x80 {
		return reasonFailure("PUBLISH", response.ReasonCode)
	}
	if err != nil || response == nil || (response.ReasonCode != 0 && response.ReasonCode != 0x10) {
		return fmt.Errorf("MQTT publish result unavailable: %w", device.ErrUnknown)
	}
	return nil
}

func (c *Connection) Close(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	// Closing the network first also bounds Disconnect when the peer stops reading.
	_ = c.network.SetWriteDeadline(time.Now().Add(c.timeout))
	done := make(chan error, 1)
	go func() { done <- c.client.Disconnect(&paho.Disconnect{ReasonCode: 0}) }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("MQTT close acknowledgment unavailable: %w", device.ErrUnknown)
		}
		return nil
	case <-ctx.Done():
		c.network.Close()
		return fmt.Errorf("MQTT close deadline reached: %w", device.ErrUnknown)
	}
}
