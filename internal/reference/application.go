// SPDX-License-Identifier: Apache-2.0

package reference

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/knowndevice/knowndevice/adapters/controlhttp"
	"github.com/knowndevice/knowndevice/adapters/credentials"
	"github.com/knowndevice/knowndevice/adapters/mqttprobe"
	"github.com/knowndevice/knowndevice/internal/controller"
	"github.com/knowndevice/knowndevice/internal/device"
	"github.com/knowndevice/knowndevice/internal/keystore"
)

type worker struct {
	mu        sync.Mutex
	dir       string
	config    device.Config
	active    *controlhttp.Request
	session   *mqttprobe.Connection
	options   mqttprobe.Options
	sessionID string
}

func (w *worker) connect(ctx context.Context, request controlhttp.Request) (*mqttprobe.Connection, string, device.Credential, error) {
	if request.Handle == nil {
		return nil, "", device.Credential{}, device.ErrDenied
	}
	keys, err := keystore.OpenReadOnly(filepath.Join(w.config.StateDir, "slots"))
	if err != nil {
		return nil, "", device.Credential{}, err
	}
	defer keys.Close()
	engine := controller.Engine{Config: w.config, Keys: keys}
	credential, err := controller.CredentialFor(ctx, &engine, *request.Handle)
	if err != nil {
		return nil, "", credential, err
	}
	if w.active != nil && w.active.Plan == request.Plan && w.session != nil {
		select {
		case <-w.session.Done():
		default:
			return w.session, w.sessionID, credential, nil
		}
	}
	candidate, err := mqttprobe.Open(ctx, w.options, credential)
	if err != nil {
		return nil, "", credential, err
	}
	_, reply, _ := mqttprobe.Topics(w.config.DeviceID, credential.Handle.Binding.Generation)
	if err := candidate.Subscribe(ctx, reply); err != nil {
		candidate.Close(context.Background())
		return nil, "", credential, err
	}
	id, err := device.RandomID()
	if err != nil {
		candidate.Close(context.Background())
		return nil, "", credential, err
	}
	return candidate, id, credential, nil
}

func (w *worker) observe(ctx context.Context, request controlhttp.Request) (device.Activation, *mqttprobe.Connection, error) {
	connection, id, credential, err := w.connect(ctx, request)
	if err != nil {
		return device.Activation{}, nil, err
	}
	accepted := false
	defer func() {
		if !accepted && connection != w.session {
			connection.Close(context.Background())
		}
	}()
	nonce, err := device.RandomID()
	if err != nil {
		return device.Activation{}, nil, err
	}
	probe := device.Probe{OperationID: request.Plan.OperationID, DeviceID: w.config.DeviceID, Generation: request.Plan.TargetGeneration, Endpoint: w.config.MQTTEndpoint, Nonce: nonce, Deadline: time.Now().UTC().Add(w.config.Timeout())}
	pub, sub, _ := mqttprobe.Topics(probe.DeviceID, probe.Generation)
	payload, _ := json.Marshal(probe)
	if err := connection.Publish(ctx, pub, payload); err != nil {
		return device.Activation{}, nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, probe.Deadline)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return device.Activation{}, nil, device.ErrUnknown
		case <-connection.Done():
			return device.Activation{}, nil, device.ErrUnknown
		case err := <-connection.Errors():
			return device.Activation{}, nil, err
		case message, ok := <-connection.Messages():
			if !ok {
				return device.Activation{}, nil, device.ErrUnknown
			}
			var candidate device.Probe
			if json.Unmarshal(message.Payload, &candidate) != nil || candidate.Nonce != probe.Nonce {
				continue
			}
			response, err := mqttprobe.MatchResponse(probe, sub, message, time.Now())
			if err != nil {
				return device.Activation{}, nil, err
			}
			accepted = true
			return device.Activation{OperationID: request.Plan.OperationID, PlanDigest: request.Plan.Digest, DeviceID: w.config.DeviceID, ApplicationID: w.config.ApplicationID, Generation: request.Plan.TargetGeneration, CertificateFingerprint: device.Hash(credential.TLS.Certificate[0]), SessionID: id, Probe: response}, connection, nil
		}
	}
}

func (w *worker) request(out http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(out, "method denied", 405)
		return
	}
	var input controlhttp.Request
	if err := device.DecodeStrict(http.MaxBytesReader(out, req.Body, 128<<10), &input); err != nil {
		http.Error(out, "invalid request", 400)
		return
	}
	response := controlhttp.Response{OperationID: input.Plan.OperationID, PlanDigest: input.Plan.Digest, DeviceID: input.Plan.DeviceID, Generation: input.Plan.TargetGeneration, Status: "denied"}
	w.mu.Lock()
	defer w.mu.Unlock()
	status := req.URL.Path == "/v1/activation" || req.URL.Path == "/v1/observed"
	now := time.Now()
	if status {
		now = input.Plan.ExpiresAt.Add(-time.Nanosecond)
	}
	digest, err := w.config.Digest()
	var ent entitlement
	entErr := readJSON(filepath.Join(w.dir, "fixtures", "entitlement.json"), &ent)
	peerValid := req.TLS != nil && len(req.TLS.PeerCertificates) > 0
	observer := req.URL.Path == "/v1/observed"
	if peerValid {
		if observer {
			peerValid = req.TLS.PeerCertificates[0].Subject.CommonName == "broker-control" && device.Hash(req.TLS.PeerCertificates[0].Raw) == ent.ControlFingerprint
		} else {
			peerValid = req.TLS.PeerCertificates[0].Subject.CommonName == device.Subject(input.Plan.DeviceID, input.Plan.TargetGeneration)
			fingerprint, err := credentials.CertificateFingerprint(input.Certificate)
			peerValid = peerValid && err == nil && fingerprint == device.Hash(req.TLS.PeerCertificates[0].Raw)
		}
	}
	valid := input.Plan.Validate(now) == nil && err == nil && input.Plan.ConfigDigest == digest && input.Plan.DeviceID == w.config.DeviceID && input.Handle != nil && input.Handle.Binding == input.Plan.Binding() && peerValid && entErr == nil && ent.Status == "authorized" && ent.DeviceID == input.Plan.DeviceID
	if valid && (req.URL.Path == "/v1/activate" || status) {
		if status && (w.active == nil || w.active.Plan != input.Plan) {
			response.Status = "not-found"
		} else if w.active != nil && w.active.Plan != input.Plan && (input.Plan.ExpectedGeneration != w.active.Plan.TargetGeneration || input.Plan.TargetGeneration <= w.active.Plan.TargetGeneration) {
			response.Status = "conflict"
		} else {
			activation, candidate, err := w.observe(req.Context(), input)
			if err != nil {
				response.Status = "unknown"
			} else {
				var fixture policy
				fixtureErr := readJSON(filepath.Join(w.dir, "fixtures", "policy.json"), &fixture)
				durable := true
				if !status {
					if fixtureErr != nil || fixture.DenyActivation {
						durable = false
					} else if writeJSON(filepath.Join(w.dir, "application", "active.json"), input) != nil {
						durable = false
					}
				}
				if durable {
					old := w.session
					w.active = &input
					w.session = candidate
					w.sessionID = activation.SessionID
					if old != nil && old != candidate {
						old.Close(context.Background())
					}
					response.Status = "ok"
					response.Activation = &activation
				} else {
					if candidate != w.session {
						candidate.Close(context.Background())
					}
					response.Status = "unknown"
				}
			}
		}
	}
	out.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(out).Encode(response)
}

func runApplication(dir string) error {
	cfg, err := device.LoadConfig(filepath.Join(dir, "device.json"))
	if err != nil {
		return err
	}
	roots, err := cfg.Roots()
	if err != nil {
		return err
	}
	w := &worker{dir: dir, config: cfg, options: mqttprobe.Options{Endpoint: cfg.MQTTEndpoint, Roots: roots, Timeout: cfg.Timeout()}}
	var prior controlhttp.Request
	if err := readJSON(filepath.Join(dir, "application", "active.json"), &prior); err == nil {
		w.active = &prior
	} else if !os.IsNotExist(err) {
		return err
	}
	tlsConfig, err := serverTLS(dir, "application")
	if err != nil {
		return err
	}
	server := &http.Server{Addr: ":9443", Handler: http.HandlerFunc(w.request), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	return server.ListenAndServeTLS("", "")
}

func runResponder(dir string) error {
	cfg, err := device.LoadConfig(filepath.Join(dir, "device.json"))
	if err != nil {
		return err
	}
	roots, err := cfg.Roots()
	if err != nil {
		return err
	}
	cert, err := keystore.LoadServiceCredential(filepath.Join(dir, "responder", "cert.pem"), filepath.Join(dir, "responder", "key.pem"), x509.ExtKeyUsageClientAuth)
	if err != nil {
		return err
	}
	options := mqttprobe.Options{Endpoint: cfg.MQTTEndpoint, Roots: roots, Timeout: cfg.Timeout()}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout())
		c, err := mqttprobe.OpenTLS(ctx, options, cert)
		cancel()
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if err := c.Subscribe(context.Background(), "kd/+/+/request"); err != nil {
			c.Close(context.Background())
			return fmt.Errorf("responder MQTT subscription denied")
		}
		loop := true
		for loop {
			select {
			case <-c.Done():
				loop = false
			case <-c.Errors():
				loop = false
			case msg, ok := <-c.Messages():
				if !ok {
					loop = false
					break
				}
				if msg.Retained {
					continue
				}
				var p device.Probe
				if device.DecodeStrict(bytes.NewReader(msg.Payload), &p) != nil || p.DeviceID != cfg.DeviceID || p.Endpoint != cfg.MQTTEndpoint || device.MatchProbe(p, p, time.Now()) != nil {
					continue
				}
				topic, response, _ := mqttprobe.Topics(p.DeviceID, p.Generation)
				if msg.Topic != topic {
					continue
				}
				var fixture policy
				if readJSON(filepath.Join(dir, "fixtures", "policy.json"), &fixture) == nil && fixture.StaleReply {
					p.Nonce = "00000000000000000000000000000000"
				}
				payload, _ := json.Marshal(p)
				_ = c.Publish(context.Background(), response, payload)
			}
		}
		c.Close(context.Background())
		time.Sleep(200 * time.Millisecond)
	}
}
