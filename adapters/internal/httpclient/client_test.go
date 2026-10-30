// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"knowndevice.local/knowndevice/adapters/internal/testtls"
	"knowndevice.local/knowndevice/sdk/device"
)

func TestMutualTLSAndNoSecretErrors(t *testing.T) {
	profile := testtls.New(t)
	credential := profile.Credential(t, device.Binding{DeviceID: "device-a", OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Generation: 1, Slot: "A"})
	var calls atomic.Int32
	server := testtls.HTTP(t, profile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != device.Subject("device-a", 1) {
			t.Error("actual signer-backed TLS credential missing")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ok":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		case "/redirect":
			w.Header().Set("Location", "https://other.invalid/leak")
			w.WriteHeader(307)
		case "/unknown":
			w.WriteHeader(500)
			fmt.Fprint(w, "private-key-secret-token")
		case "/denied":
			w.WriteHeader(403)
			fmt.Fprint(w, "private-key-secret-token")
		case "/oversized":
			fmt.Fprint(w, strings.Repeat("x", MaxBody+1))
		case "/trailing":
			fmt.Fprint(w, "{\"status\":\"ok\"} {\"secret\":\"leaked\"}")
		case "/fields":
			fmt.Fprint(w, "{\"status\":\"ok\",\"secret\":\"leaked\"}")
		case "/duplicate":
			fmt.Fprint(w, "{\"status\":\"unknown\",\"status\":\"ok\"}")
		}
	}))
	client, err := New(Options{URL: "https://lab.known-device.invalid", Roots: profile.Roots, Timeout: time.Second, DialContext: server.DialContext})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path     string
		sentinel error
	}{
		{path: "/ok"}, {path: "/redirect", sentinel: device.ErrUnknown}, {path: "/unknown", sentinel: device.ErrUnknown}, {path: "/denied", sentinel: device.ErrDenied}, {path: "/oversized", sentinel: device.ErrUnknown}, {path: "/trailing", sentinel: device.ErrUnknown}, {path: "/fields", sentinel: device.ErrUnknown}, {path: "/duplicate", sentinel: device.ErrUnknown},
	} {
		t.Run(test.path, func(t *testing.T) {
			before := calls.Load()
			var result struct {
				Status string `json:"status"`
			}
			err := client.Post(context.Background(), test.path, &credential, map[string]string{"ott": "private-key-secret-token"}, &result)
			if (test.sentinel == nil && err != nil) || (test.sentinel != nil && !errors.Is(err, test.sentinel)) {
				t.Fatalf("error = %v, want %v", err, test.sentinel)
			}
			if err != nil && (strings.Contains(err.Error(), "private-key-secret-token") || strings.Contains(err.Error(), "leaked")) {
				t.Fatal("remote secret appeared in an error")
			}
			if calls.Load() != before+1 {
				t.Fatal("request retried or redirected")
			}
		})
	}
}

func TestTLSValidationAndConfiguration(t *testing.T) {
	profile := testtls.New(t)
	for _, origin := range []string{"http://lab.known-device.invalid", "https://user:secret@lab.known-device.invalid", "https://lab.known-device.invalid/path", "https://lab.known-device.invalid?q=secret"} {
		if _, err := New(Options{URL: origin, Roots: profile.Roots, Timeout: time.Second}); err == nil {
			t.Fatalf("unsafe origin accepted: %s", origin)
		}
	}
	server := testtls.HTTP(t, profile, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS reached the handler") }))
	client, err := New(Options{URL: "https://lab.known-device.invalid", Roots: testtls.New(t).Roots, Timeout: time.Second, DialContext: server.DialContext})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Post(context.Background(), "/ok", nil, struct{}{}, new(any)); !errors.Is(err, device.ErrUnknown) {
		t.Fatalf("untrusted TLS error = %v", err)
	}
}
