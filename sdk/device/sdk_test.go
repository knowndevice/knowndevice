// SPDX-License-Identifier: Apache-2.0

package device_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/knowndevice/knowndevice/adapters/controlhttp"
	"github.com/knowndevice/knowndevice/adapters/mqttprobe"
	"github.com/knowndevice/knowndevice/adapters/profilehttp"
	"github.com/knowndevice/knowndevice/adapters/stepca"
	"github.com/knowndevice/knowndevice/sdk/credentialprofile"
	"github.com/knowndevice/knowndevice/sdk/device"
)

var (
	_ device.Authority    = (*profilehttp.Client)(nil)
	_ device.Importer     = (*profilehttp.Client)(nil)
	_ device.Entitlement  = (*profilehttp.Client)(nil)
	_ device.Registration = (*profilehttp.Client)(nil)
	_ device.Transport    = (*profilehttp.Client)(nil)
	_ device.Application  = (*profilehttp.Client)(nil)
	_ device.Withdrawal   = (*profilehttp.Client)(nil)
	_ device.Clock        = device.SystemClock{}
	_ device.Authority    = (*stepca.Client)(nil)
	_ device.Authority    = (*controlhttp.Client)(nil)
	_ device.Importer     = (*controlhttp.Client)(nil)
	_ device.Platform     = (*controlhttp.Client)(nil)
	_ device.Transport    = (*mqttprobe.Client)(nil)
)

func TestPublicRolesRefuseIncompleteComposition(t *testing.T) {
	client := &profilehttp.Client{}
	a := device.Adapters{Entitlement: client, Authority: client, Platform: client, Transport: client, Application: client, Clock: device.SystemClock{}, Withdrawal: client}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, remove := range []func(*device.Adapters){
		func(a *device.Adapters) { a.Entitlement = nil },
		func(a *device.Adapters) { a.Authority = nil },
		func(a *device.Adapters) { a.Platform = nil },
		func(a *device.Adapters) { a.Transport = nil },
		func(a *device.Adapters) { a.Application = nil },
		func(a *device.Adapters) { a.Clock = nil },
		func(a *device.Adapters) { a.Withdrawal = nil },
		func(a *device.Adapters) { a.Authority = (*profilehttp.Client)(nil) },
	} {
		incomplete := a
		remove(&incomplete)
		if err := incomplete.Validate(); !errors.Is(err, device.ErrUnsupported) {
			t.Fatal("incomplete composition was accepted")
		}
	}
	if _, err := device.RequiredCapability("mqtt"); !errors.Is(err, device.ErrUnsupported) {
		t.Fatal("wire protocol was treated as a universal adapter role")
	}
}

func TestPublicProfilesUseTheSelectedIdentityPolicy(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{credentialprofile.ReferenceID, credentialprofile.StableID} {
		policy, err := credentialprofile.Find(id, 1)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := policy.CreateCSR(key, "sdk-consumer", 2)
		if err != nil {
			t.Fatal(err)
		}
		request, err := policy.ValidateCSR(csr, "sdk-consumer", 2)
		if err != nil {
			t.Fatal(err)
		}
		if id == credentialprofile.StableID && (request.Subject.CommonName != "sdk-consumer" || len(request.DNSNames) != 0) {
			t.Fatal("reference certificate naming leaked into the stable profile")
		}
		if id == credentialprofile.ReferenceID && request.Subject.CommonName != "g2.sdk-consumer.known-device.invalid" {
			t.Fatal("reference profile identity changed")
		}
	}
}

func TestSignerCredentialCannotBecomeJSON(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := device.Credential{TLS: tls.Certificate{PrivateKey: key}}
	data, err := json.Marshal(credential)
	if len(data) != 0 || !errors.Is(err, device.ErrUnsupported) {
		t.Fatal("signer-bearing credential was serialized")
	}
	marker := "SECRET_PRIVATE_MATERIAL_MARKER"
	if err = json.Unmarshal([]byte(`{"TLS":{"PrivateKey":"`+marker+`"}}`), &credential); !errors.Is(err, device.ErrUnsupported) || strings.Contains(err.Error(), marker) || credential.TLS.PrivateKey != key {
		t.Fatal("private input was accepted, exposed or replaced the signer")
	}
}
