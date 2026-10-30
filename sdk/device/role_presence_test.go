// SPDX-License-Identifier: Apache-2.0

package device_test

import (
	"errors"
	"testing"

	"knowndevice.local/knowndevice/adapters/profilehttp"
	"knowndevice.local/knowndevice/sdk/device"
)

func TestLegacyRolesRefuseEveryTypedNilBeforeFacade(t *testing.T) {
	client := &profilehttp.Client{}
	base := device.Roles{Entitlement: client, Platform: client, Transport: client, Application: client, Withdrawal: client, Clock: device.SystemClock{}}
	for _, remove := range []func(*device.Roles){
		func(r *device.Roles) { r.Entitlement = (*profilehttp.Client)(nil) },
		func(r *device.Roles) { r.Platform = (*profilehttp.Client)(nil) },
		func(r *device.Roles) { r.Transport = (*profilehttp.Client)(nil) },
		func(r *device.Roles) { r.Application = (*profilehttp.Client)(nil) },
		func(r *device.Roles) { r.Withdrawal = (*profilehttp.Client)(nil) },
		func(r *device.Roles) { r.Clock = (*device.SystemClock)(nil) },
	} {
		roles := base
		remove(&roles)
		if !errors.Is(roles.Validate(), device.ErrUnsupported) {
			t.Fatal("missing role was accepted")
		}
		if facade, err := roles.LegacyFacade(); facade != nil || !errors.Is(err, device.ErrUnsupported) {
			t.Fatal("missing role reached the controller facade")
		}
	}
}
