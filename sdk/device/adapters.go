// SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"reflect"
)

// Importer reconciles an exact existing issuance reservation with recovered public material.
// Implementing this interface does not imply a vendor operation lookup or a retry guarantee.
type Importer interface {
	Import(context.Context, IssueRequest, []byte) error
}

// Adapters assigns each RFC 0005 role to its selected implementation.
// Presence of an interface does not establish its capabilities or trust policy.
type Adapters struct {
	Entitlement Entitlement
	Authority   Authority
	Platform    Registration
	Transport   Transport
	Application Application
	Clock       Clock
	Withdrawal  Withdrawal
}

// Validate refuses an incomplete composition before any domain operation.
func (a Adapters) Validate() error {
	for _, role := range []any{a.Entitlement, a.Authority, a.Platform, a.Transport, a.Application, a.Clock, a.Withdrawal} {
		if missingRole(role) {
			return ErrUnsupported
		}
	}
	return nil
}

func missingRole(role any) bool {
	if role == nil {
		return true
	}
	value := reflect.ValueOf(role)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}

// RequiredCapability returns the required declared capability for a reviewed role.
// Capability names alone do not authorize an effect or establish runtime support.
func RequiredCapability(role string) (string, error) {
	capability, ok := requiredCapabilities[role]
	if !ok {
		return "", ErrUnsupported
	}
	return capability, nil
}
