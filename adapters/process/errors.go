// SPDX-License-Identifier: Apache-2.0

package process

import (
	"errors"

	"github.com/knowndevice/knowndevice/sdk/device"
)

type ErrorData struct {
	Version   string `json:"version"`
	Kind      string `json:"kind"`
	Outcome   string `json:"outcome"`
	Retryable bool   `json:"retryable"`
	Scope     *Scope `json:"scope,omitempty"`
}
type RPCError struct {
	Code    int       `json:"code"`
	Message string    `json:"message"`
	Data    ErrorData `json:"data"`
}

type errorSpec struct {
	code                   int
	kind, message, outcome string
}

var errorSpecs = map[string]errorSpec{
	"parse-error":      {-32700, "parse-error", "Parse error", "denied"},
	"invalid-request":  {-32600, "invalid-request", "Invalid Request", "denied"},
	"method-not-found": {-32601, "method-not-found", "Method not found", "unsupported"},
	"invalid-params":   {-32602, "invalid-params", "Invalid params", "denied"},
	"internal-error":   {-32603, "internal-error", "Internal error", "unknown"},
	"unsupported":      {-32010, "unsupported", "Required capability unsupported", "unsupported"},
	"denied":           {-32011, "denied", "Authorization or application access denied", "denied"},
	"conflict":         {-32012, "conflict", "Operation binding or generation conflict", "conflict"},
	"unknown":          {-32013, "unknown", "Remote outcome unknown; reconciliation required", "unknown"},
	"adapter-failure":  {-32014, "adapter-failure", "Adapter failed; remote outcome unknown", "unknown"},
	"plan-expired":     {-32015, "plan-expired", "Original plan expired; intervention required", "intervention-required"},
	"not-started":      {-32016, "not-started", "Bound operation effect not started", "not-started"},
	"resource-limit":   {-32017, "resource-limit", "Resource limit exceeded; remote outcome unknown", "unknown"},
}

func rpcError(kind string, scope *Scope) *RPCError {
	spec, ok := errorSpecs[kind]
	if !ok {
		spec = errorSpecs["internal-error"]
	}
	return &RPCError{spec.code, spec.message, ErrorData{ErrorVersion, spec.kind, spec.outcome, false, scope}}
}

func backendError(err error, method string, scope *Scope) *RPCError {
	kind := "unknown"
	switch {
	case errors.Is(err, device.ErrUnsupported):
		kind = "unsupported"
	case errors.Is(err, device.ErrConflict):
		kind = "conflict"
	case errors.Is(err, device.ErrDenied):
		kind = "denied"
	case errors.Is(err, device.ErrPlanExpired):
		kind = "plan-expired"
	case errors.Is(err, device.ErrNotFound) && statusMethod(method):
		kind = "not-started"
	}
	if scope == nil {
		return rpcError("internal-error", nil)
	}
	return rpcError(kind, scope)
}

func mapError(remote *RPCError, method string, scope *Scope) error {
	if !validError(remote, method, scope) {
		return device.ErrUnknown
	}
	spec, ok := errorSpecs[remote.Data.Kind]
	if !ok || remote.Code != spec.code || remote.Message != spec.message || remote.Data.Version != ErrorVersion || remote.Data.Outcome != spec.outcome || remote.Data.Retryable {
		return device.ErrUnknown
	}
	if scope != nil && (remote.Data.Scope == nil || !scope.equal(*remote.Data.Scope)) {
		return device.ErrUnknown
	}
	if scope == nil && remote.Data.Scope != nil {
		return device.ErrUnknown
	}
	switch spec.kind {
	case "unsupported", "method-not-found":
		return device.ErrUnsupported
	case "denied", "invalid-params", "invalid-request", "parse-error":
		return device.ErrDenied
	case "conflict":
		return device.ErrConflict
	case "plan-expired":
		return device.ErrPlanExpired
	case "not-started":
		if statusMethod(method) && scope != nil {
			return device.ErrNotFound
		}
	}
	return device.ErrUnknown
}

func validError(remote *RPCError, method string, scope *Scope) bool {
	if remote == nil {
		return false
	}
	spec, ok := errorSpecs[remote.Data.Kind]
	if !ok || remote.Code != spec.code || remote.Message != spec.message || remote.Data.Version != ErrorVersion || remote.Data.Outcome != spec.outcome || remote.Data.Retryable {
		return false
	}
	if scope != nil && (remote.Data.Scope == nil || !scope.equal(*remote.Data.Scope)) {
		return false
	}
	if scope == nil && remote.Data.Scope != nil {
		return false
	}
	if spec.kind == "not-started" && (scope == nil || !statusMethod(method)) {
		return false
	}
	return true
}
