// SPDX-License-Identifier: Apache-2.0

package device

import (
	"math"
	"testing"
	"time"
)

func TestP17ClockAgeDriftRestartAndFloor(t *testing.T) {
	at := time.Now()
	a := ClockAssessment{Earliest: at.Add(-time.Second), Latest: at.Add(time.Second), AssessedAt: at, DriftPPM: 50, MaximumAge: 10 * time.Second, Trusted: true, Source: "trusted-system-clock"}
	early, late, e := a.Interval(at.Add(5*time.Second), time.Time{})
	if e != nil || !early.Before(at.Add(4*time.Second)) || !late.After(at.Add(6*time.Second)) {
		t.Fatal("drift did not conservatively widen interval")
	}
	for _, change := range []func(*ClockAssessment){func(a *ClockAssessment) { a.Trusted = false }, func(a *ClockAssessment) { a.AssessedAt = at.Add(-11 * time.Second) }, func(a *ClockAssessment) { a.AssessedAt = at.Add(time.Second) }, func(a *ClockAssessment) { a.AssessedAt = time.Time{} }, func(a *ClockAssessment) { a.DriftPPM = math.Inf(1) }, func(a *ClockAssessment) { a.Latest = a.Earliest.Add(-time.Second) }} {
		bad := a
		change(&bad)
		if _, _, e = bad.Interval(at, time.Time{}); e == nil {
			t.Fatal("invalid/stale/restarted assessment accepted")
		}
	}
	if _, _, e = a.Interval(at, at); e == nil {
		t.Fatal("interval below durable floor accepted")
	}
}
func TestP19LegacyPlanDigestVector(t *testing.T) {
	p := Plan{APIVersion: "knowndevice/v1alpha1", OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DeviceID: "gateway", Mode: "rotate", ExpectedGeneration: 1, TargetGeneration: 2, TargetSlot: "B", ConfigDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ExpiresAt: time.Date(2026, 10, 12, 12, 5, 0, 0, time.UTC)}
	canonical := `{"apiVersion":"knowndevice/v1alpha1","operationId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","deviceId":"gateway","mode":"rotate","expectedGeneration":1,"targetGeneration":2,"targetSlot":"B","configDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expiresAt":"2026-10-12T12:05:00Z","digest":""}`
	got, e := p.CalculateDigest()
	if e != nil || got != Hash([]byte(canonical)) {
		t.Fatal("legacy canonical digest changed")
	}
	p.Digest = got
	if e = p.Validate(p.ExpiresAt.Add(-time.Minute)); e != nil {
		t.Fatal(e)
	}
	p.ProfileID = "stable-device-cn"
	if p.Validate(p.ExpiresAt.Add(-time.Minute)) == nil {
		t.Fatal("v2 field silently accepted in v1")
	}
}

func TestP17BackwardWallSampleCannotHideBehindMonotonicElapsed(t *testing.T) {
	at := time.Now()
	a := ClockAssessment{Earliest: at.Add(-time.Second), Latest: at.Add(time.Second), AssessedAt: at, DriftPPM: 50, MaximumAge: 10 * time.Second, Trusted: true, Source: "trusted-system-clock"}
	floor := at.UTC().Add(-2 * time.Second)
	now := at.Add(5 * time.Second)
	if _, _, e := a.Interval(now, floor); e != nil {
		t.Fatal(e)
	}
	if _, _, e := a.interval(now, floor.Add(-time.Nanosecond), floor); e == nil {
		t.Fatal("backward wall sample accepted while monotonic elapsed advanced")
	}
}

func TestP17ZeroBackdateCannotDisableV2Policy(t *testing.T) {
	l := DefaultLimits()
	l.MaxBackdateSeconds = 0
	if l.Validate() == nil {
		t.Fatal("zero backdate silently disabled the selected issuance policy")
	}
}

func TestP17CompositionCannotUnderstateClockUncertainty(t *testing.T) {
	for _, maximum := range []int{0, 999, 1000} {
		l := DefaultLimits()
		l.MaximumUncertaintyMillis = maximum
		if l.Validate() == nil {
			t.Fatalf("configured limit %d understated one-second clock uncertainty plus drift", maximum)
		}
	}
	l := DefaultLimits()
	l.MaximumUncertaintyMillis = 1001
	if err := l.Validate(); err != nil {
		t.Fatal(err)
	}
	l.MaximumUncertaintyMillis, l.DriftPPM = 1000, 0
	if err := l.Validate(); err != nil {
		t.Fatal(err)
	}
}
