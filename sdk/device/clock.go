// SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"math"
	"time"
)

// ClockAssessment retains a local assessment instant with monotonic continuity.
// A process response or restart requires a fresh host assessment, never a decoded instant.
type ClockAssessment struct {
	Earliest   time.Time
	Latest     time.Time
	AssessedAt time.Time
	DriftPPM   float64
	MaximumAge time.Duration
	Trusted    bool
	Source     string
}

func (a ClockAssessment) Interval(now, floor time.Time) (time.Time, time.Time, error) {
	return a.interval(now, now.UTC(), floor)
}

func (a ClockAssessment) interval(now, wallSample, floor time.Time) (time.Time, time.Time, error) {
	elapsed := now.Sub(a.AssessedAt)
	if wallSample.Before(floor.UTC()) || !a.Trusted || a.Source != "trusted-system-clock" || a.Earliest.IsZero() || a.Latest.Before(a.Earliest) || a.AssessedAt.IsZero() || elapsed < 0 || elapsed > a.MaximumAge || a.MaximumAge <= 0 || math.IsNaN(a.DriftPPM) || math.IsInf(a.DriftPPM, 0) || a.DriftPPM < 0 || a.DriftPPM > 1000 {
		return time.Time{}, time.Time{}, ErrDenied
	}
	drift := time.Duration(math.Ceil(float64(elapsed) * a.DriftPPM / 1e6))
	earliest := a.Earliest.Add(elapsed - drift)
	latest := a.Latest.Add(elapsed + drift)
	if earliest.Before(floor) {
		return time.Time{}, time.Time{}, ErrDenied
	}
	return earliest, latest, nil
}

type SystemClock struct {
	Uncertainty time.Duration
	MaximumAge  time.Duration
	DriftPPM    float64
}

func (c SystemClock) Assess(ctx context.Context, floor time.Time) (ClockAssessment, error) {
	if e := ctx.Err(); e != nil {
		return ClockAssessment{}, e
	}
	now := time.Now()
	a := ClockAssessment{Earliest: now.Add(-c.Uncertainty).UTC(), Latest: now.Add(c.Uncertainty).UTC(), AssessedAt: now, DriftPPM: c.DriftPPM, MaximumAge: c.MaximumAge, Trusted: true, Source: "trusted-system-clock"}
	if c.Uncertainty < 0 || a.Earliest.Before(floor) {
		return ClockAssessment{}, ErrDenied
	}
	return a, nil
}
