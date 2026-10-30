// SPDX-License-Identifier: Apache-2.0

package continuity

import "fmt"

// Scenarios returns the supported, deterministic in-memory fixtures.
func Scenarios() []string {
	return []string{"rotation", "acl-denied", "clock-untrusted", "revoked", "missing-recovery"}
}

// Report separates the fixture result from the observed device state. A
// correctly detected failure can pass the fixture while leaving it blocked.
type Report struct {
	SchemaVersion string     `json:"schemaVersion"`
	Scope         string     `json:"scope"`
	Scenario      string     `json:"scenario"`
	FixturePassed bool       `json:"fixturePassed"`
	Outcome       string     `json:"outcome"`
	Reason        string     `json:"reason"`
	Checkpoints   []Snapshot `json:"checkpoints"`
}

// Simulate models ordering and policy stops without I/O or cryptography.
func Simulate(scenario string) (Report, error) {
	r := Report{
		SchemaVersion: "knowndevice/v1alpha1", Scope: "in-memory-model",
		Scenario: scenario, Outcome: "blocked",
	}
	o, err := NewOperation(1)
	if err != nil {
		return Report{}, err
	}
	r.Checkpoints = []Snapshot{o.Snapshot()}
	switch scenario {
	case "clock-untrusted":
		r.Reason = "a trusted wall clock is required"
	case "revoked":
		r.Reason = "the fixture registry denies recovery for a revoked device"
	case "missing-recovery":
		r.Reason = "no separate recovery credential is configured"
	case "rotation", "acl-denied":
		for _, phase := range []Phase{Planned, Staged, Registered, Verified, Committed, Retired} {
			if scenario == "acl-denied" && phase == Verified {
				r.Reason = "the fixture application probe was denied; generation 1 remains active"
				break
			}
			if err := o.Advance(phase); err != nil {
				return Report{}, err
			}
			r.Checkpoints = append(r.Checkpoints, o.Snapshot())
		}
		if scenario == "rotation" {
			r.Outcome = "completed"
			r.Reason = "the model verified generation 2 before committing and retiring generation 1"
		}
	default:
		return Report{}, fmt.Errorf("unknown scenario %q", scenario)
	}
	r.FixturePassed = true
	return r, nil
}
