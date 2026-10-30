// SPDX-License-Identifier: Apache-2.0

// Package continuity models the ordering of a credential rotation.
// Persistence and real device adapters are outside this bootstrap model.
package continuity

import "fmt"

// Phase identifies a checkpoint in a rotation, not the health of a device.
type Phase string

const (
	Ready      Phase = "ready"
	Planned    Phase = "planned"
	Staged     Phase = "staged"
	Registered Phase = "registered"
	Verified   Phase = "verified"
	Committed  Phase = "committed"
	Retired    Phase = "retired"
)

var nextPhase = map[Phase]Phase{
	Ready: Planned, Planned: Staged, Staged: Registered,
	Registered: Verified, Verified: Committed, Committed: Retired,
}

// Operation owns its checkpoint and generation counters so callers cannot
// bypass the verification requirement by changing fields directly.
type Operation struct {
	phase      Phase
	active     uint64
	target     uint64
	previous   uint64
	oldRetired bool
}

// Snapshot is public metadata. It contains no credential or key material.
type Snapshot struct {
	Phase              Phase  `json:"phase"`
	ActiveGeneration   uint64 `json:"activeGeneration"`
	TargetGeneration   uint64 `json:"targetGeneration"`
	PreviousGeneration uint64 `json:"previousGeneration"`
	PreviousRetired    bool   `json:"previousRetired"`
}

// NewOperation reserves the next generation for this modeled operation.
func NewOperation(active uint64) (*Operation, error) {
	if active == 0 || active == ^uint64(0) {
		return nil, fmt.Errorf("active generation must be between 1 and %d", ^uint64(0)-1)
	}
	return &Operation{phase: Ready, active: active, previous: active, target: active + 1}, nil
}

// Advance accepts only the next checkpoint. Verified is supplied by the
// simulator; a future controller must obtain and validate an adapter receipt.
func (o *Operation) Advance(to Phase) error {
	next, exists := nextPhase[o.phase]
	if !exists || next != to {
		return fmt.Errorf("rotation cannot move from %s to %s", o.phase, to)
	}
	if to == Committed {
		o.active = o.target
	}
	if to == Retired {
		o.oldRetired = true
	}
	o.phase = to
	return nil
}

// Snapshot returns a copy of the current metadata.
func (o *Operation) Snapshot() Snapshot {
	return Snapshot{o.phase, o.active, o.target, o.previous, o.oldRetired}
}
