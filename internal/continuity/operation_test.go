// SPDX-License-Identifier: Apache-2.0

package continuity

import "testing"

func TestOrderingAndGenerationSafety(t *testing.T) {
	sequence := []Phase{Ready, Planned, Staged, Registered, Verified, Committed, Retired}
	for i, phase := range sequence {
		t.Run(string(phase), func(t *testing.T) {
			o, err := NewOperation(7)
			if err != nil {
				t.Fatal(err)
			}
			for _, step := range sequence[1 : i+1] {
				if err := o.Advance(step); err != nil {
					t.Fatal(err)
				}
			}
			before := o.Snapshot()
			for _, candidate := range sequence {
				if i+1 < len(sequence) && candidate == sequence[i+1] {
					continue
				}
				if err := o.Advance(candidate); err == nil {
					t.Fatalf("accepted %s -> %s", phase, candidate)
				}
				if got := o.Snapshot(); got != before {
					t.Fatalf("rejected transition changed state: %+v", got)
				}
			}
			wantActive := uint64(7)
			if i >= 5 {
				wantActive = 8
			}
			if before.ActiveGeneration != wantActive || before.PreviousRetired != (phase == Retired) {
				t.Fatalf("unsafe generations at %s: %+v", phase, before)
			}
		})
	}
}

func TestGenerationBounds(t *testing.T) {
	for _, generation := range []uint64{0, ^uint64(0)} {
		if _, err := NewOperation(generation); err == nil {
			t.Fatalf("accepted invalid generation %d", generation)
		}
	}
}

func TestBlockedFixturesKeepActiveCredential(t *testing.T) {
	for _, scenario := range Scenarios()[1:] {
		r, err := Simulate(scenario)
		if err != nil {
			t.Fatal(err)
		}
		last := r.Checkpoints[len(r.Checkpoints)-1]
		if r.Outcome != "blocked" || !r.FixturePassed || last.ActiveGeneration != 1 || last.PreviousRetired {
			t.Fatalf("unsafe result for %s: %+v", scenario, r)
		}
	}
}

func TestSuccessfulFixture(t *testing.T) {
	r, err := Simulate("rotation")
	if err != nil {
		t.Fatal(err)
	}
	last := r.Checkpoints[len(r.Checkpoints)-1]
	if r.Outcome != "completed" || last.Phase != Retired || last.ActiveGeneration != 2 || !last.PreviousRetired {
		t.Fatalf("incomplete rotation: %+v", r)
	}
}

func TestUnknownScenario(t *testing.T) {
	if _, err := Simulate("power-loss"); err == nil {
		t.Fatal("power loss requires persistent storage; it must not appear implemented")
	}
}

func FuzzRejectedTransitionsPreserveState(f *testing.F) {
	f.Add("retired")
	f.Add("committed")
	f.Fuzz(func(t *testing.T, target string) {
		o, err := NewOperation(1)
		if err != nil {
			t.Fatal(err)
		}
		before := o.Snapshot()
		if err := o.Advance(Phase(target)); err != nil && o.Snapshot() != before {
			t.Fatal("rejected transition changed state")
		}
	})
}
