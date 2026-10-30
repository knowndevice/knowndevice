// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"knowndevice.local/knowndevice/internal/continuity"
)

func TestCLIReportsBlockedFixtureWithoutClaimingDeviceSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"simulate", "--scenario", "acl-denied"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	var report continuity.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Outcome != "blocked" || report.Scope != "in-memory-model" || !report.FixturePassed || stderr.Len() != 0 {
		t.Fatalf("misleading report: %+v, stderr: %s", report, stderr.String())
	}
}

func TestCLIRejectsUnknownInputs(t *testing.T) {
	for _, args := range [][]string{{"apply"}, {"simulate", "--scenario", "power-loss"}, {"simulate", "extra"}, {"version", "extra"}} {
		var stdout, stderr bytes.Buffer
		if got := run(args, &stdout, &stderr); got != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("%v: code %d, stdout %q, stderr %q", args, got, stdout.String(), stderr.String())
		}
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestOutputFailureIsNotSuccess(t *testing.T) {
	var stderr bytes.Buffer
	if got := run([]string{"simulate"}, brokenWriter{}, &stderr); got != 4 {
		t.Fatalf("write failure returned %d", got)
	}
}
