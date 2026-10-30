// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"knowndevice.local/knowndevice/adapters/process"
	"knowndevice.local/knowndevice/adapters/profilehttp"
	"knowndevice.local/knowndevice/sdk/device"
)

func main() {
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "adapter executable identity unavailable")
		os.Exit(2)
	}
	digest, err := process.ExecutableDigest(executable)
	if err != nil {
		fmt.Fprintln(os.Stderr, "adapter executable identity refused")
		os.Exit(2)
	}
	opts := process.ServerOptions{ArtifactDigest: digest, Factory: func(snapshot *device.PublicSnapshot) (device.Adapters, error) {
		client, err := profilehttp.New(snapshot)
		if err != nil {
			return device.Adapters{}, err
		}
		clock := device.SystemClock{Uncertainty: time.Second, MaximumAge: time.Duration(snapshot.Limits.MaximumAssessmentAgeSeconds) * time.Second, DriftPPM: float64(snapshot.Limits.DriftPPM)}
		return device.Adapters{Entitlement: client, Authority: client, Platform: client, Transport: client, Application: client, Clock: clock, Withdrawal: client}, nil
	}}
	if process.Serve(context.Background(), os.Stdin, os.Stdout, opts) != nil {
		fmt.Fprintln(os.Stderr, "adapter process stopped after protocol refusal")
		os.Exit(1)
	}
}
