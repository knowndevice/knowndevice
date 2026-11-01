// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/knowndevice/knowndevice/adapters/process"
	"github.com/knowndevice/knowndevice/sdk/device"
)

var _ device.Clock = (*process.Client)(nil)

func inspectProcess(selected options) (processProof, error) {
	file, err := os.Open(selected.snapshot)
	if err != nil {
		return processProof{}, fmt.Errorf("open canonical public snapshot failed")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(process.MaxSnapshotBytes)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > process.MaxSnapshotBytes {
		return processProof{}, fmt.Errorf("public snapshot is unreadable or exceeds the process limit")
	}
	snapshot, err := device.DecodeSnapshot(data)
	if err != nil || snapshot.Composition.ID != "local-http-process-lab" || snapshot.Composition.Version != 1 {
		return processProof{}, fmt.Errorf("snapshot does not select the reviewed process composition")
	}
	base := selected.workDir
	if base == "" {
		base = filepath.Join(".cache", "sdk-consumer")
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return processProof{}, fmt.Errorf("create controlled process staging directory failed")
	}
	workDir, err := os.MkdirTemp(base, "session-")
	if err != nil {
		return processProof{}, fmt.Errorf("create unique process staging directory failed")
	}
	workDir, err = filepath.Abs(workDir)
	if err == nil {
		workDir, err = filepath.EvalSymlinks(workDir)
	}
	if err != nil {
		return processProof{}, fmt.Errorf("resolve controlled process staging directory failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := process.Start(ctx, process.Options{Executable: selected.adapter, ArtifactDigest: snapshot.Composition.ProcessArtifactDigest, WorkDir: workDir, Snapshot: snapshot, Log: io.Discard})
	if err != nil {
		return processProof{}, fmt.Errorf("process initialization failed")
	}
	closed := false
	defer func() {
		if !closed {
			_ = client.Close()
		}
	}()
	if err := client.Adapters().Validate(); err != nil {
		return processProof{}, fmt.Errorf("initialized process roles are incomplete")
	}
	assessment, err := client.Assess(ctx, time.Time{})
	if err != nil {
		return processProof{}, fmt.Errorf("initialized process clock assessment failed")
	}
	if _, _, err = assessment.Interval(time.Now(), time.Time{}); err != nil {
		return processProof{}, fmt.Errorf("process clock interval is stale or untrusted")
	}
	if err := client.Health(ctx); err != nil {
		return processProof{}, fmt.Errorf("initialized process session health failed")
	}
	if err := client.Close(); err != nil {
		closed = true
		return processProof{}, fmt.Errorf("close initialized process session failed")
	}
	closed = true
	return processProof{Scope: "initialized-process-session-and-clock", ProtocolVersion: process.ProtocolVersion, ErrorVersion: process.ErrorVersion, SchemaDigest: process.Schema().SHA256, ArtifactDigest: snapshot.Composition.ProcessArtifactDigest, SnapshotDigest: snapshot.Digest(), SessionHealth: "ready", ClockSource: assessment.Source, ClockTrusted: assessment.Trusted}, nil
}
