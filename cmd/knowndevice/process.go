// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/knowndevice/knowndevice/adapters/process"
	"github.com/knowndevice/knowndevice/internal/device"
)

type composedRemote interface {
	remote
	SetPlan(device.Plan) error
	Roles() device.Roles
}

type processRemote struct{ *process.Client }

func (r processRemote) Roles() device.Roles {
	a := r.Adapters()
	return device.Roles{Entitlement: a.Entitlement, Platform: a.Platform, Transport: a.Transport, Application: a.Application, Clock: a.Clock, Withdrawal: a.Withdrawal}
}

func processExecutable() (string, error) {
	if path := os.Getenv("KNOWNDEVICE_PROCESS_ADAPTER"); path != "" {
		if !filepath.IsAbs(path) {
			return "", device.ErrDenied
		}
		return path, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return "", device.ErrUnsupported
	}
	return filepath.Join(filepath.Dir(executable), "kd-adapter"), nil
}

func processClient(ctx context.Context, c device.Config, s *device.PublicSnapshot) (remote, error) {
	path, err := processExecutable()
	if err != nil {
		return nil, err
	}
	workDir := filepath.Join(c.StateDir, ".process")
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return nil, device.ErrDenied
	}
	opts := process.Options{Executable: path, ArtifactDigest: s.Composition.ProcessArtifactDigest, WorkDir: workDir, Snapshot: s}
	if os.Getenv("KNOWNDEVICE_PROCESS_TIMING") == "1" {
		opts.Log = os.Stderr
	}
	client, err := process.Start(ctx, opts)
	if err != nil {
		return nil, err
	}
	return processRemote{client}, nil
}

func closeRemote(r remote) {
	if closer, ok := r.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}
