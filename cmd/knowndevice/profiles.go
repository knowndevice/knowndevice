// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"knowndevice.local/knowndevice/adapters/process"
	"knowndevice.local/knowndevice/internal/controller"
	"knowndevice.local/knowndevice/internal/device"
	"knowndevice.local/knowndevice/internal/journal"
	"knowndevice.local/knowndevice/internal/keystore"
)

func activeProbePlan(s device.State) (device.Plan, error) {
	if s.Active == nil {
		return device.Plan{}, fmt.Errorf("active generation required")
	}
	// V2 transport authorization binds the exact target credential to its plan.
	// A pending rotation retains its own plan, without the previous active plan.
	if s.Operation == nil || s.Operation.Plan.Binding() != s.Active.Binding {
		return device.Plan{}, fmt.Errorf("active V2 probe unavailable: original active-generation plan is not retained; device health is unknown")
	}
	return s.Operation.Plan, nil
}

func openJournal(ctx context.Context, path string, c device.Config) (*journal.Store, error) {
	if c.APIVersion == device.V2 {
		p := c.CredentialProfile
		return journal.OpenV2(ctx, path, c.DeploymentID, c.DeviceID, p.ID, p.Version, p.PolicyDigest)
	}
	return journal.Open(ctx, path, c.DeviceID)
}
func readJournal(ctx context.Context, path string, c device.Config) (device.State, error) {
	if c.APIVersion == device.V2 {
		p := c.CredentialProfile
		return journal.ReadV2(ctx, path, c.DeploymentID, c.DeviceID, p.ID, p.Version, p.PolicyDigest)
	}
	return journal.Read(ctx, path, c.DeviceID)
}
func openKeys(c device.Config, readonly bool) (*keystore.Store, error) {
	path := filepath.Join(c.StateDir, "slots")
	if c.APIVersion == device.V2 {
		p := c.CredentialProfile
		if readonly {
			return keystore.OpenReadOnlyV2(path, c.DeploymentID, c.DeviceID, p.ID, p.Version, p.PolicyDigest)
		}
		return keystore.OpenV2(path, c.DeploymentID, c.DeviceID, p.ID, p.Version, p.PolicyDigest)
	}
	if readonly {
		return keystore.OpenReadOnly(path)
	}
	return keystore.Open(path)
}
func configRoots(c device.Config) (*x509.CertPool, error) {
	if c.APIVersion == device.V2 {
		s, e := c.ResolveSnapshot()
		if e != nil {
			return nil, e
		}
		return s.Roots("operational")
	}
	return c.Roots()
}
func clockFor(s *device.PublicSnapshot) device.Clock {
	return device.SystemClock{Uncertainty: time.Second, MaximumAge: time.Duration(s.Limits.MaximumAssessmentAgeSeconds) * time.Second, DriftPPM: float64(s.Limits.DriftPPM)}
}

// Versioned adapter content is checked before planning or effects.
func verifyAdapterArtifacts(s *device.PublicSnapshot) error {
	executable, e := os.Executable()
	if e != nil {
		return device.ErrUnsupported
	}
	b, e := os.ReadFile(executable)
	if e != nil {
		return device.ErrUnsupported
	}
	actual := device.Hash(b)
	for _, a := range s.Composition.Adapters {
		if (a.Role == "clock" || a.Role == "transport") && a.ArtifactDigest != actual {
			return device.ErrConflict
		}
	}
	if s.Composition.ID == "local-http-process-lab" {
		path, err := processExecutable()
		if err != nil {
			return err
		}
		return process.VerifyExecutable(path, s.Composition.ProcessArtifactDigest)
	}
	return nil
}

func freshIdentityPreflight(ctx context.Context, c device.Config) error {
	state := device.State{SchemaVersion: 2, DeploymentID: c.DeploymentID, DeviceID: c.DeviceID, ProfileID: c.CredentialProfile.ID, ProfileVersion: c.CredentialProfile.Version, ProfileDigest: c.CredentialProfile.PolicyDigest}
	p, e := controller.NewPlan(c, state, "enroll", time.Now().UTC())
	if e != nil {
		return e
	}
	remote, e := remoteClient(ctx, c)
	if e != nil {
		return e
	}
	defer closeRemote(remote)
	recovery, e := recoveryCredential(c)
	if e != nil || recovery == nil {
		return device.ErrDenied
	}
	return remote.Authorize(ctx, p, recovery)
}
