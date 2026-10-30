// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"knowndevice.local/knowndevice/adapters/controlhttp"
	"knowndevice.local/knowndevice/adapters/mqttprobe"
	"knowndevice.local/knowndevice/adapters/profilehttp"
	"knowndevice.local/knowndevice/internal/continuity"
	"knowndevice.local/knowndevice/internal/controller"
	"knowndevice.local/knowndevice/internal/device"
	"knowndevice.local/knowndevice/internal/keystore"
)

const version = "0.0.0-dev"

type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }
func main()                       { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, stdout, stderr io.Writer) int {
	root := command(stdout, stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(stderr, err)
		if e, ok := err.(exitError); ok {
			return e.code
		}
		return 2
	}
	return 0
}
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return exitError{4, fmt.Errorf("write report failed")}
	}
	return nil
}

func command(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "knowndevice", Short: "Device identity continuity for the local reference lab", SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(&cobra.Command{Use: "version", Short: "Print the development version", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		_, err := fmt.Fprintln(stdout, version)
		if err != nil {
			return exitError{4, err}
		}
		return nil
	}})
	var scenario string
	sim := &cobra.Command{Use: "simulate", Short: "Run a deterministic in-memory fixture", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		r, err := continuity.Simulate(scenario)
		if err != nil {
			return exitError{2, err}
		}
		return writeJSON(stdout, r)
	}}
	sim.Flags().StringVar(&scenario, "scenario", "rotation", "Fixture: "+strings.Join(continuity.Scenarios(), ", "))
	root.AddCommand(sim)
	shorts := map[string]string{"validate": "Validate strict JSON/YAML configuration", "init": "Initialize a private journal and two-slot store", "doctor": "Check local trust and recovery prerequisites", "status": "Read persisted metadata without a device health claim", "plan": "Print a side-effect-free bounded transition plan", "apply": "Apply the exact authorized plan through real adapters", "reconcile": "Resume the persisted operation through status lookups", "probe": "Probe the active generation against the external responder", "recover": "Check separate device recovery authorization"}
	for _, name := range []string{"validate", "init", "doctor", "status", "plan", "apply", "reconcile", "probe", "recover"} {
		var configPath, planPath, mode, certificatePath string
		var preflight bool
		name := name
		cmd := &cobra.Command{Use: name, Short: shorts[name], Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
			cfg, err := device.LoadConfig(configPath)
			if err != nil {
				return exitError{2, err}
			}
			return deviceCommand(c.Context(), name, cfg, planPath, mode, certificatePath, preflight, stdout)
		}}
		if name == "probe" {
			cmd.Long = "Probe the active generation against the external responder.\n\nV2 requires the retained original plan for that exact active credential and its\nremaining authorization lifetime. During a pending rotation, the previous active\nplan is no longer retained; probe exits 3 with an explicit unavailability reason\nand unknown device health. This limitation applies to HTTP and process adapters."
		}
		cmd.Flags().StringVar(&configPath, "config", "device.json", "Device profile path")
		if name == "plan" {
			cmd.Flags().StringVar(&mode, "mode", "rotate", "enroll, rotate or recover")
		}
		if name == "apply" {
			cmd.Flags().StringVar(&planPath, "plan", "", "Exact plan JSON path")
			_ = cmd.MarkFlagRequired("plan")
		}
		if name == "recover" {
			cmd.Flags().BoolVar(&preflight, "preflight", false, "Read current server entitlement without issuance")
		}
		if name == "reconcile" {
			cmd.Flags().StringVar(&certificatePath, "certificate", "", "Explicit recovered public certificate chain for an unknown issuance")
		}
		root.AddCommand(cmd)
	}
	root.AddCommand(&cobra.Command{Use: "reference", Short: "Print the CLI reference from this command tree", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		_, err := io.WriteString(stdout, reference(root))
		if err != nil {
			return exitError{4, err}
		}
		return nil
	}})
	return root
}

func deviceCommand(ctx context.Context, name string, cfg device.Config, planPath, mode, certificatePath string, preflight bool, stdout io.Writer) error {
	path := filepath.Join(cfg.StateDir, "journal.db")
	if cfg.APIVersion == device.V2 && (name == "apply" || name == "reconcile") {
		s, err := readJournal(ctx, path, cfg)
		if err != nil {
			return exitError{4, err}
		}
		if s.Operation != nil && s.Operation.Phase == device.Retired {
			p := s.Operation.Plan
			if name == "apply" {
				p, err = loadPlan(planPath)
				if err != nil {
					return exitError{2, err}
				}
			}
			if p == s.Operation.Plan {
				if certificatePath != "" {
					return exitError{3, fmt.Errorf("certificate import requires an unresolved issuance intent")}
				}
				r, err := controller.CompletedHistory(s, p)
				if err != nil {
					return exitError{4, err}
				}
				return writeJSON(stdout, r)
			}
		}
	}
	if cfg.APIVersion == device.V2 {
		snap, err := cfg.ResolveSnapshot()
		if err != nil {
			return exitError{3, err}
		}
		if err = verifyAdapterArtifacts(snap); err != nil {
			return exitError{3, fmt.Errorf("configured adapter artifact differs from this binary")}
		}
	}
	if name == "validate" {
		return writeJSON(stdout, map[string]any{"apiVersion": cfg.APIVersion, "scope": "configuration", "valid": true})
	}
	if name == "doctor" {
		if _, err := configRoots(cfg); err != nil {
			return exitError{3, err}
		}
		recovery, err := recoveryCredential(cfg)
		if err != nil {
			return exitError{3, fmt.Errorf("recovery credential unavailable")}
		}
		return writeJSON(stdout, map[string]any{"scope": "local-profile-preflight", "clockTrust": cfg.ClockTrust, "recoveryPresent": recovery != nil, "deviceHealth": "unknown"})
	}
	if name == "init" {
		if cfg.APIVersion == device.V2 {
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				if err = freshIdentityPreflight(ctx, cfg); err != nil {
					return exitError{3, fmt.Errorf("fresh identity initialization denied or unavailable")}
				}
			} else if err != nil {
				return exitError{4, err}
			}
		}
		store, err := openJournal(ctx, path, cfg)
		if err != nil {
			return exitError{4, err}
		}
		defer store.Close()
		keys, err := openKeys(cfg, false)
		if err != nil {
			return exitError{4, err}
		}
		defer keys.Close()
		state, err := store.Load(ctx)
		if err != nil {
			return exitError{4, err}
		}
		return writeJSON(stdout, controller.Report(state))
	}
	if name == "status" || name == "plan" || name == "probe" || name == "recover" {
		s, err := readJournal(ctx, path, cfg)
		if err != nil {
			return exitError{4, err}
		}
		if name == "status" {
			return writeJSON(stdout, controller.Report(s))
		}
		if name == "plan" {
			p, err := controller.NewPlan(cfg, s, mode, time.Now().UTC())
			if err != nil {
				return exitError{2, err}
			}
			return writeJSON(stdout, p)
		}
		var probePlan device.Plan
		if name == "probe" && cfg.APIVersion == device.V2 {
			probePlan, err = activeProbePlan(s)
			if err != nil {
				return exitError{3, err}
			}
		}
		remote, err := remoteClient(ctx, cfg)
		if err != nil {
			return exitError{3, err}
		}
		defer closeRemote(remote)
		if name == "recover" {
			if !preflight {
				return exitError{2, fmt.Errorf("recover requires --preflight; apply a plan with mode recover to mutate")}
			}
			if cfg.ClockTrust != "trusted-system-clock" || time.Now().Before(s.ClockFloor) {
				return exitError{3, fmt.Errorf("clock is untrusted or rolled back")}
			}
			mode := "recover"
			if s.Active == nil {
				mode = "enroll"
			}
			p, err := controller.NewPlan(cfg, s, mode, time.Now().UTC())
			if err != nil {
				return exitError{3, err}
			}
			recovery, err := recoveryCredential(cfg)
			if err != nil || recovery == nil {
				return exitError{3, fmt.Errorf("recovery credential unavailable")}
			}
			if err := remote.Authorize(ctx, p, recovery); err != nil {
				return exitError{3, fmt.Errorf("server recovery preflight denied or unavailable")}
			}
			return writeJSON(stdout, map[string]any{"scope": "server-recovery-preflight", "deviceId": cfg.DeviceID, "outcome": "authorized", "deviceHealth": "unknown"})
		}
		if cfg.ClockTrust != "trusted-system-clock" || time.Now().Before(s.ClockFloor) || s.Active == nil {
			return exitError{3, fmt.Errorf("trusted clock and active generation required")}
		}
		keys, err := openKeys(cfg, true)
		if err != nil {
			return exitError{4, err}
		}
		defer keys.Close()
		e := controller.Engine{Config: cfg, Keys: keys}
		if cfg.APIVersion == device.V2 {
			snap, err := cfg.ResolveSnapshot()
			if err != nil {
				return exitError{3, err}
			}
			e.Snapshot = snap
			e.Clock = clockFor(snap)
			if r, ok := remote.(composedRemote); ok {
				e.Clock = r.Roles().Clock
			}
			if r, ok := remote.(composedRemote); ok {
				if err = r.SetPlan(probePlan); err != nil {
					return exitError{3, err}
				}
			}
		}
		cred, err := controller.CredentialFor(ctx, &e, *s.Active)
		if err != nil {
			return exitError{3, err}
		}
		id := s.Active.Binding.OperationID
		nonce, err := device.RandomID()
		if err != nil {
			return err
		}
		endpoint := cfg.MQTTEndpoint
		scope := "mqtt-application-probe"
		if cfg.APIVersion == device.V2 {
			endpoint = cfg.TransportEndpoint
			scope = "http-application-probe"
		}
		p := device.Probe{OperationID: id, DeviceID: cfg.DeviceID, Generation: s.Active.Binding.Generation, Endpoint: endpoint, Nonce: nonce, Deadline: time.Now().UTC().Add(cfg.Timeout())}
		reply, err := remote.Probe(ctx, p, cred)
		if err != nil {
			return exitError{3, fmt.Errorf("active application probe failed")}
		}
		return writeJSON(stdout, struct {
			Scope string       `json:"scope"`
			Probe device.Probe `json:"probe"`
		}{scope, reply})
	}
	store, err := openJournal(ctx, path, cfg)
	if err != nil {
		return exitError{4, err}
	}
	defer store.Close()
	keys, err := openKeys(cfg, false)
	if err != nil {
		return exitError{4, err}
	}
	defer keys.Close()
	var p device.Plan
	if name == "apply" {
		p, err = loadPlan(planPath)
		if err != nil {
			return exitError{2, err}
		}
	} else {
		s, err := store.Load(ctx)
		if err != nil || s.Operation == nil {
			return exitError{3, fmt.Errorf("no persisted operation to reconcile")}
		}
		p = s.Operation.Plan
	}
	remote, err := remoteClient(ctx, cfg)
	if err != nil {
		return exitError{3, err}
	}
	defer closeRemote(remote)
	recovery, err := recoveryCredential(cfg)
	if err != nil {
		return exitError{3, fmt.Errorf("configured recovery credential invalid")}
	}
	e := controller.Engine{Config: cfg, Journal: store, Keys: keys, Authority: remote, Platform: remote, Recovery: recovery, Checkpoint: labCheckpoint(cfg.StateDir)}
	if cfg.APIVersion == device.V2 {
		snap, err := cfg.ResolveSnapshot()
		if err != nil {
			return exitError{3, err}
		}
		e.Snapshot = snap
		e.Clock = clockFor(snap)
		r, ok := remote.(composedRemote)
		if !ok {
			return exitError{3, device.ErrUnsupported}
		}
		if err = r.SetPlan(p); err != nil {
			return exitError{3, err}
		}
		e.Platform, err = r.Roles().LegacyFacade()
		if err != nil {
			return exitError{3, err}
		}
		e.Clock = r.Roles().Clock
	}
	if certificatePath != "" {
		s, err := store.Load(ctx)
		if err != nil || s.Operation == nil || s.Operation.Phase != device.IssueIntent {
			return exitError{3, fmt.Errorf("certificate import requires an unresolved issuance intent")}
		}
		f, err := os.Open(certificatePath)
		if err != nil {
			return exitError{2, fmt.Errorf("recovered certificate unreadable")}
		}
		chain, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
		f.Close()
		if err != nil || len(chain) > 64<<10 {
			return exitError{2, fmt.Errorf("recovered certificate unreadable or too large")}
		}
		var auth *device.Credential
		if p.Mode == "enroll" || p.Mode == "recover" {
			auth = recovery
		} else if s.Active != nil {
			cred, err := controller.CredentialFor(ctx, &e, *s.Active)
			if err != nil {
				return exitError{3, err}
			}
			auth = &cred
		}
		if cfg.ClockTrust != "trusted-system-clock" || time.Now().Before(s.ClockFloor) || auth == nil {
			return exitError{3, fmt.Errorf("certificate import preconditions denied")}
		}
		if err := remote.Import(ctx, device.IssueRequest{Plan: p, CSR: s.Operation.CSR, Credential: auth}, chain); err != nil {
			return exitError{3, fmt.Errorf("certificate import denied or unknown")}
		}
	}
	r, err := e.Apply(ctx, p)
	if writeErr := writeJSON(stdout, r); writeErr != nil {
		return writeErr
	}
	if err != nil {
		return exitError{3, fmt.Errorf("transition stopped: %s", r.Reason)}
	}
	return nil
}

func loadPlan(path string) (device.Plan, error) {
	var p device.Plan
	f, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer f.Close()
	err = device.DecodeStrict(f, &p)
	return p, err
}

type remote interface {
	device.Authority
	device.Platform
	Import(context.Context, device.IssueRequest, []byte) error
}

func remoteClient(ctx context.Context, c device.Config) (remote, error) {
	if c.APIVersion == device.V2 {
		s, e := c.ResolveSnapshot()
		if e != nil {
			return nil, e
		}
		if s.Composition.ID == "local-http-process-lab" {
			return processClient(ctx, c, s)
		}
		return profilehttp.New(s)
	}
	roots, err := c.Roots()
	if err != nil {
		return nil, err
	}
	probe, err := mqttprobe.New(mqttprobe.Options{Endpoint: c.MQTTEndpoint, Roots: roots, Timeout: c.Timeout()})
	if err != nil {
		return nil, err
	}
	return controlhttp.New(controlhttp.Options{ControlURL: c.ControlURL, ApplicationURL: c.ApplicationURL, ControlRoots: roots, ApplicationRoots: roots, CertificateRoots: roots, ApplicationID: c.ApplicationID, ProbeEndpoint: c.MQTTEndpoint, Timeout: c.Timeout(), ProbeTransport: probe})
}
func recoveryCredential(c device.Config) (*device.Credential, error) {
	if c.RecoveryCertificate == "" {
		return nil, nil
	}
	cert, err := keystore.LoadCredential(c.RecoveryCertificate, c.RecoveryKey)
	if err != nil {
		return nil, err
	}
	return &device.Credential{TLS: cert, Recovery: true, DeviceID: c.DeviceID}, nil
}
func labCheckpoint(stateDir string) func(string) error {
	if os.Getenv("KNOWNDEVICE_REFERENCE_LAB") != "1" || os.Getenv("KNOWNDEVICE_LAB_PAUSE_AT") == "" {
		return nil
	}
	return func(phase string) error {
		if phase != os.Getenv("KNOWNDEVICE_LAB_PAUSE_AT") {
			return nil
		}
		f, err := os.OpenFile(filepath.Join(stateDir, "checkpoint.marker"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = f.WriteString(phase)
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return err
		}
		for {
			time.Sleep(time.Second)
		}
	}
}
func reference(root *cobra.Command) string {
	var b strings.Builder
	b.WriteString("# CLI reference\n\nVersion: 0.0.0-dev. Device commands select explicit v1alpha1 reference or\nv1alpha2 credential profiles; fixtures report their separate in-memory scope.\n\n")
	for _, c := range root.Commands() {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		description := c.Short + "."
		if c.Long != "" {
			description = c.Long
		}
		fmt.Fprintf(&b, "## `%s`\n\n%s\n\n```text\n%s\n```\n\n", c.CommandPath(), description, c.Flags().FlagUsages())
	}
	b.WriteString("Exit codes: 0 completed; 2 input/usage error; 3 transition blocked or unknown;\n4 local storage/output failure. JSON reports use stdout; errors use stderr.\nA fixture passing does not establish device or hardware success.\n")
	return b.String()
}
