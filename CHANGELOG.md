# Changelog

Versions follow Semantic Versioning. Dates use YYYY-MM-DD.

## Unreleased

No device release has been published. Stable SDK/migrations, published release
artifacts, hardware protection and power-cut validation remain outside this
development profile.

### Reference path

- Added the architecture, roadmap, decision records, threat model and
  contribution rules.
- Added a development CLI with five in-memory continuity fixtures and
  transition-order tests.
- Added the unreleased Linux reference controller with strict Cobra commands,
  digest-bound plans, SQLite journaling and two software signer slots.
- Added real step-ca/Mosquitto adapters, an independent application/responder,
  generation-specific withdrawal and separate scoped recovery.
- Added a digest-pinned generated-data lab, killed-process checkpoint tests,
  actual filesystem-fault profiles, unknown issuance import and alpha schemas.
  The filesystem-fault profiles run only when `KD_FS_ROOT` and `KD_FS_FAULT`
  select a prepared filesystem, not in the default gate or CI.

### Credential profiles

- Added explicit v1alpha2 credential profiles on fresh version-2 stores,
  immutable role trust, exact server/peer key bindings, durable application
  activation evidence and the separate local HTTP profile lab.

### Alpha SDK and process contracts

- Expose the reviewed strict Go profile/trust/composition and role contracts
  through public packages, preserving internal compatibility aliases and legacy
  encoding. Local replace proves external importability without publication.
- Add RFC 0006, complete negotiated JSON-RPC NDJSON schemas, safe scoped errors,
  temporary host signer grants and a separately pinned fresh process composition.
  Timeout/cancel/lost responses preserve durable uncertainty and never grant
  blind issuance retry or system isolation.

### Adapter tooling

- Add a Go generator for a working standalone fixture/reference adapter module,
  exact manifest/schema, declared permissions and limits, fixtures and local CI.
  Existing destinations and unsafe paths are refused without overwriting files.
- Add public shared semantic conformance cases for built-in and generated
  process adapters. Controlled TLS fixtures remain distinct from actual service
  effects, independent integrations, SDK publication and hardware evidence.
- Classify strict local HTTP profile/CSR refusals as the same safe ErrDenied
  sentinel used by process adapters, without weakening validation.
- Apply the existing complete process activation/retirement checks to native
  HTTP success as well. Shared negative cases deliver the named malformed proof;
  successful entitlement is checked before valid issuance.

### Audit corrections

- Require one allowed certificate path across the complete assessed interval,
  and refuse nil certificates at the public chain-validation boundary.
- Recheck live Application proof and the stored activation revision in the
  controller before pointer changes, withdrawal, revocation and key destruction.
  Persist the new observation before its dependent effect and refuse replay
  after restart, including an observation already used by withdrawal.
- Refuse contradictory native HTTP role/status evidence before interpreting
  completion or authoritative absence.
- Encode literal SQLite registry paths and count lab CA dispatch attempts
  separately from received responses, including attempts with a lost response.
- Keep the last confirmed v1 checkpoint in a receipt when a checkpoint or
  result write fails, instead of reporting the unpersisted phase.
- Credit a recovery-scope denial only for an authenticated, fully bound denial;
  unavailable endpoints, timeouts and generic errors remain unknown.
- Report an active v2 probe during a pending rotation as unavailable (exit 3,
  unknown health) instead of building an adapter without the target plan.

### Repository and build

- Set the module path to `github.com/knowndevice/knowndevice`.
- Pin Go 1.27.3, which includes `crypto/x509` security fixes.
- Add `scripts/lab_matrix.sh`, which runs the reference and both profile labs
  with built-in and generated-process adapters for one Linux architecture.
  CI runs it natively on amd64 and arm64.
- Report PASS, SKIP or FAIL for every step in `scripts/lab_matrix.sh`, with
  exit codes for PASS and FAIL. Add `--cell NAME` to run one cell. Record the
  load average at start and end in `summary.txt`, along with any `kd-*`
  containers and networks left after the run.
- Fix the CI workflow, which used the `runner` context in job-level `env`.
- Give profile lab process compositions a 10 s request timeout, because two
  activation requests share one process call scope.
- Pin Go to `.go-version` and reject other versions; lint workflows with
  actionlint and shellcheck; fail on called govulncheck findings without
  reviewed exceptions. Run a `dco` sign-off check on pull requests; upload
  scanned `logs/` and `summary.txt` when a lab run fails.
- Run lab containers as the user in `KNOWNDEVICE_LAB_USER` (root when unset).
  On Docker Engine for Linux, root containers could not use the seeded state:
  `init` and the lab checks stopped with "journal storage must be owned by the
  current user". `scripts/lab_matrix.sh` sets it to the calling user, or to
  root under rootless Docker, where container root is the calling user.
- List the C compiler that the race tests need.
- Add `scripts/race_timing.py` and Quality input `race_timing_count` to measure
  race tests with host load, plus per-request process timing behind
  `KNOWNDEVICE_PROCESS_TIMING`. Scale test budgets and adjust test clocks and
  fixtures based on measurements; product limits stay unchanged.
- The reference lab control service answers registration and retirement only
  after the restarted broker delivers a readiness message to the responder and
  the responder echoes it, bounded to four fifths of the request timeout.
  Before, the verification probe could run before the responder had
  resubscribed, so `apply` stopped at `remote-outcome-unknown` after each
  broker restart and needed `reconcile`. The control service may publish only
  on its readiness topic. A retry after an `unknown` answer waits without
  restarting the broker again, and a retried retirement no longer reports
  `denied` when the application check fails after the policy already changed.
- Compile the race tests before running them in `make check`. On a cold build
  cache, concurrent compilation pushed process adapter subprocess startup past
  its 5-second bound and failed the gate.
- Add a release workflow and `scripts/release_build.py`. A version tag on
  `main` builds Linux amd64/arm64 archives, CycloneDX SBOMs and
  `SHA256SUMS` on both native runners, requires identical bytes, and
  attests provenance and SBOMs through GitHub OIDC. It does not publish a
  GitHub release. `knowndevice version` prints the release version.
- Named a private contact in the code of conduct.
- Updated docs to use the module path `github.com/knowndevice/knowndevice`.
- Updated the profile and process lab instructions to copy the adapter artifact
  and state the rootless Docker rule.
- Changed `scripts/check_repository.py --publication` to check public files
  (module path, private vulnerability reporting link, conduct contact,
  CODEOWNERS) instead of local metadata.
