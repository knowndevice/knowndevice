# Development

Use Go 1.27.3, Python 3.11 or newer and a C compiler for the race tests
(`build-essential` on Debian or Ubuntu). Go dependencies are pinned in go.mod
and verified by go.sum; scripts use the Python standard library. `make check`
runs repository checks, checks the Go toolchain, lints workflows, scans for
vulnerabilities, tests maintenance scripts, checks Go formatting, runs vet
and race tests, and builds binaries.
Logs go to `.cache/checks`; binaries go to `bin`.
The gate also tests and runs the standalone public-import SDK consumer and
builds the process wrapper. `KNOWNDEVICE_BIN_DIR` may select a separate artifact
output directory; active labs must use their separately copied immutable
artifacts.

```sh
make check
make test
make build
make demo
```

The gate keeps Go caches in `.cache`, so it does not need to change global
caches. Select a Python version with `KNOWNDEVICE_PYTHON`. If the default
`python3` is older, the gate finds a local Python 3.11+. It does not install
system packages, change global Go installs or settings, or launch model
sessions. Downloads of the pinned Go toolchain and builds of actionlint and
govulncheck with `go run` stay inside `.cache`.

## What the gate needs

| Gate | Needs | Fails when |
| --- | --- | --- |
| `go-toolchain` | The Go release in `.go-version`; network access the first time | The selected go command reports another version |
| `workflows` | `shellcheck` on `PATH`; network access the first time | actionlint or shellcheck reports a finding in `.github/workflows`, or `shellcheck` is missing |
| `vulnerabilities` | Network access to the Go module proxy, checksum database and vuln.go.dev on every run | govulncheck reports a called vulnerable symbol that is not in [the accepted list](security/vulnerability-exceptions.md) |

The gate selects the pinned toolchain and rejects any other version. It sets
`GOTOOLCHAIN=go<version from .go-version>`, replacing any `GOTOOLCHAIN` value
in the environment. When the installed `go` is another release, the go command
downloads the exact toolchain into `.cache/go-mod` and verifies it through the
Go checksum database. Formatting uses that toolchain's `gofmt`. Offline, the
toolchain and workflow gates need an already filled `.cache/go-mod`; the
vulnerability scan fails.

Tool versions are pinned: actionlint v1.7.12 in `scripts/ci_local.sh` and
govulncheck v1.9.0 in `scripts/vuln_check.py`. Both are built with `go run`
from modules verified through the checksum database. `shellcheck` comes from
`PATH`, so its version can differ between machines. GitHub's Ubuntu 24.04
images include it; on macOS, install it with `brew install shellcheck`.

`bash scripts/ci_local.sh audit` runs only the three gates above.
`bash scripts/ci_local.sh docs` runs only the repository check.

## Hosted checks

Quality runs `make check`, `make demo` and the lab matrix on amd64 and arm64.
The lab step stops after 50 minutes. When a step fails, Quality scans the lab
matrix's `logs/` and `summary.txt` with `scripts/secret_scan.py`. If the scan
passes, it uploads only those two paths as the
`lab-matrix-logs-<arch>-attempt-<n>` artifact. Generated demo keys elsewhere
in the matrix directory are never uploaded. If the scan finds a private-key
header, `PRIVATE KEY` text, a base64 DER private key, a private JWK member,
a token-shaped string, a symbolic link, a special file or a directory it
cannot list, nothing is uploaded and the step fails. Marker failures name
only the files and markers.

The DCO workflow runs a check named `dco` on every pull request. It fails when
a non-merge commit between the base and head commits lacks a
`Signed-off-by: Name <email>` trailer. It skips merge commits and does not
match the sign-off to the commit author. When the base commit contains the
checker script, the workflow uses that copy, so editing the script in a pull
request does not weaken the check. The workflow file runs from the pull
request, so changes to `.github/workflows/dco.yml` need maintainer review.
The `main` branch ruleset requires `dco`. Run the checker locally before
pushing:

```sh
python3 scripts/dco_check.py --base origin/main --head HEAD
```

## Code conventions

Use gofmt, short cohesive packages, explicit errors and context deadlines.
Name an interface for a real boundary with a consumer; avoid speculative
abstractions, a shared `utils` package, and generic wrappers around one call.
Public APIs get contract comments. Other comments explain a constraint,
trust assumption, or failure case. Tests check observable behavior and
invariants; do not chase a coverage percentage with implementation copies.

Use standard-library cryptography. Adapters use a `crypto.Signer` or a
key-store operation, not private-key serialization through the controller.
Every remote mutation declares status/retry semantics. Treat a timeout as
potential success until a status check proves otherwise.

Require tests for generation/precondition changes, redaction, parsing limits,
and recovery authorization. Run fuzz tests on protocol/config decoders and
transition inputs. Native Linux and hardware evidence are separate from
cross-compilation. Cross-building a binary is not a hardware test.

The real generated-data integration matrix runs separately with the
[reference quickstart](quickstart.md). It uses digest-pinned Docker images,
an independent application/responder and actual killed CLI processes.

`bash scripts/fs_faults.sh --execute` runs twelve Linux Docker containers on
the Docker host's architecture. The `enospc-tmpfs` and `erofs-readonly`
profiles cover `journal` and `keystore`, with `v1`
(`TestFilesystemFaultMount`) and `v2` (`TestV2FilesystemFaultMount`). Four
containers run ENOSPC on fresh 8 MiB tmpfs mounts; eight run EROFS setup and
read-only checks on fresh bind directories. The tests need `KD_FS_ROOT` and
`KD_FS_FAULT`; the script sets both.

The `filesystem-faults` CI job runs the command on native amd64
(`ubuntu-24.04`) and native arm64 (`ubuntu-24.04-arm`). The default gate and
`make check` still skip these tests. Skips are not passes.

A pass requires exit 0, no skip, and `--- PASS:` for the selected test. The
mount line must show `/fault` with tmpfs and rw for `enospc`, ro for `erofs`,
or rw for `setup`. Each non-setup run and each of its subtests must log the
observed fault. The filler line before the fault does not count as an
observation. A run with only skips exits 3. Results go to a new
`.work/fs-faults-<UTC>-<pid>/`, or `KNOWNDEVICE_FS_FAULT_DIR`; the job keeps
`logs/` and `summary.txt` for 14 days.

The module path is `github.com/knowndevice/knowndevice`. No module version
is published yet; a consumer outside this checkout uses a local `replace`,
as `examples/sdk-consumer` does.

## Documentation conventions

Each available command needs exact arguments, effects, exit codes, a working
example, failure behavior, and known limits. Each adapter documents versions,
permissions, key custody, retry/reconcile, activation/retirement effects,
resource limits, and its conformance profile. Schemas and API reference
must be generated or checked against the same definitions the host uses.

Use tutorials for a complete user outcome, how-to guides for an operation,
reference for exact contracts, and explanation for trust/architecture.
Run examples in CI as their implementation becomes available. A link check
does not establish that a command or source claim is correct.

## Working on a change

Claim an issue and reference it in the pull request. Each issue names a roadmap
ID (KD-0xx) that the roadmap and design records cite.
For a larger change, explain the decisions, affected contracts, acceptance
criteria, and observed checks. Durable decisions belong in ADRs and issues.
Follow [CONTRIBUTING](../CONTRIBUTING.md) and the
[decision template](decisions/template.md) for changes to trust or storage.

Local research, source specifications, planning notes, and contributor
client configuration are excluded by `.gitignore`. Public documentation
must stand on its own and link only to published files. The public checkout
includes the code and checks needed to build, test, and contribute.

## Timing-bound tests

Some race tests bound wall-clock time and can fail on a heavily loaded host.
Measure them with:

```sh
python3 scripts/race_timing.py run --out .cache/timing/<name> --count 3
python3 scripts/race_timing.py summarize FILE
```

A manual Quality run with `race_timing_count` above 0 measures on both hosted
runners after the gate. Record each result with the host's one-minute load;
rerun a load-induced failure before calling it a defect.

| Test or fixture | Bound | Decision |
| --- | --- | --- |
| Process adapter start-up | 5 s default; package tests 30 s | Scale only package tests, whose adapter is the race-enabled test binary. |
| Process test snapshot requests | 1 s to 5 s | Scale the signing-request wait from 1 s to 5 s and the result wait from 2 s to 10 s. |
| Process test adapter clock uncertainty | 1 s to 100 ms | Leave more time for the assessment round trip; the product limit stays 2,000 ms. |
| `TestBuiltinPublicSuite` | 1 to 3 minutes | Scale the suite context; the 30 s per-case context stays unchanged. |
| Controller live-proof tests | Fixed clock; 5 s evidence age unchanged | Set the fresh observation 500 ms after the stored one; retain replay rejection after reopening the journal. |
| Profile lab delayed-handshake test | 100 ms to 1 s context deadline | Keep the deadline below the 2.2 s signer delay; plan lifetime stays 3 s. |
| Profile lab process compositions | 5 s to 10 s request timeout | Two activation requests share one process call scope, where the built-in client gives each its own. Real process adapters keep the shared scope. |
| `TestBlockedServerOutputRespectsContext` | 1 s teardown | Retain; no measured failures. |

With `KNOWNDEVICE_PROCESS_TIMING=1`, the CLI prints one line per process
adapter request to stderr. The profile lab sets it for controller commands and
shows the log when a command fails. Process adapter tests print the log when
they fail.
