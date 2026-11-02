# Development

Use Go 1.27.3, Python 3.11 or newer and a C compiler for the race tests
(`build-essential` on Debian or Ubuntu). Go dependencies are pinned in go.mod
and verified by go.sum; scripts use the Python standard library. `make check` runs
repository checks, maintenance-script tests, Go formatting, vet, race
tests, and builds. Logs go to `.cache/checks`; binaries go to `bin`.
The gate also tests/runs the standalone public-import SDK consumer and builds
the process wrapper. `KNOWNDEVICE_BIN_DIR` may select a separate artifact output
directory; active labs must use their separately copied immutable artifacts.

```sh
make check
make test
make build
make demo
```

Go caches are local to `.cache` when running the gate, so the process does
not need to modify global caches. A Python version can be selected with
`KNOWNDEVICE_PYTHON`. The gate discovers a local Python 3.11+ if the default
`python3` is older. It never installs tools or launches model sessions.

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
Filesystem-fault tests in journal/keystore require `KD_FS_ROOT`
and `KD_FS_FAULT` on a Linux ENOSPC or read-only mount; ordinary
native tests explicitly skip that profile. Do not report those skips as passes.

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
| `TestBlockedServerOutputRespectsContext` | 1 s teardown | Retain; no measured failures. |

With `KNOWNDEVICE_PROCESS_TIMING=1`, the CLI prints one line per process
adapter request to stderr. The profile lab sets it for controller commands and
shows the log when a command fails. Process adapter tests print the log when
they fail.
