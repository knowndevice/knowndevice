# Development

Use Go 1.27.3 and Python 3.11 or newer. Go dependencies are pinned in go.mod
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

Claim an issue and reference it in the pull request once GitHub is connected.
For a larger change, explain the decisions, affected contracts, acceptance
criteria, and observed checks. Durable decisions belong in ADRs and issues.
Follow [CONTRIBUTING](../CONTRIBUTING.md) and the
[decision template](decisions/template.md) for changes to trust or storage.

Local research, source specifications, planning notes, and contributor
client configuration are excluded by `.gitignore`. Public documentation
must stand on its own and link only to published files. The public checkout
includes the code and checks needed to build, test, and contribute.
