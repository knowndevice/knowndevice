# Development

Use Go 1.27.3, Python 3.11 or newer and a C compiler for the race tests
(`build-essential` on Debian or Ubuntu). Go dependencies are pinned in go.mod
and verified by go.sum; scripts use the Python standard library. `make check` runs
repository checks, the Go toolchain check, workflow lint, the vulnerability
scan, maintenance-script tests, Go formatting, vet, race tests, and builds.
Logs go to `.cache/checks`; binaries go to `bin`.
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
`python3` is older. It does not install system packages, change global Go
installs or settings, or launch model sessions. It does download the pinned Go
toolchain and builds actionlint and govulncheck with `go run`, all inside
`.cache`.

## What the gate needs

| Gate | Needs | Fails when |
| --- | --- | --- |
| `go-toolchain` | The Go release in `.go-version`; network access the first time | The go command it ends up with reports another version |
| `workflows` | `shellcheck` on `PATH`; network access the first time | actionlint or shellcheck reports a finding in `.github/workflows`, or `shellcheck` is missing |
| `vulnerabilities` | Network access to the Go module proxy, checksum database and vuln.go.dev on every run | govulncheck reports a called vulnerable symbol that is not in [the accepted list](security/vulnerability-exceptions.md) |

The gate switches to the pinned toolchain and rejects any other version it
ends up with. It sets `GOTOOLCHAIN=go<version from .go-version>`; when the
installed `go` is another release, the go command downloads that exact
toolchain into `.cache/go-mod`, verified through the Go checksum database.
Formatting uses that toolchain's `gofmt`. A `GOTOOLCHAIN` value set in the
environment is replaced for the gate. Offline, the toolchain
and workflow gates work only from an already filled `.cache/go-mod`, and the
vulnerability scan fails.

Tool versions are pinned: actionlint v1.7.12 in `scripts/ci_local.sh` and
govulncheck v1.9.0 in `scripts/vuln_check.py`. Both are built with `go run`
from modules verified through the checksum database. `shellcheck` comes from
`PATH`; GitHub's Ubuntu 24.04 images ship it, and on macOS `brew install
shellcheck` provides it. Its version can differ between machines.

`bash scripts/ci_local.sh audit` runs only the three gates above.
`bash scripts/ci_local.sh docs` runs only the repository check.

## Hosted checks

Quality runs `make check`, `make demo` and the lab matrix on amd64 and arm64.
The lab step stops after 50 minutes. When a step fails, Quality scans the lab
matrix's `logs/` and `summary.txt` with `scripts/secret_scan.py` and uploads
only those two paths as the `lab-matrix-logs-<arch>-attempt-<n>` artifact.
The matrix directory also holds generated demo keys, which are never
uploaded. If the scan finds a private-key header, `PRIVATE KEY` text, a
base64 DER private key, a private JWK member, a token-shaped string, a
symbolic link, a special file or a directory it cannot list, nothing is
uploaded and the step fails, naming only the files.

The DCO workflow runs a check named `dco` on every pull request. It fails when
a non-merge commit between the base and head commits has no
`Signed-off-by: Name <email>` trailer. Merge commits are not checked, and the
sign-off is not matched to the commit author. The checker script comes from
the base commit, so a pull request cannot weaken it by editing the script. The
workflow file itself runs from the pull request, so changes to
`.github/workflows/dco.yml` need maintainer review. `dco` is not a required
check until the branch ruleset names it. Run the checker locally before pushing:

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
