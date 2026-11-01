# Contributing

Known Device welcomes code, tests, documentation, and reports from device
operators. Public discussion and repository documentation use English.
Maintainer conversations can use another language.

For a defect, describe the version, hardware, storage, connection profile,
expected behavior, observed behavior, and a minimal reproduction. Redact
device identifiers and credentials. Report vulnerabilities privately using
[SECURITY](SECURITY.md).

For a new adapter or a behavior change, discuss an issue first. A small
documentation correction can go straight to a pull request. An adapter
needs success, timeout, duplicate-operation, interrupted-process, and
unsupported-capability cases; see [protocol](protocol/README.md).

## Local development

```sh
make check
make demo
```

Use Go 1.27.3 and Python 3.11+. See [development](docs/development.md) for
tool configuration and conventions for code and
documentation. `make check` and `make demo` need
no services. The reference and profile labs also need Docker with Compose;
see the [quickstart](docs/quickstart.md). `bash scripts/lab_matrix.sh arm64`
(or `amd64`) runs every lab cell for one architecture, as CI does.
`--cell NAME` runs one cell, such as `stable-device-cn-builtin`; an unknown
name prints the valid ones. Every step that runs writes a PASS, SKIP or FAIL
line to `summary.txt` in the matrix directory. PASS and FAIL lines carry the
exit code; SKIP lines name the reason. The summary also records the load
average at start and end and any `kd-*` containers or networks left afterwards.

## Pull requests

Keep one behavior change per pull request. Include the problem, resulting
behavior, relevant issue, tests actually run, and known limitations. Change
documentation and examples with the code. A skipped test is a skipped test;
do not describe it as passing. Do not add copied logs containing secrets.

Use `fix:`, `feat:`, `docs:`, `test:`, `refactor:`, `build:`, `ci:`, or `chore:`
followed by a concrete subject. The maintainer may squash related commits.
Stage explicit paths and preserve other contributors' uncommitted work.

All contributors retain their copyright. Contributions use Apache-2.0.
Sign each commit with `git commit -s` to certify the
[Developer Certificate of Origin](https://developercertificate.org/).
Use your own identity and certify only work you have the right to submit.
A DCO sign-off is separate from cryptographic commit signing. A CLA is not
required. Preserve third-party license and attribution notices.

## Review and decisions

One maintainer reviews ordinary changes. Changes to recovery authorization,
key handling, storage durability, or stable contracts require a separate
security/PKI review before release. While the project has one maintainer,
that review can come from an external contributor; do not invent approvals.

New public contracts, incompatible changes, and new trust mechanisms need
an RFC using [the decision template](docs/decisions/template.md).
Document alternatives and the migration path. The tests and
[protected contracts](docs/protected-contracts.md) guide review.

Follow [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) and the
[writing rules](docs/style.md). Describe what the software does and what
was tested. Broad claims such as “production-ready” require published
evidence for a defined scope.
