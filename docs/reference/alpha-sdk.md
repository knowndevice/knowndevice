# Alpha Go SDK

`sdk/device` and `sdk/credentialprofile` expose the same strict types and
validators used by the controller and built-in adapters. They are unreleased
alpha packages. The module path is `github.com/knowndevice/knowndevice`; no
module version is published and no stable SDK guarantee exists.
[RFC 0006](../decisions/0006-alpha-sdk-process-adapters.md) defines process
execution; [RFC 0005](../decisions/0005-credential-profiles.md) governs identity,
trust, time, activation and withdrawal.

| Public package | Contract |
| --- | --- |
| sdk/device | Plans, opaque handles, public trust/composition, clock intervals and seven typed roles |
| sdk/credentialprofile | Reviewed reference/stable policies and strict CSR/leaf/chain validation |
| adapters/profilehttp | Authenticated local HTTP roles |
| adapters/process | Negotiated bounded stdio host/server, scoped signing and complete role-evidence validation |
| api/schemas | Embedded matching alpha schemas |
| sdk/adaptergen | Safe creation of a standalone Go fixture/reference adapter module and exact manifest |
| sdk/conformance | Public common semantic cases through an explicit harness |
| sdk/conformance/fixture | Generated TLS fixture services and built-in/process connectors; in-memory state only |

Internal aliases retain exact type/error identity and legacy encoding.
`Adapters.Validate` refuses missing or typed nil roles. `Importer` is optional;
a Go method does not establish real service lookup or idempotency. New profiles
and compositions still require review, rather than arbitrary policy callbacks.

The current composition validator accepts only `local-http-lab/1`,
`local-http-lab/2` and `local-http-process-lab/1`, with their fixed role IDs,
HTTPS endpoints, reachable Application callback, no-state-transfer session
policy and whole-service lab withdrawal. Implementing the seven interfaces
can replace code within that scope. Supporting another transport, topology or
application policy requires a reviewed additive composition change. Neutral
evidence types alone do not establish support for that deployment.

`process.ValidateActivation` and `ValidateRetirement` expose the same complete
success validators used by the process host. The native HTTP adapter also checks
them before returning success. These helpers perform no authentication or effect:
the caller must authenticate the response channel, and the controller still
owns conservative time assessment, durable ordering and activation CAS. Missing
or unbound inputs remain unknown; a self-described evidence source grants no trust.

See [adapter creation and conformance](adapter-tooling.md) for the working local
generator. The generated module uses public imports and an explicit local SDK
replace; its selected backend remains profilehttp. This neither publishes the
SDK nor establishes an independent KD-029 implementation.

## External consumer

The [consumer](../../examples/sdk-consumer/README.md) has its own Go module and
uses only public imports with local `replace ../..`:

```sh
cd examples/sdk-consumer
go test -race -count=1 ./...
go run .
```

It creates ephemeral signer-backed CSRs for both policies and rejects a wrong
profile/signer. It initializes no identity store and performs no CA issuance.
Optional `--adapter`/`--snapshot` mode initializes an actual process and reads
a bounded clock assessment. Local replace proves importability only, without
SDK publication, device health, hardware or independent conformance claims.

`Credential` carries a public chain and `crypto.Signer` in memory and refuses
JSON serialization/deserialization. `Handle` has no arbitrary path or private
bytes. Process `WireCredential` contains public material and a temporary opaque
signerRef; only the host holds the signer. Revoking that grant preserves durable
intent and slots. No process callback can stage, activate, export or destroy keys.

## Fresh process composition

Build first, then seed separately pinned artifacts on a new identity. This
example uses Linux arm64; amd64 on an arm64 Docker host is emulated:

```sh
make check
bin/kd-profilelab seed --dir .work/new-process-lab --profile stable-device-cn --service-artifact bin/kd-profilelab-linux-arm64 --controller-artifact bin/knowndevice-linux-arm64 --process-artifact bin/kd-adapter-linux-arm64
export KNOWNDEVICE_PROFILE_DIR="$PWD/.work/new-process-lab"
export KNOWNDEVICE_PROFILE_ARCH=arm64
export KNOWNDEVICE_PROFILE_BIN_DIR="$PWD/.work/new-process-lab/artifacts"
export KNOWNDEVICE_LAB_USER="$(id -u):$(id -g)"
export KNOWNDEVICE_PROFILE_RUNTIME="Linux arm64 on aarch64 Docker host"
docker compose -f lab/profiles/compose.yaml -p new-process-lab up -d
docker compose -f lab/profiles/compose.yaml -p new-process-lab run --rm checks
docker compose -f lab/profiles/compose.yaml -p new-process-lab down
```

Use `reference-generation-cn` for the other V2 profile on another fresh
directory/project. `--authority-lifetime-seconds 300` binds that explicit shorter
request while retaining the shared strict policy. Seed selects
`local-http-process-lab/1`, pinning `processArtifactDigest` separately from the
underlying service/controller artifacts. Native `local-http-lab/1` and `/2`
omit/refuse that field. No store migration, plan edit or backend fallback exists.
Keep copied artifacts immutable while mounted; do not rebuild those paths.

The CLI selects `kd-adapter` beside its executable by default. Per-command
`KNOWNDEVICE_PROCESS_ADAPTER` may select an absolute path, whose exact bounded
regular-file digest must still match the snapshot. It grants no new authority.
`KNOWNDEVICE_BIN_DIR` selects a separate gate build output directory. These
values affect only the invoked process, without global configuration changes.

Initialize checks exact versions/schema digest, profile/snapshot/composition,
capabilities, HTTPS origins, signer permission and limits before domain access.
The [protocol reference](../../protocol/README.md) records methods and failures.
Timeout/cancel/crash/late or lost reply after dispatch remains unknown; a fresh
session queries/imports the original durable reservation, without blind replay.
Cancel stops work/grants, without undoing effects, deleting intent or releasing
reserved generations. Unfinished expired plans still need intervention.

The same backend/controller requires authenticated durable Application status,
activation revision and new post-switch independent actual-peer observation.
Candidate verification grants no CAS. Exact leaf/SPKI determines generation;
CN, ClientID and device payload do not. Unknown issuance never resends `/sign`.
Withdrawal still needs durable deny/session evidence, explicit old access denial
and fresh target use before CA revoke or destruction.

The local wrapper declares no key-file/read/write permission. Selected code
and its brokered signing are trusted; subprocess permissions are not an OS
sandbox. This composition retains reachable Application callback, no backlog
transfer and whole-service lab withdrawal. P12/NAT/queued observations, selective
KD-030, independent KD-029, hardware, SDK freeze and release gates stay separate.
