# Known Device

Known Device preserves a logical device identity while its credentials change.
The development controller now implements one reference path: Linux software
keys, a SQLite journal, Smallstep `step-ca`, Mosquitto mutual TLS, an independent
MQTT application and an external challenge responder.

A replacement can fail halfway through. The controller persists intent before
issuance, registration, activation and withdrawal, then reconciles after
restart. A successful TLS handshake alone cannot commit a generation: the
external probe and the application's live observation must also pass.

**Status: `0.0.0-dev`, unreleased reference implementation toward 0.1.**
This is a local generated-data lab without a stable SDK, production deployment
or hardware power-loss claim. The [roadmap](ROADMAP.md) keeps those gates separate.

Explicit [v1alpha2 profiles](docs/reference/credential-profiles.md) add reviewed
reference/stable-CN validation, role trust snapshots and a fresh generated-data
HTTP enforcer/application lab. The stable subject uses exact authenticated
peer leaf/SPKI reservations. This opt-in internal composition is separate from
an independent second deployment or shared withdrawal.
The [alpha SDK](docs/reference/alpha-sdk.md) exposes the same strict Go contracts;
[RFC 0006](docs/decisions/0006-alpha-sdk-process-adapters.md) defines the negotiated
stdio adapter path on a separate fresh, pinned process composition.

## Run the reference path

Install Go 1.27.3, Python 3.11+, Bash, Make and Docker with Compose. No hosted
account is required. The first build downloads pinned Go dependencies; the lab
downloads digest-pinned images.

```sh
make check
bin/kd-reference seed --dir .work/reference
docker compose -f lab/compose.yaml up -d
docker compose -f lab/compose.yaml run --rm checks
docker compose -f lab/compose.yaml down
```

The default lab architecture is `arm64`. On an amd64 Docker host set
`KNOWNDEVICE_LAB_ARCH=amd64` before Compose. Seed requires a new directory and
generates unique private demo material. Follow the
[quickstart](docs/quickstart.md) for manual enrollment, rotation, interruption,
recovery and retained evidence.

`make demo` still runs deterministic fixtures with `scope: in-memory-model`.
They remain separate from device evidence.

## Delivered scope

| Capability | Development status |
| --- | --- |
| Cobra CLI, strict JSON/YAML, bounded digest-bound plans | Implemented |
| SQLite WAL/FULL journal, version refusal, writer lock, revision fencing | Implemented |
| Two ECDSA software signer slots, synced pointer, retirement tombstones | Implemented |
| `step-ca` 0.29.0 issuance/revoke and unknown-result reconciliation | Implemented in the reference profile |
| Mosquitto 2.0.22 mTLS, generational ACL, external MQTT 5 probe | Implemented in the reference profile |
| Independent application activation and server-observed confirmation | Implemented in the reference profile |
| Separate device recovery signer and current entitlement checks | Implemented in the reference profile |
| Linux amd64/arm64 binaries | Built by `make build`; runtime evidence names its architecture |
| Explicit reference/stable credential policies, fresh V2 and role trust | Implemented internally; named local scope and limits in the profile reference |
| Importable alpha Go SDK and bounded negotiated process adapters | Local development implementation; local replace proves importability, without publication or stable guarantees |
| Go adapter generator and public conformance suite | Local alpha tooling for the selected fixture/reference backend; [creation and limits](docs/reference/adapter-tooling.md) |
| Stable SDK, systemd scheduler, MCP | Planned for 0.2 or later |
| EST, pilot platform, TPM 2.0 on named hardware | Planned for 1.0 |
| Signed releases, migrations, SBOM, public security channels | Release work remains |
| Fleet coordinator, MCU, PKCS#11, OTA | Future RFCs |

An ACL denial or activation failure stops commit and preserves the previous
authorized generation. Uncertain issuance stays `unknown` without another CA
request. Explicit import of recovered public evidence is bounded and validated.

## Boundaries

The lab control service holds the CA provisioner and broker privileges; the
device receives neither. Recovery has its own signer and no MQTT permissions.
A revoked or retired registry entry cannot recover.

Broker withdrawal uses synced ACL replacement and a broker restart, disconnecting
**all lab clients**. The controller observes the new application again and
checks old reconnect denial before revoking or deleting the previous key.
CA revocation alone cannot establish broker withdrawal.

A privileged administrator can copy software keys. This profile assumes a
trusted system clock and detects rollback against a durable wall-time floor;
it supplies neither trusted time nor disk rollback resistance. An unknown CA
result without a recovered chain needs intervention. Keep journal and slots
together; a WAL without its shared-memory sidecar requires intervention.
No backup or migration tool is delivered.
An unfinished plan past its deadline also requires intervention; this alpha
has no in-place reauthorization or cancellation. It preserves the recorded
generation and refuses further effects or a replacement recovery plan.

The application and responder are trusted processes. Their observations cover
the configured MQTT path, not every consumer, OS isolation or hardware
attestation. Container SIGKILL and filesystem faults remain distinct from power
cuts on named hardware.

## Documentation and contribution

- [Quickstart](docs/quickstart.md) · [CLI reference](docs/reference/cli.md)
- [Architecture](docs/architecture.md) · [First path RFC](docs/decisions/0004-first-device-path.md)
- [Threat model](docs/security/threat-model.md) · [Alpha schemas](api/README.md)
- [Integrations](docs/integrations.md) · [Compatibility](docs/compatibility.md)
- [Development](docs/development.md) · [Roadmap](ROADMAP.md)

Read [CONTRIBUTING](CONTRIBUTING.md), [GOVERNANCE](GOVERNANCE.md),
[SECURITY](SECURITY.md) and [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md).
Known Device uses [Apache-2.0](LICENSE); dependency notices are in [NOTICE](NOTICE).
The module path is `github.com/knowndevice/knowndevice`; no module version is
published yet.
The Cloudflare site awaits the first useful release gates and a separate
publication scope.
