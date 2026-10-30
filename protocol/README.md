# Process adapter protocol

The local alpha protocol is `knowndevice-process/0.1-alpha.1`, JSON-RPC 2.0
NDJSON over stdio. [RFC 0006](../docs/decisions/0006-alpha-sdk-process-adapters.md)
defines methods, failure semantics and the
[complete schema](../api/schemas/process-v1alpha1.schema.json), negotiated by
identity/version and exact SHA-256 bytes. This process extension is separate
from device network protocols and MCP, without a stable SDK freeze or published
module claim. See the [SDK reference](../docs/reference/alpha-sdk.md) for the
fresh pinned composition and [adapter tooling](../docs/reference/adapter-tooling.md)
for the local Go generator and public shared conformance cases.

`adapters/process.Start` launches an explicit pinned regular executable from
a private staged copy, without shell/PATH lookup. `Serve` hosts public
`sdk/device.Adapters`; `cmd/kd-adapter` supplies the same authenticated HTTP
roles and bounded SystemClock used by native execution.

## Negotiation and framing

`plugin.initialize` succeeds once before domain access. It agrees exact
protocol/error/schema versions and digests, profile/policy, canonical public
snapshot and composition, wrapper artifact, required capabilities, permissions
and fixed limits. A missing role/capability or mismatch refuses before domain
effects. There is no default backend or root-pool substitution.

Use UTF-8 with one JSON object per LF/CRLF line. Host IDs are `h-` plus 32 hex;
reverse signer IDs use `s-`. Reject batches, empty/partial lines, positional/null
params, null/numeric IDs, duplicate/unknown/wrong-case fields, invalid UTF-8,
extra documents and structural/byte limit violations. Duplicate IDs never
redispatch an effect. A response has exactly result or error and a pending ID.
Unexpected responses or unsolicited reverse requests terminate the session;
only active scope-bound `signer.sign` callbacks are accepted from the process.
Domain notifications never perform effects. Stdout carries protocol only.
The host drains bounded stderr without forwarding raw bytes into logs/errors.

## Available methods

| Role | Methods | Required semantics |
| --- | --- | --- |
| Session | plugin.initialize, plugin.health, plugin.shutdown | Exact negotiation; session-only health |
| Entitlement | entitlement.authorize | Current authenticated bounded permission |
| Authority | authority.issue, authority.lookup, authority.import, authority.revoke, authority.revocationStatus | Original CSR/key and exact reservation; unsupported/unknown status stays explicit |
| Platform | platform.register, platform.registrationStatus | Exact candidate binding and durable status |
| Transport | transport.probe | Fresh bounded challenge, without activation |
| Application | application.activate, application.activationStatus | Durable activation/revision and new independent actual-peer observation |
| Withdrawal | withdrawal.withdraw, withdrawal.status | Durable deny, verified session removal, explicit old denial and fresh target use |
| Clock | clock.assess | Conservative interval and local monotonic reassessment |
| Host signer | signer.sign | Temporary exact parent/scope/ref and bounded signing |
| Cancellation | operation.cancel notification | Stop work/grants, without undo or intent deletion |

Non-clock domain calls carry full immutable Plan and Scope: operation/device/
deployment, profile/snapshot/composition/digests, expected/target generation,
deadline and explicit public credential operands. Success echoes exact Scope
with a typed value. Previous artifact and current caller are distinct. The
process cannot replace server entitlement/CAS, profile validation or controller
fencing/ordering with its receipt. No generic operation.status, key lifecycle/
export, rekey, durable-plan cancellation, reauthorization, generator or MCP
method exists.

## Errors, cancellation and restart

Error version is `knowndevice-process-errors/1`. Standard JSON-RPC codes retain
their meaning. Codes -32010 through -32017 mean unsupported, denied, conflict,
unknown, adapter failure, expired plan, authoritative not-started and resource
limit respectively. Schema fixes code/kind/outcome/message and retryable=false;
domain errors require exact current Scope. Initialize unsupported and clock
control unknown errors are explicitly unscoped.

Only a matching declared lookup/status may establish not-started. Unbound or
contradictory errors become unknown, without mutation retry. Raw step-ca has no
invented operation lookup/idempotency. HTTP 404, timeout, malformed response and
a claimed operation key do not prove absence of effect.

Deadlines fit context, snapshot timeout and original plan expiry. Once sent,
timeout/cancel/crash/lost or late reply preserves unknown effects and original
intent. Cancel revokes grants and stops further work, with bounded session
teardown. A fresh session reinitializes then looks up/imports the original
reservation; it never resends uncertain issuance or releases its generation.
Expired unfinished plans require intervention. No automatic restart/retry exists.

Clock results omit remote monotonic timestamps. The host widens both bounds by
the full locally measured round trip, reduces remaining age and assigns a fresh
local monotonic assessment. The complete interval must fit validity, remaining
lifetime, floor and deadlines, including restart. No trusted-time/disk rollback
guarantee follows from this local clock assumption.

## Limits and confinement

| Resource | Fixed maximum |
| --- | --- |
| NDJSON line | 1 MiB before body allocation |
| CSR / chain / certificates | 16 KiB / 64 KiB total / 8 |
| Public snapshot / decoded JSON string | 128 KiB / 256 KiB |
| Nesting / values / object fields / array items | 32 / 10,000 / 64 / 256 |
| In-flight domain calls / session IDs | 1 plus bounded controls / 4096 |
| Signer calls / digest / signature | 32 per parent / 64 bytes / 512 bytes |
| Stderr drain | 1 MiB per session, raw bytes never forwarded |
| Domain timeout / initialize / close grace | 60 seconds / 5 seconds / 1 second |
| Executable / arguments | 128 MiB / 16 args, 1 KiB each, 8 KiB total |

Wire artifacts are inline bounded public bytes; arbitrary paths/URLs are not
results. The separate host OpenArtifact helper verifies one clean relative
regular file, declared size/digest under an owned root, refusing traversal and
symlinks through rooted access. It does not restrict mounts or direct syscalls.
Executable staging binds verified bytes in a new private directory; the child
uses a minimal environment without inherited secret configuration.

Permissions name exact selected HTTPS origins and request-scoped signing. The
local wrapper has empty key-file/read/write permissions. They describe trusted
code and bound host brokerage, without OS isolation or hardware evidence.
Cancellation, expiry, TLS alerts, closed sockets and passive CA success alone
cannot prove effective withdrawal or authorize previous-key destruction.

## Generated adapters and conformance

The Go generator creates an external module that composes the same public
profilehttp roles and SystemClock behind Serve. It adds no process method,
version, limits or trust policy. Its concrete manifest requires a validated
canonical snapshot and exact executable pin; a static manifest template does
not grant permission. Network origins are the exact selected HTTPS origins,
filesystem lists are empty and signer brokerage remains call-scoped.

The public conformance suite exercises the same semantic cases through native
and generated process connectors. Controlled lost/late replies, duplicates,
adapter restart and cancellation are fixture evidence. Exact unknown status
never authorizes another issuance. Real step-ca/application storage, controller
checkpoints and session effects require separate fresh service evidence.
Conformance does not turn a selected subprocess into OS isolation or establish
an independent implementation or SDK publication.
