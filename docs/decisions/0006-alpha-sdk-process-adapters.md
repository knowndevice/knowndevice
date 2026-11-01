# RFC 0006: Alpha Go SDK and negotiated process adapters

Status: internally reviewed alpha design, 13 October 2026. KD-013 local
scope only. Round 1 found three P2 corrections, recorded below; implementation
uses the corrected design and schemas, with closure checked in round 2.
This extends [RFC 0005](0005-credential-profiles.md); it changes neither V1/V2
storage versions nor the existing credential policy/digest rules.

Expose the reviewed types and strict validators as `sdk/device` and
`sdk/credentialprofile`. Run selected adapters through a bounded JSON-RPC 2.0
stdio session after explicit version, schema, profile, capability, permission
and limit agreement. A process is trusted selected code, not an OS sandbox.
The local module remains `knowndevice.local/knowndevice`; local replace proves
external importability without naming a canonical repository or publishing it.
Later change: the module path is now `github.com/knowndevice/knowndevice`,
and no version is published.

## Alternatives and ownership

| Alternative | Result |
| --- | --- |
| Publish aliases while leaving policy implementations private | Importable types but unclear public validation path and private implementation dependencies |
| Duplicate public types and validators | Conversion and policy drift at every controller/adapter boundary |
| Move the existing implementation and retain internal aliases | One policy, identical Go type/error identity and fixed-struct JSON; selected |

`sdk/device` owns plans, opaque handles, public credentials, profiles/trust
snapshots, composition, clock intervals and typed roles. `sdk/credentialprofile`
owns the reviewed strict CSR/leaf/chain validator. Internal aliases preserve
source compatibility and `errors.Is`. Existing field order/tags and legacy
checkpoint names remain. `Credential` is an in-memory public-chain plus
`crypto.Signer` carrier and refuses JSON serialization; private key fields
cannot accidentally become protocol data. The process wire has its own
public-only credential DTO.

`Adapters` contains Entitlement, Authority, Platform registration, Transport,
Application, Clock and Withdrawal. `Importer` is optional; unsupported import
is refused. The existing `Roles.LegacyFacade` only adapts controller sequencing;
it does not make the old combined Platform a universal extension requirement.
MQTT frames, topics, reason codes and CN-selected usernames remain native
adapter facts. The SDK's two reviewed credential profiles are explicit choices.
New policies/compositions still need review rather than arbitrary callbacks.

The controller owns intent, fencing, ordering, public-material validation and
checkpoint advancement. The role backend owns authenticated service effects
and status. The process layer owns framing, negotiation, bounded execution,
scope correlation and signer brokerage. None can use its receipt to grant
remote authority or bypass another layer's checks.

## Wire and complete schemas

Protocol version: `knowndevice-process/0.1-alpha.1`. Error version:
`knowndevice-process-errors/1`. The complete JSON Schema 2020-12 contract is
[process schema](../../api/schemas/process-v1alpha1.schema.json), identity
`urn:knowndevice:process:0.1-alpha.1`, schema version `1`. Negotiation compares
the SHA-256 of the exact embedded schema bytes, not just its name. Its `$defs`
cover every request, notification, response, error, public credential, scope,
plan, result and canonical public snapshot. Semantic checks additionally
enforce byte totals, digests, action permissions, exact bindings and time.

Use UTF-8 NDJSON with one JSON object and LF per message; accept CRLF. Reject
empty lines, a final unterminated line, batches, positional params, invalid
UTF-8, trailing documents, null/number IDs, duplicate keys, wrong-case fields
and unknown fields. Requests use a unique `h-` plus 32 lowercase hex ID from
the host; reverse signer requests use `s-` plus 32 hex. Responses copy that ID.
Success has exactly `result`; failure exactly `error`. No domain notification
may trigger an effect. Stdout contains protocol only. The host drains stderr
without forwarding raw bytes; it may report fixed metadata/counts only.

Parse/invalid-request errors with unknown IDs use null. Well-formed unknown
methods return method-not-found for a request and no response for a
notification. Malformed framing, duplicate IDs, oversized messages, unsolicited
reverse methods or unexpected/duplicate responses terminate the session;
in-flight effects become unknown. Nothing from an invalid message is logged.

## Initialization and selected scope

`plugin.initialize` must be the first request and may succeed once per session.
Params contain `protocolVersions`, `errorVersions`, `schemas`, `artifactDigest`,
`snapshotDigest`, `compositionDigest`, `profile`, canonical base64 `snapshot`,
`requiredCapabilities`, `permissions` and `limits`. The result chooses one
supported protocol/error version and echoes the exact schema identities,
artifact/snapshot/composition/profile, permissions and limits, with the
available capabilities. Lists are bounded, sorted and distinct. Unknown
required capabilities, a missing role, any mismatch or unsupported version
refuses initialization before a domain call or signer grant. Exact limits are
agreed, with no silent widening, fallback backend or root union.

The canonical snapshot is resolved by the host and validated independently by
the process. It contains loaded public DER, role trust/pins and the selected
composition. It supplies no new trust to the remote server, which independently
pins that same snapshot. Host and process retain those bytes for the session.
An unfinished operation cannot reopen changed trust or select another artifact.

For actual protected process transitions select fresh
`local-http-process-lab/1`. It retains the native local HTTP role artifacts,
explicit 300–1200-second authority lifetime, callback, no-state-transfer session
policy and whole-service lab withdrawal. A new required `processArtifactDigest`
pins the wrapper executable in the composition and plan digest. This field is
omitted and forbidden for `local-http-lab/1` and `/2`, preserving their exact
encoding and behavior. The process choice uses new generated state only; no
existing store, snapshot, plan or identity is converted.

The local wrapper implements the same `profilehttp` backend and SystemClock
behind public interfaces. Its declared network permissions are the exact
normalized HTTPS origins of control, application, issuance and transport in
the snapshot. Filesystem read/write permission lists are empty; public snapshot
bytes arrive through initialize. Signer brokerage is explicit. Permissions are
an allowlist for host brokerage and a description of trusted process behavior;
they do not restrict direct syscalls or establish system isolation.

## Methods and typed values

| Method | Params definition | Success value | Effect/status semantics |
| --- | --- | --- | --- |
| `plugin.initialize` | initializeParams | initializeResult | Required once before domain access |
| `plugin.health` | empty | healthResult | Session health only; no device/application health |
| `plugin.shutdown` | empty | empty | Cancels pending work; effects still require reconciliation |
| `entitlement.authorize` | authorizeParams | empty | Current authenticated entitlement; no issuance |
| `authority.issue` | issueParams | certificate | Exact original CSR; durable intent remains controller/server responsibility |
| `authority.lookup` | issueParams | certificate | Exact authenticated stored issuance; unsupported/unknown without real lookup |
| `authority.import` | importParams | empty | Existing unknown reservation only, no issuance |
| `authority.revoke` | pairParams | empty | Current target authenticates; previous selects public artifact |
| `authority.revocationStatus` | pairParams | empty | Bound authoritative state or unknown; CA success is not withdrawal |
| `platform.register` | credentialParams | empty | Exact candidate mapping and server preconditions |
| `platform.registrationStatus` | credentialParams | empty | Existing durable mapping; no registration |
| `transport.probe` | probeParams | probe | Fresh exact challenge; no activation |
| `application.activate` | credentialParams | activation | Durable Application switch/status and new independent observation |
| `application.activationStatus` | credentialParams | activation | Authenticated existing status followed by fresh observation |
| `withdrawal.withdraw` | pairParams | retirement | Exact durable deny, session removal/denial and current application |
| `withdrawal.status` | pairParams | retirement | Reconcile existing withdrawal; unknown if proof incomplete |
| `clock.assess` | clockParams | clockResult | Closed interval under the declared local clock assumption |
| `signer.sign` | signParams | signResult | Process-to-host callback only within one permitted active call |
| `operation.cancel` | cancelParams | no response | Host notification only; stops work without undoing effects |

Every non-clock domain request carries the full immutable Plan and Scope:
operation/device/deployment, plan/snapshot/composition/profile digests and version,
expected/target generations and deadline. Scope must exactly match Plan and
selected snapshot; deadline is at most the host context, snapshot request timeout
and original plan expiry. Role-specific trust digests are already in Plan.
The JSON-RPC ID is also the parent request correlation. Success wraps the exact
Scope and typed `value`; it cannot be applied to a different call/generation.
Clock results and control/sign results have their own complete schemas.
Completion status is role-specific: Application observation requires
`completed`; the selected native Withdrawal envelope uses `ok` only with the
complete durable deny/session/old-denial/fresh-target proof. Its accepted
Application scope is exactly `fresh-challenge`, without a telemetry/backlog
claim. A bare status string cannot establish either completion.
Both observation windows are bounded by the selected challenge lifetime.
Withdrawal requires an envelope revision at least the durable policy revision,
an explicit challenge denial, and a later independent target observation with
a different nonce. The public process validator applies the same constraints
as the controller journal before returning success.

`wireCredential` contains Handle, raw DER chain, original CSR, recovery flag,
device ID, public SPKI and a temporary opaque signerRef. Parsed SPKI, chain
and handle agree; operational profiles use the shared strict validator.
Recovery has its separately pinned leaf/SPKI and no operational generation.
Previous credentials are explicit artifact operands; current target credentials
provide revoke/withdraw authority. Historical validation does not grant access.
Server entitlement, exact peer identity and active-generation CAS remain final
authorities; a syntactically valid client scope cannot replace them.

Required semantic capabilities remain RFC 0005's `current-entitlement`,
`bounded-unknown-issuance`, `exact-peer-binding`, `explicit-access-observation`,
`durable-activation-and-fresh-observation`, `bounded-interval` and
`durable-deny-and-session-inventory`. Capability declarations do not invent raw
step-ca operation lookup/idempotency. No generic `operation.status`, rekey,
key export, key-store lifecycle, plan cancellation, reauthorization or MCP
method exists in this alpha.

## Resource and time limits

Both peers enforce the same fixed limits before allocation/dispatch; initialize
cannot request more. The original 8 MiB draft line allowance is superseded.

| Resource | Hard limit |
| --- | --- |
| NDJSON line, excluding LF/optional CR | 1 MiB |
| CSR / public chain / certificates | 16 KiB / 64 KiB total / 8 |
| Canonical public snapshot | 128 KiB |
| JSON nesting / values / object members / array elements | 32 / 10,000 / 64 / 256 |
| Individual decoded JSON string | 256 KiB |
| In-flight domain calls | 1, with bounded signer callbacks/cancel control |
| Unique request IDs per session | 4096; budget exhaustion closes/refuses, IDs never reused |
| Signer callbacks per parent | 32 |
| Signing digest / returned signature | 64 / 512 bytes |
| Stderr drain budget | 1 MiB per session; raw bytes never forwarded |
| Request timeout / initialize timeout / shutdown grace | 60 seconds / 5 seconds / 1 second |
| Executable size / local artifact helper file count | 128 MiB / one explicitly requested file per open |
| Executable arguments | 16, each at most 1024 bytes, total at most 8 KiB |

Framing is bounded while reading, including unterminated input. Strict token
validation rejects duplicate keys and excessive structural/string/value counts
before typed decode. Byte totals are checked after bounded base64 decoding.
Executable staging/verification checks its cap before reading/copying. Reader,
writer and process teardown cannot outlive the bounded host context indefinitely.

The shared profile/controller still assesses the whole conservative interval,
certificate validity, drift, age, remaining lifetime, floor and plan/challenge
deadlines. A serialized process monotonic instant is never trusted. Clock wire
results omit AssessedAt; the host measures local RPC elapsed time, widens both
returned bounds by the full elapsed duration, reduces remaining assessment age
by that duration and assigns a new local monotonic AssessedAt on receipt.
Reject a round trip exhausting age or the selected uncertainty bound. Restart
requires a new assessment. A slow domain response is rechecked by the existing
backend/controller and cannot extend any authorization deadline.

## Failure, cancellation and reconciliation

JSON-RPC standard errors retain -32700, -32600, -32601, -32602 and -32603.
Domain errors contain fixed safe messages and data with `version`, `kind`,
`outcome`, `retryable: false`, and exact Scope where applicable. No remote body,
token, payload, arbitrary exception text or private path enters errors/logs.
The schema pins each code/kind/outcome/message combination. Domain errors require
the exact current Scope; initialization's unsupported refusal is the sole
unscoped domain-code exception. A host validates the combination and Scope
before mapping an error to a Go sentinel. `not-started` is accepted only from
the matching declared status/lookup method; any contradictory, missing or stale
binding is unknown and never permits a mutation retry.
Clock assessment has snapshot scope rather than a durable operation. Its
failures use an unscoped standard internal error with unknown outcome, or
unsupported, and cannot establish absence or authorize any effect.

| Code | Kind | Meaning |
| --- | --- | --- |
| -32010 | unsupported | Required version, role, capability or method unavailable |
| -32011 | denied | Authenticated scope/policy refusal or local refusal before dispatch |
| -32012 | conflict | Stale generation, changed binding/digest or precondition conflict |
| -32013 | unknown | Attempted effect/result uncertain; reconcile exact durable intent |
| -32014 | adapter-failure | Local adapter/session failure; attempted effect remains unknown |
| -32015 | plan-expired | Unfinished original deadline requires intervention |
| -32016 | not-started | Only a real bound authoritative lookup establishes no effect |
| -32017 | resource-limit | Refused local bounded resource; dispatched effects remain unknown |

The host never retries a domain mutation automatically. Cancellation before
dispatch can establish that this process call was not sent. Once sent, context
expiry/cancel, crash, EOF, malformed or lost/late response means unknown for an
attempted mutation. Send `operation.cancel` with parent ID and exact Scope;
retire signer grants, cancel contexts and close the session after bounded grace.
The process checks cancellation/deadline before each further backend step.
It cannot undo an issuance, switch, CAS, deny or revocation, delete durable
intent, release generation reservations or claim rollback. Ignore late results
for local advancement; a fresh session initializes then invokes the exact role
lookup/import with original Plan/CSR/SPKI. Issuance unknown never sends another
`/sign`. Unsupported lookup returns unsupported or unknown, never absence.

Domain request IDs are single use. A duplicate ID never redispatches a backend
effect. A new ID or matching operation ID is not transport idempotency; the
backend's durable reservation/guarded exact status defines any safe repeat.
Pending IDs/signers are removed on completion/cancel/session loss, while the
bounded session ID ledger prevents duplicate/late responses from crossing a
new request. No unsolicited process request can mutate host stores, application
selection, registry, configuration, clock or keys.

Candidate verification cannot authorize activation CAS. Durable authenticated
Application status, nonzero activation revision and new post-switch independent
actual-peer observation remain mandatory. Withdrawal still precedes passive CA
revoke and destruction, and requires explicit old access denial plus fresh target
use. Timeout, local expiry, TLS alerts, closed sockets and CA HTTP success alone
remain insufficient. Outcome, checkpoint and live health remain separate.

## Signer and artifact confinement

The host accepts only an operator-selected absolute regular executable under
an owned directory, with no symlink component and an exact SHA-256 pin matching
the immutable process composition. It reads bounded bytes through rooted access,
verifies the digest, stages those exact bytes in a new private directory under
the explicitly selected WorkDir and executes that copy without shell/PATH
lookup. Minimal child environment prevents inherited secret settings; stdin,
stdout and stderr are explicit pipes. Never rebuild an active lab artifact.

Each host credential grants a fresh unguessable signerRef scoped to one parent
ID, exact Scope, action, deadline and public SPKI. `signer.sign` must use that
Scope/ref/parent and allowed SHA-256/384/512 digest length. Only ECDSA P-256
signers are supported here, including TLS's digest choice; CSR policy remains
SHA-256. Signature size/call budgets apply. The host verifies the signature
against the registered public key and revokes the reference on completion or
cancel. No signing, export, activate or destroy callback exists outside that
grant. Trusted process code can use an allowed signature; brokerage does not
prove remote endpoint confinement or isolate arbitrary syscalls.
Revoke/status grants only the current target signer; previous material is a
public-only artifact. Withdrawal additionally grants the previous signer solely
for the declared negative access observation. Recovery grants never become
operational/application/withdrawal grants.

Protocol artifacts are inline bounded public bytes only; arbitrary paths/URLs
are not accepted results. A separate host `OpenArtifact` helper accepts one
slash-relative clean path, declared size and SHA-256 beneath an owned root.
Reject absolute paths, dot/traversal, symlink components, nonregular files,
oversize and digest mismatch. Rooted open prevents escapes during traversal;
this does not restrict mounts or the subprocess's direct filesystem access.

## Acceptance and remaining work

Test public-only external imports, both profile validators, strict schema/DTO
agreement, initialized host-to-real-process calls and native/process backend
equivalence. Cover malformed/duplicate/unknown input, wrong case/role/profile,
size/depth/count limits, missing capabilities, stale generation, unsolicited
mutations/signing, timeout/cancel, late/lost replies, real process restart,
exact lookup and confinement; fuzz framing and token/typed parsers.

Repeat actual reference matrices and both profile cells on named Linux arm64
and emulated amd64 after relevant changes, using fresh copied artifacts and
identities. Retain failures and intentional unknown generations. Run the full
workspace gate on the workspace and a copy of the public tree. Scan actual
logs, receipts and errors for secret markers and obtain independent read-only
review of the change.

This supplies no KD-014 generator, independent public conformance author,
KD-029 deployment, selective KD-030 withdrawal, P12 outbound/NAT/queued route,
backlog transfer, hardware, SDK freeze or release/publication acceptance.
Rollback to native execution is allowed only on a different fresh composition;
never edit an existing digest or supersede uncertain intent to change transport.

## Primary interfaces

Checked on 13 October 2026: [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
defines exact response correlation, result/error exclusivity and notification
rules; this bounded application profile excludes batching/positional params.
[NDJSON 1.0](https://github.com/ndjson/ndjson-spec) defines UTF-8 and LF/CRLF
framing; empty lines are explicitly refused here.
[Go os.Root](https://pkg.go.dev/os#Root),
[os/exec](https://pkg.go.dev/os/exec#CommandContext) and
[crypto.Signer](https://pkg.go.dev/crypto#Signer) document the confinement,
process-context and public/signing boundaries used here. Installed Go 1.27.2
sources also govern pinned behavior. These checks are source observations,
separate from implementation, test or hardware evidence.

## Independent design review

Formal round 1 was read only and found 0 P1 and 3 P2. Corrections narrow process
activation/withdrawal schemas to completed activated evidence with nonzero
revision and fresh live fields, pin safe code/kind/outcome/message combinations
and mandatory domain scope, and reject typed nil roles in both public aggregates.
The existing controller already refused staged activation; the schema correction
aligns the external success contract with that protected behavior. Corrected
behavior and actual evidence are reviewed again during round 2. This review
is not an external security audit.
