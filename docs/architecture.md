# Architecture

The delivered development profile is described in
[RFC 0004](decisions/0004-first-device-path.md). Public alpha contracts live in
`sdk/device` and `sdk/credentialprofile`; internal aliases preserve the existing
controller/store type identity. [RFC 0006](decisions/0006-alpha-sdk-process-adapters.md)
adds the negotiated process adapter path without changing transition ordering.
`internal/continuity` contains the separate in-memory fixtures.

[RFC 0005](decisions/0005-credential-profiles.md) defines explicit versioned credential
profiles, role trust and internal adapter composition implemented by KD-028.
Its stable-CN profile uses exact server certificate/key-to-generation enforcement.
The [profile reference](reference/credential-profiles.md) describes the fresh V2
HTTP lab; the original path below remains RFC 0004.

## Components

| Component | Owns |
| --- | --- |
| sdk/device | Alpha plans, public bindings, signer handles, strict configuration/trust/composition and typed roles |
| internal/device | Compatibility aliases to the same public types and errors |
| internal/controller | Ordering, restart reconciliation, certificate/activation checks, redacted receipts |
| internal/journal | Explicit SQLite schema 1/fresh 2, WAL/FULL, immutable identity, revision/fence and process lock |
| sdk/credentialprofile | Shared strict CSR/leaf/chain policy for both reviewed profiles |
| sdk/adaptergen | Exclusive creation of an external Go adapter module and its manifest, schemas, fixtures and CI |
| sdk/conformance | Public shared semantic cases and complete result checks through an explicit harness |
| sdk/conformance/fixture | Generated TLS HTTP fixture services with an in-memory effect ledger; separate from durable service evidence |
| internal/profilelab | Fresh generated V2 authority/control/application/peer enforcer and failure driver |
| adapters/profilehttp | Separate internal roles, immutable trust, bound neutral evidence |
| adapters/process | Bounded negotiated JSON-RPC NDJSON, exact scope correlation, scoped signer brokerage, unknown-result refusal |
| internal/keystore | Two confined software slots, signing, public chains, durable pointer and tombstones |
| adapters/stepca | Actual /sign and passive revoke, chain/CSR validation, explicit unknown effects |
| adapters/controlhttp | Scoped mTLS control/registry and application requests |
| adapters/mqttprobe | MQTT 5, bounded packets, fresh external request/reply and denial observation |
| internal/reference | Generated-data control service, independent application, responder and test driver |
| cmd/knowndevice | Cobra commands; metadata, transitions, preflight and separate simulations |
| cmd/kd-adapter | Selected public HTTP-role backend over protocol-only stdio |
| cmd/kd-adaptergen | Local Go adapter generator; no SDK publication or new composition |

Private keys stay behind signer/handle APIs. The journal stores public CSR,
certificates and observations, never operational private keys. The reference
control service holds the CA provisioner; it issues scoped tokens only in memory.
The device has an operational signer or a separate unique recovery signer.
The application has read-only slots; the responder has its own service key.
In the reference lab the control service also connects to the broker with its
service certificate. Its ACL allows only the readiness request/response topics
it uses to confirm that the responder is back after a broker restart.

## Durable transition

```mermaid
flowchart LR
    Plan[Persist plan and counter] --> Key[Stage distinct signer]
    Key --> Issue[Persist issuance intent]
    Issue --> CA[Issue and validate chain]
    CA --> Register[Register target ACL]
    Register --> Probe[Fresh external MQTT probe]
    Probe --> App[Observe independent application]
    App --> Commit[Sync pointer and commit]
    Commit --> Broker[Withdraw old ACL and sessions]
    Broker --> Observe[Re-observe current application]
    Observe --> Revoke[Revoke old certificate]
    Revoke --> Destroy[Destroy previous slot]
```

Every mutating effect has a durable intent and checkpoint. Journal and slot
updates are separate transactions. Restart checks the exact binding, public key,
CSR, chain and pointer and reconciles missing acknowledgments. A stable lock
prevents two local writers; SQLite updates compare revision and writer fence.
Slots use confined paths, private modes, file/directory synchronization and
atomic rename. Retired bindings have tombstones and cannot be revived.

The server reserves the operation/digest/target/CSR tuple before actual issuance
and compares the expected active generation. A late or differently bound result
cannot overwrite another operation. The same plan can repeat only explicitly
guarded service operations with durable status. Raw step-ca has no assumed
operation lookup or idempotent issuance: an unconfirmed result stays unknown,
without another /sign. Import requires explicit recovered public evidence and
fresh scope/chain/key/time checks.

An unfinished plan that expires requires intervention. The alpha refuses
further effects and a replacement plan; it has no in-place reauthorization or
cancellation. This preserves the recorded generation and unknown effects,
with a separate `plan-expired-intervention-required` receipt reason.
An already completed exact plan keeps its historical outcome after expiry,
with unknown health and no new effects or journal outcome rewrite.

## Application and broker

The external responder returns the exact operation, device, generation,
endpoint, random nonce and deadline on generation-specific topics. Retained,
stale or mismatched replies cannot authorize commit.

The independent application creates a candidate connection beside the old one,
verifies it, persists its intended active handle and only then switches and
closes the old session. Failure closes the candidate. A random session ID
distinguishes a real reconnect. The server independently queries the application's
authenticated observation endpoint; a device's self-issued ACK cannot advance
the registry. Live observation is repeated after broker restart.

On the V2 path, the controller durably records each new accepted Application
observation before its dependent pointer, withdrawal, revocation or destruction
step. Its nonce and request ID must differ from consumed activation/retirement
observations, its timestamp must advance and its activation revision must stay
fixed. A recent stored observation is history after restart, not a new challenge.
If this evidence write fails, the dependent effect stops.

The Mosquitto profile maps certificate CN to a generation username and explicit
ACL. Withdrawal atomically syncs the ACL, stops/waits for the broker and starts
it again. **All clients reconnect.** Retirement records durable policy and
terminated sessions; the device also observes old access denial and a fresh
current application probe. Valid old certificates require explicit MQTT denial.
Expired old certificates require verified server TLS and a protected remote
certificate refusal; local expiry/network failure is insufficient.

Retirement and CA revoke authenticate with the current target signer. The old
public chain and handle identify the artifact to withdraw. Historical validation
of an expired artifact grants no authentication, activation or fallback rights.

## Recovery, clock and limits

Enrollment/recovery require the separately pinned recovery signer; rotation
requires the exact current operational generation. The server reads current
fixture entitlement and denies revoked/retired devices. Recovery grants no MQTT
ACL. Missing/expired recovery needs intervention.

The controller requires `trusted-system-clock` and rejects wall time before
its durable floor. This assumption supplies neither a trusted time service nor
protection against a restored disk snapshot. Receipt outcome and checkpoint are
distinct from health; persisted status never claims a live application result.

Unknown/newer storage versions fail closed; migration is not implemented.
A WAL without its shared-memory sidecar needs intervention. Backup consistency,
retention, jittered scheduling, process isolation, TPM, hardware power-cut and
independent SDK conformance remain separate work. Process-kill/container tests do not
establish physical media durability or hardware erasure.

## Profile-aware path

V2 composes entitlement, authority, platform registration, transport,
application, clock and withdrawal roles behind the same transition sequence.
A persisted public snapshot binds profile policy, composition/version/artifact,
role roots/identities/caller pins, application/session policy and limits.
The server independently allows the exact snapshot; no missing role borrows
another pool. Its reservation records exact namespace/device/operation/plan,
original signed CSR/SPKI, certificate/generation, active binding and revisions.

The HTTP enforcer derives the peer leaf/SPKI from TLS and pins the connection;
a stable CN or device payload does not choose a generation. The application
has its own durable selection/status and revision. Control reads that status
through a pinned observer principal, creates a new bounded challenge and obtains
post-switch actual-peer observation before activation CAS. Callback code releases
local serialization during the remote observation and revalidates the reservation,
registry, entitlement and time after it returns.

V2 clocks propagate a finite trusted closed interval by monotonic elapsed time
and drift. Both bounds must fit certificate chains and deadlines; activation
requires the declared remaining lifetime. Restart obtains a new assessment
against the persisted lower-bound floor. The selected application has no
persistent backlog transfer. Withdrawal persists exact deny, removes sessions
under the declared whole-service lab scope, explicitly observes old reconnect
denial and freshly observes target use before revocation/key destruction.
These local roles remain trusted code, with no process isolation, hardware or
independent second-profile claim.

## Process execution

Fresh `local-http-process-lab/1` pins the wrapper executable separately from
the underlying HTTP service/controller artifacts. The host validates/copies
that artifact into a private execution directory, initializes exact protocol,
schema digest, capabilities, permissions, profile/snapshot and resource limits,
then dispatches the same public role interfaces. There is no backend fallback.
Host signers stay local; one call grants temporary opaque signing references.
Results and versioned errors bind the full plan and request scope. Known absence
is accepted only on an authoritative declared lookup/status method.

Timeout/cancel/session loss after dispatch remains unknown. A fresh process
session reinitializes and queries the original durable reservation; it never
reissues an uncertain certificate or removes intent. Late results cannot
advance a new call. Clock wire values receive conservative local elapsed-time
widening and a new local monotonic assessment; serialized monotonic timestamps
are not authority. The trusted subprocess and its permission declarations
provide no OS isolation, direct syscall confinement or hardware evidence.

## Adapter tooling

The [generator and conformance suite](reference/adapter-tooling.md) use the
existing public contracts. Generated adapters compose profilehttp and SystemClock
and run through the same process host. Their names identify modules, without
adding a credential profile, role ID or trust mechanism. The concrete manifest
binds a selected snapshot and executable; declarations grant no remote authority.

The public suite runs the same cases through an explicit adapter factory and
checks errors, full activation/withdrawal evidence and observed effect counters.
Its public fixture harness uses actual TLS connections and separate role roots,
with generated keys behind signers. Faults and the surviving in-memory backend
ledger are controlled test inputs. Restart creates a new adapter session over
that ledger; it does not prove service storage durability. Fresh step-ca and
application failure matrices remain separate. Tooling does not establish an
independent author, KD-029 interoperability, selective withdrawal or hardware.

Native profilehttp and the process host use the same complete activation and
retirement success checks through public `process.ValidateActivation` and
`ValidateRetirement`. The existing strict validators and protocol schema are
unchanged. The helpers perform no effect or channel authentication; controller
time/CAS and authenticated service authority remain separate. Adversarial fixture
cases deliver distinct malformed proofs to each adapter, require an observed
delivery and explicit refusal, and retain the old generation and effect counters.
