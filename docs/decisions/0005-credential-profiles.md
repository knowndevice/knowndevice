# RFC 0005: Credential profiles, trust roles and adapter composition

Status: internally reviewed alpha design, 12 October 2026; local KD-028
implementation in the declared local composition, 13 October 2026. Related tasks: KD-027
(design), KD-028 (implementation), KD-013/014 (SDK and conformance), KD-029
(independent second profile) and KD-030 (scoped withdrawal). Ownership follows
the task assignee; no pilot operator or external approval is assigned here.

Choose explicit, versioned credential profiles and compose adapters by role.
Keep the reference generation-specific certificate identity. Add a profile
with a stable device CN whose generation authority comes from a durable,
server-enforced certificate/key binding. Bind role-specific trust and the
composition to each plan; preserve reconciliation and retirement ordering.

KD-028 implements these profiles and role bindings through explicit v1alpha2
configuration, schemas, fresh stores and the local HTTP composition. See the
[profile reference](../reference/credential-profiles.md) for its exact scope.
[RFC 0004](0004-first-device-path.md) describes the delivered reference path;
its unreleased status and the remaining [0.1 gates](../../ROADMAP.md) remain.
Retained reference runs have 42 PASS on arm64 and emulated amd64. They establish
neither named-hardware behavior nor an independent integration profile.

## Problem and alternatives

The v1alpha1 path's CSR construction, controller/key-store checks and adapters
require `gN.DEVICE.known-device.invalid` as the only CN and DNS SAN. The CLI
shares one root pool among control, application, issuance and MQTT. Platform
combines entitlement, registration, probe, application and retirement; its HTTP
denial seam uses MQTT types. Changing only the CA cannot remove these
assumptions. See [architecture](../architecture.md),
[current contracts](../protected-contracts.md) and
[adapters](../../adapters/README.md).

| Alternative | Benefit | Cost and failure boundary |
| --- | --- | --- |
| Make the reference naming, root pool and MQTT flow universal | Smallest change; existing lab remains direct | Excludes stable device identities and other application/session models; a common root union admits the wrong service role |
| Let each stack adapter supply arbitrary CSR, validation and lifecycle callbacks | Accommodates vendor rules quickly; few common types | Safety checks become inconsistent; adapters can accept the same subject with the wrong key or silently weaken recovery/withdrawal; incompatible core forks remain likely |
| Version credential rules and compose adapters with common bound evidence | Keeps strict validation, shared ordering and distinct trust; supports stable subject through explicit server mapping | Requires versioned schemas, enforcement capabilities and more refusal cases; a stack without exact peer-key/session mapping is unsupported |

Select the third alternative. The credential profile owns identity and public
material validation; adapters own actual effects and protocol observations;
the controller owns ordering and checks. A profile cannot authorize itself or
replace entitlement. Capabilities are requirements with rejection behavior,
not advertised integration support. A service may implement several roles,
but each role keeps separate permissions, trust and evidence.

Reversal requires a new profile/version and a reviewed migration. Do not relax
an existing validator, reinterpret a stored identity, edit a plan digest or
silently map an unknown profile to the reference default. A stable SDK waits
for independent second-profile evidence and the 1.0 contract review.

## Profiles and immutable bindings

A **credential profile** specifies certificate identity, CSR rules, key and
signature algorithms, accepted issuance policy and validation. A **deployment
composition** selects versioned role adapters, endpoints, trust, application
scope, session policy, observation route, withdrawal scope and limits. Neither
description establishes interoperability until its named stack is tested.

Approved identifiers are `reference-generation-cn/1` and `stable-device-cn/1`.
Each carries `id`, integer `version` and a `policyDigest` over its complete
public policy. A composition has its own ID, version and digest. Unknown
versions, changed content under a known digest and missing required
capabilities fail before key staging or remote effects. A profile version
changes whenever any acceptance rule changes, including SANs, algorithms,
issuer constraints or validity policy. Endpoint/adapter/trust changes also
change the resolved configuration digest, even without a profile change.

Keep logical device ID, credential generation, key identity, execution
outcome, checkpoint and health distinct. Both profiles retain the current
device ID grammar, random operation ID, bounded deadline, expected and target
generation, non-reused generation counter, target slot and signer boundary.
Tenant/deployment scope is an explicit immutable registry namespace; it is
never inferred from CN. A single-tenant lab declares one deployment namespace.

Use lowercase SHA-256 hex of exact DER for `publicKeyDigest` (SubjectPublicKeyInfo),
`csrDigest` (complete signed CSR) and `certificateFingerprint` (leaf certificate).
Compare parsed key algorithm/parameters and SPKI bytes as well as their
digests. Certificate issuer identity and serial number are stored as public
revocation references; neither substitutes for the leaf/key binding.

The plan precedes key creation. Its digest binds the configuration, device,
operation, mode, generations, slot and deadline; it does not pretend to know
the future CSR. After key staging, one immutable issuance reservation binds
that plan to the exact CSR and SPKI. Persist the original CSR; ECDSA signing
can produce different DER on another attempt. Restart must not create a new
CSR, key or reservation for the same uncertain issuance.

### CSR construction and certificate validation

Construct PKCS#10 with the staged handle's signer and public key; verify its
signature locally, at control reservation and at the authority boundary.
PKCS#10 carries a signed subject, public key and attributes; it does not
authorize a Known Device operation. [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986.html).

| Rule | reference-generation-cn/1 | stable-device-cn/1 |
| --- | --- | --- |
| Subject | Exactly one CN RDN: `gN.DEVICE.known-device.invalid`, N is target generation in decimal | Exactly one CN RDN: `DEVICE`, byte-for-byte registry device ID; unchanged across generations |
| CSR SAN | Exactly one DNS SAN equal to CN; no IP, URI or email SAN | No SAN extension; no DNS, IP, URI or email SAN |
| CSR attributes/extensions | One extensionRequest containing only the specified SAN; reject duplicates and additional attributes/extensions | Empty attributes; reject extensionRequest, challengePassword and every other attribute |
| Key / CSR signature | Distinct ECDSA P-256 key per generation; ECDSA with SHA-256 | Same algorithm and distinct-key rule; stable identity does not permit key reuse |
| Certificate identity | Same exact single CN and DNS SAN as CSR | Same exact single CN and absent SAN as CSR |
| Generation at the access service | Existing generation CN plus registered leaf/SPKI binding | Actual authenticated peer leaf/SPKI mapped to the server reservation; CN or client-supplied generation alone is insufficient |

An exact subject check examines all RDNs and attributes, including duplicate
CNs and unknown OIDs. It must not compare only a parsed CommonName or display
string. Do not add a generation, operation, custom identity OID or unreviewed
SAN to the stable profile. Such a change needs another profile/version.

For both profiles require a non-CA leaf, digitalSignature key usage,
clientAuth EKU, no anyExtendedKeyUsage, and no unhandled critical extension.
Preserve the reference profile's acceptance of additional specific EKUs;
EKUs never grant control/application service roles. The stable profile permits
only clientAuth. Certificate extensions required by normal chain validation
(basic constraints, key usage, EKU, SKI/AKI) may be CA-added; identity-bearing
extensions must match the profile exactly. Issuance policy explicitly declares
any additional noncritical extension; an undeclared identity/authorization
extension is rejected, never consumed as authority.

Validate bounded PEM/DER, exact CSR/leaf/signer/handle SPKI agreement, the
profile, the configured operational issuance chain and approved issuer,
signature algorithms, and the entire assessed time interval within validity
under the clock rules below.
Validate path constraints and EKU with explicit roots; a root included in the
returned chain supplies no trust. Configure allowed certificate lifetimes,
maximum backdate and minimum remaining lifetime for activation in the
composition; the CA result must meet them. These checks specialize X.509
path/usage validation, rather than replacing it. [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).

Enforce CSR <=16 KiB and public chain <=64 KiB/8 certificates at every
controller, store and adapter boundary, rejecting empty material and junk.
Private material never crosses the signer/opaque-handle boundary. Historical
validation may bind an expired previous artifact for withdrawal/revocation
and a restricted negative observation. It grants no authentication, activation,
fallback, import of a usable target or recovery permission.

KD-028 must use the same selected profile at CSR creation, controller,
key-store reload, control service, authority and platform validation. Do not
make portability by skipping a check in any of these locations.

### Server reservation and enforcement

The trusted control service persists the following immutable reservation
before sending issuance. Public fields are defined here as proposed data,
not an implemented vendor or process API:

| Binding | Required server value |
| --- | --- |
| Namespace and identity | `deploymentId`, `deviceId`; current registry entitlement/recovery status and revision |
| Plan | Entire validated plan, `operationId`, mode, expected/target generation, slot, `configDigest`, `planDigest`, expiry and one-issue budget |
| Expected current | Authoritative active generation, leaf fingerprint and SPKI digest; absent only for enrollment at generation 0 |
| Policy | Credential profile ID/version/policyDigest, composition digest, role trust digests and exact application/endpoint scope |
| Candidate proof | Original signed CSR DER, csrDigest and SPKI digest; verified CSR signature and staged-handle public binding |
| Effects and fencing | Reservation revision, highest reserved generation, issuance send-intent/result, registration/activation/withdrawal status and exact remote references |
| Issued artifact | Verified chain, leaf fingerprint, issuer/serial, validity and the same CSR/SPKI/profile binding; initially absent |

In one serialized durable reservation transaction, control checks fresh
entitlement, the authorized caller/mode, plan expiry/digests and expected
active binding. It reserves unique `(deploymentId, deviceId, operationId)`
and `(deploymentId, deviceId, targetGeneration)` keys, enforces one unfinished
operation per device, advances a monotonic reservation floor and refuses a
reused SPKI for that device. Every consumed target remains reserved after
failure/restart. A replay with the same complete tuple reads status; any
different plan, profile, CSR or key is a conflict. A rolled-back device cannot
overwrite the server floor. Server disk rollback resistance is not claimed.

Control persists send-intent before asking the authority and the verified
public result before acknowledging. Its transaction cannot span the CA.
Unconfirmed issuance consumes the budget and stays `unknown`, even if the
process died before it can prove whether bytes reached the CA. Raw step-ca
has no assumed Known Device operation lookup or idempotent issue capability.
No resend follows an uncertain `/sign`, error response or token expiry.

Import is an explicit authenticated reconciliation operation for that exact
unknown reservation, with fresh entitlement, expected generation, profile,
CSR/key/chain/time checks. It cannot replace an existing different result or
send another issuance. If no unique valid public chain can be recovered,
intervention is required; the slot, reservation and uncertainty remain.
Discovery of multiple certificates for the reserved key also requires
intervention and scoped accounting/withdrawal, not arbitrary selection.

At registration, the platform must consume an authenticated control binding
and compare its revision, complete candidate tuple and verified certificate.
The data-plane enforcer must derive leaf fingerprint/SPKI from the actual TLS
peer (or a vendor's tested authenticated certificate-ID mapping), then look up
that exact binding. A CN, username, topic, ClientID, application payload or
device-supplied generation cannot choose a binding. Candidate authorization
has explicit scope beside the current generation; an unregistered certificate
with the same stable CN receives no application access.

The platform pins each authenticated network connection to the actual
generation/key at connection creation. It may not reclassify a live old-key
connection as new when the active record changes. TLS resumption tickets must
preserve and recheck that credential binding or be disabled; a ticket cannot
bypass later withdrawal. Durable application session state, including an MQTT
ClientID's subscriptions/backlog, is distinct from a network connection. A
declared transfer/resume policy may let the target retain that state on a new
connection authenticated with the target key. It never lets the old key resume
access. Authorization is durable and checked on reconnect and at the declared
enforcement points. A stack that exposes only a stable CN and cannot enforce
exact key/generation access is unsupported for the stable profile.

All role requests/results carry the immutable plan/reservation binding,
subject generation and key/certificate reference, request ID, role/action and
bounded deadline. Activation/withdrawal distinguish target and previous
bindings explicitly; a bare `generation` field cannot select either. Remote
responses are accepted only over the role's authenticated channel and at the
expected revision. HTTP 404, timeout, redirect, malformed body or a generic
vendor ACK cannot establish absence. Only a bound authoritative status with
declared semantics can establish `not-started`, completion or denial.

Activation CAS compares the full expected active binding and reservation,
checks registration, completed durable Application activation/status and a
new independent application observation after that activation, then
durably changes the authoritative active binding. Repeating an exact
successful CAS reads its record; it never advances another operation. A stale
result cannot commit or withdraw the active generation, even if its CN matches.
Local pointer, application state and server CAS are separate durable effects;
restart reconciles all three before commit or retirement.

### Caller scope and recovery

| Action | Accepted authenticated caller and preconditions |
| --- | --- |
| Rotate entitlement / issue / issuance reconciliation | Exact currently authorized operational generation, leaf and key for the expected binding |
| Enroll / recover entitlement / issue / issuance reconciliation | Separate device-scoped recovery signer, exact pinned public binding, valid recovery chain/time and current registry entitlement; enroll expects 0, recover expects recorded current generation |
| Candidate registration and activation request | Exact issued target signer bound to the existing reservation; cannot authorize another issuance, device, plan or generation |
| Durable application status / independent observation | Pinned application-status and observer service identities for the configured application/scope; device operational/recovery signers cannot produce accepted status or observer records |
| Withdrawal and CA revocation | Exact current target operational signer after observed activation/CAS; previous public chain selects the withdrawn artifact and supplies no caller authority |
| Status | Read-only, action-scoped authenticated caller; historical metadata cannot authorize a new effect |

Recovery is its own credential profile and trust role, with a unique signer
per device and a registry-pinned leaf/SPKI binding. It has no operational
generation or MQTT/application permissions. Its identity follows the separate
reference `recovery.DEVICE.known-device.invalid` CN/DNS convention unless a
later recovery RFC changes it; `stable-device-cn/1` does not reinterpret it.
Operational and recovery SPKIs must differ. Reject revoked/retired devices,
missing/expired/untrusted recovery, wrong namespace, operational credentials
used for recovery, and recovery used for register/activate/withdraw.

Every new protected effect rechecks current entitlement and the reservation;
an old entitlement response or offline cached permit cannot revive authority.
Inability to obtain authoritative entitlement blocks new effects. Preserve
the last recorded generation, but do not claim its live health or ongoing
remote authorization from that preservation. Device revocation may deny all
generations; continuity does not override that policy.

## Trust by role and digest

Separate TLS server authentication, issuance chain validation, client/caller
authentication and application observation authority. DNS checking of a TLS
server is unrelated to the profile's deliberate CN-based device identity.
Every network connection verifies its server SAN/hostname, chain, usage and
time; leaf/SPKI pins add restrictions and never disable those checks.

| Domain | Client trusts / expected peer | Service accepts / allowed authority |
| --- | --- | --- |
| Control | Control server roots, HTTPS origin and exact SAN identity; optional additional leaf/SPKI pin | Explicit operational issuance roots with exact active/candidate registry binding, and separate recovery roots/pin on recovery actions only |
| Application | Application service roots, origin, status/reporting and observer service identities, and application ID | Exact issued target operational signer for its activation request; pinned control observer for reads and separately scoped application service reporter for outbound status, with disjoint action permissions |
| Issuance | CA HTTPS server roots/origin/identity separately from operational certificate issuer roots and allowed issuer policy | Scoped control-side provisioner/authority credentials; no device receives CA administrative privilege |
| Recovery | Recovery issuer roots, exact per-device leaf/SPKI, identity and lifecycle in the registry | Recovery actions at control only; never admitted as an operational/application principal |
| Transport | Transport server roots, endpoint, SAN identity and protocol policy | Explicit operational issuer policy plus enforced generation/leaf/SPKI mapping and application ACL; observer/responder service principals have separate scopes |

Service certificates for control, application and transport use distinct
role identities and trust stores. Operational issuer trust is an explicitly
declared input to control's operational-client validator and transport's
device-client validator; it is not a pool that trusts service certificates
or recovery credentials. A chain that passes generic TLS but has the wrong
peer kind, purpose, configured role identity or registry binding is denied.
Observer/responder service certificates cannot become device generations.
The application observation issuer/peer policy is explicit, including the
service identity permitted to read the observation endpoint.

The legacy lab intentionally shares a CA. Preserve that v1alpha1 behavior
with its documented limitation. New separated-trust compositions must declare
distinct service and recovery trust domains; reference compatibility cannot
silently supply a union for a missing role. Explicit operational-client issuer
reuse across allowed actions is different from trusting every issuer for
every role. Wrong-role certificates must be rejected even where a deployment
shares an organizational PKI.

For proposed v1alpha2, resolve a **public trust snapshot** before planning:

1. Parse bounded explicit PEM files once; reject junk, duplicate DER and
   unsupported certificates. Sort anchor DER hashes and pin lists; retain
   verified public DER in an immutable operation snapshot. Do not load ambient
   system roots, arbitrary URLs or environment proxies.
2. Serialize a versioned fixed-field JSON structure containing the profile
   policy, composition, exact role/action labels, normalized endpoints,
   expected peer identities, issuer constraints, DER hashes, public credential
   pins, adapter ID/version/artifact digest/configuration, required capabilities,
   application/session/observation/withdrawal policies and resource/time limits.
   Include public recovery identity/pin, never private bytes or a CA token.
3. Hash each role snapshot and the complete resolved structure. Put the
   profile/composition references and role trust digests in the plan as well
   as `configDigest`; cover them with the plan digest. Use the existing
   fixed-struct JSON/SHA-256 approach under a new API version, with digest
   test vectors and explicit list ordering. Do not reuse v1alpha1 digest rules
   for a differently shaped plan. File path alone never binds trust content.
4. Persist the exact public snapshot with intent; use those loaded bytes for
   requests, including restart, rather than reopening a mutable path between
   validation and TLS. Require the selected local configuration and server's
   independently provisioned allowed snapshot to match the plan. The server
   must not trust an arbitrary root set supplied by the device.
5. If configured material/identity/profile changes while unfinished, refuse
   further effects under that plan. Authenticated read-only reconciliation can
   use the original still-allowed snapshot; record what remains unknown. If
   original trust is expired, distrusted or removed by server policy, require
   intervention. Never widen roots, switch profiles or rewrite the digest.

These hashes identify accepted content; they are not a trust distribution or
root rollover protocol. Trust is provisioned through an authorized local and
server configuration process. Root expiry, emergency root changes, ownership
transfer and signed-time/bootstrap mechanisms need separate review. Public
trust snapshots disclose deployment metadata and follow redacted-report rules.

## Adapter composition

The proposed contract splits the current Platform responsibilities. It does
not export `internal/device` as a stable SDK or prescribe MQTT types to an
HTTPS, CoAP or other adapter. Exact Go/process method names remain KD-013
work, governed by these role responsibilities and acceptance rules.

| Role | Owns | Required result / capability |
| --- | --- | --- |
| Entitlement | Current device/tenant status, caller mode/scope, expected binding, bounded issuance permission | Authenticated current decision/revision bound to the plan; no CA or application side effect |
| Authority | Profile-constrained issuance, public-chain validation, import/status and certificate revocation | Exact reservation/CSR/key artifact; declare status/idempotency gaps and unknown effects; no application health claim |
| Platform | Register the candidate's credential-to-device/generation mapping and access scope; query durable registration | Peer-derived leaf/SPKI binding capability, server revision and declared candidate/current coexistence; no local pointer mutation |
| Transport | Authenticated connection, bounded challenge exchange and negative reconnect observation on the chosen wire protocol | Bound peer/path/freshness/access observations; no generation commit or implicit application activation |
| Application | Stage/verify actual candidate use, persist/switch intended credential, report active instance/connection and independently observed acceptance scope | Distinct candidate-verified and durably activated records; new post-activation observation; close only the failed candidate before successful switch |
| Clock | Assess wall time/source/uncertainty and local monotonic deadlines against a durable floor | Trusted/untrusted/unknown assessment with age/uncertainty bound; does not manufacture trusted time |
| Withdrawal | Persist exact previous-generation deny policy, terminate its sessions, reconcile and prove effective access removal | Durable policy revision, authenticated session termination/inventory, explicit old reconnect/access denial and current application observation |

The signer/key store and journal remain core boundaries. The host supplies
scoped signer or opaque signing operations, public profile/reservation data
and permitted actions; adapters receive no raw private-key serialization.
The composition declares which implementation supplies each required role
and which role/action may use each credential. There is no default adapter
substitution after a capability or trust failure.

Before any effect, negotiate versions, required capabilities, endpoint and
artifact identity, size/time limits, permission scope and status semantics.
Required capabilities include exact peer credential binding, application
activation/status, independent fresh observation, and the selected withdrawal
scope. A reference-lab composition may explicitly declare whole-broker
withdrawal; a shared-deployment composition must require generation-scoped
withdrawal. Refuse a capability gap instead of accepting a weaker observation.

An adapter result contains a versioned evidence envelope: role/action,
request/operation IDs, deployment/device, plan/config/profile/composition/trust
digests, expected/target and observed subject binding, remote revision/reference,
observation source, time/deadline and safe status. Application evidence adds
application ID, phase, durable activation revision/record reference, exact
active binding, actual authenticated peer certificate/key, live instance and
connection ID, application session ID, accepted challenge and application scope.
The connection ID changes on reconnect even if application session state stays.
Withdrawal evidence also
names the exact previous credential, policy revision and session scope.

`candidate-verified` evidence proves staging only and cannot advance activation
CAS. `activated` evidence requires an Application-role durable status record
binding operation, digests, target credential and active selection revision,
plus a new independent observation of actual use after that selection. The
observer cross-references that revision and the target's authenticated
connection. A staged nonce, a device's `activated` field or an activation
request acknowledgment cannot supply either condition. Lost switch responses
must be reconciled through authenticated durable status, then fresh observation.

Common semantic observations distinguish authenticated peer acceptance,
explicit access denial, verified session termination and unknown. A wire
adapter translates its tested native facts into those observations and keeps
bounded native reason metadata if useful. MQTT reason codes, retained flags,
topics and Go TLS alert shapes belong to the MQTT/TLS profile; another adapter
is not required to return them. Unsupported negative observation prevents
retirement, even when ordinary connectivity works.

Every mutation has a local durable intent, server preconditions, bounded
context, and a declared reconciliation method. Local refusal before sending
may prove `denied`/`not-started`. Anything with uncertain remote effect remains
`unknown`. Repeat only exact operations with tested guarded semantics; a
claimed idempotency key or retryable error cannot grant another CA issue.
Cancellation stops further work and reconciles effects already attempted;
it does not erase intent, release a reserved generation or revoke a successful
effect. An expired unfinished plan still requires intervention. Reauthorization,
supersession and cancellation of the durable plan need a separate protocol.

Built-in and process adapters use the same binding/evidence rules.
[The process protocol](../../protocol/README.md) now implements the locally
reviewed JSON-RPC/NDJSON role negotiation in
[RFC 0006](0006-alpha-sdk-process-adapters.md). SDK publication remains pending. Process
transport and read-only MCP are host interfaces, separate from device wire
protocols. A subprocess is trusted selected code, not OS isolation.

## Clock decisions and freshness

The new clock contract supplies a trusted closed wall-time interval
`[earliest, latest]`, its local monotonic assessment instant, a finite drift
bound and maximum assessment age. The composition sets maximum uncertainty,
assessment age and drift assumption and binds them to the digest. This is an
explicit trust assumption, not a delivered time service or time attestation.
Unknown/untrusted, unbounded, too-wide or stale assessments block effects.

Before each decision, advance both bounds by monotonic elapsed time and widen
them by the declared worst-case drift for that elapsed time. A backward wall
sample inconsistent with the durable floor is refused; conservatively advance
the floor only to a validated lower bound. If monotonic continuity is lost,
including restart, obtain a new assessment and compare the durable floor.
Never persist a monotonic reading as proof across reboot or subtract uncertainty
to manufacture additional authorization time.

Require `NotBefore <= earliest` and `latest < NotAfter` for the complete
authentication/issuance chain. Check validity/path constraints at both ends
of the interval; checking only its midpoint is insufficient. Require
`NotAfter - latest >= minimumRemainingLifetime` at activation, and
`latest < planExpiresAt` and `latest < challengeDeadline` at every effect/CAS
that depends on them. An interval crossing either boundary is refused even
if its midpoint passes. The latest conservative bound also governs expiry of
entitlement and observation records. Recheck after a slow remote operation;
historical status reconciliation cannot extend a deadline or create live health.

Control measures challenge elapsed time with its own monotonic clock, alongside
the conservative wall deadline, so an observer/device timestamp alone cannot
prove freshness. Restart invalidates outstanding live challenges until a new
assessment and challenge are obtained. The legacy v1alpha1 trusted-system-clock
and floor behavior stays unchanged; new interval rules apply to v1alpha2.

## Activation, sessions and observation without inbound reachability

Keep the RFC 0004 order: staged distinct key → issue → register → fresh
verification → actual application activation → reconcile application/server/
pointer → commit → effective previous access withdrawal → fresh current
application observation → CA revoke → key destruction. No role can skip an
edge based on its own success receipt. An application switch that succeeds
before a lost response is reconciled, not interpreted as a failed candidate.

Declare ClientID/session policy, subscriptions, session expiry, resumption,
coexistence and interruption budget in the composition. Reference verification
uses random clean MQTT sessions and no retained challenges. That verification
policy is separate from the actual application's session/backlog policy.
MQTT uses ClientID for session state; reusing an already connected ClientID
takes over its connection. Clean Start and Session Expiry change persistence,
so a successful clean probe does not measure backlog continuity.
[MQTT 5 sections 3.1.2, 3.1.3.1, 3.1.4 and 4.1](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html).

If candidate and current cannot coexist under an application's required
ClientID, the profile must specify and test another permitted staging route,
such as a separate candidate identity/session with equivalent application
permissions. The candidate must be verified before switch. Preserve the
previous authorized key/access until the new application is observed active.
A profile without a safe staging route is unsupported. Measure interruption
during an allowed reconnect separately; preservation of authorization does
not promise uninterrupted traffic. Never silently change ClientID or discard
the old persistent session/backlog to make verification pass.

The existing direct control-to-application callback remains the reference
observation route. The proposed outbound observation route uses established
authenticated channels and server-side evidence, without requiring a listener
on the device or designing a new signed ACK protocol:

1. Application staging produces `candidate-verified` evidence. Application
   then durably completes its active selection and reports `activated` status
   with a monotonic activation revision, exact target binding and live instance.
   Control obtains that status over the pinned Application-role channel.
   For an unreachable device-side application, its distinct application service
   principal reports status on an outbound authenticated channel; the service
   trust/identity and application/device scope are part of the composition.
   This is a trusted application status report, not a device operational-key
   ACK. A server-side application may expose the same durable status directly.
   Without this independently authenticated status route, the profile is unsupported.
2. Only after that durable status, control allocates and records a new random
   single-use 128-bit challenge
   bound to operation, plan/config/profile/trust, target leaf/SPKI, application,
   activation revision, endpoint/path, observer identity and a deadline of at most one minute,
   also bounded by plan expiry. The target application initiates an outbound
   connection or uses its already active target connection through the chosen
   authenticated transport. The earlier staged challenge cannot be reused.
3. An independently authorized application observer on the server side sees
   the actual authenticated peer binding and tested application event. It
   receives the challenge through the authenticated control channel and
   witnesses the required response/use on that exact session. The device can
   carry correlation data, but cannot assert which TLS key the observer saw.
   If TLS terminates in a gateway, the gateway is an explicit trusted enforcer
   with an authenticated bound evidence interface; untrusted forwarding
   headers and device-supplied peer metadata are rejected.
4. The observer durably records post-activation acceptance, connection/application
   session/instance IDs, the Application activation revision and exact active
   binding, its own revision, new challenge and scope. Control reads that record through
   the application-role channel using its pinned observer/service policy.
   A device-delivered copy is a hint for lookup, not activation authority.
5. Control checks completed durable `activated` status and its matching observer
   record, nonce, one-use consumption, target/key/connection, all digests,
   current registration/entitlement, source identity, deadline and assessed
   time at activation CAS. Duplicate queries return the same record; replay
   for another CAS or plan is rejected. Cached status can reconcile historical
   activation but supplies no fresh health or retirement observation.
6. After restart, reconnect or withdrawal, demand a new challenge/current
   application observation before any next effect that depends on live use.
   An expired challenge requires a new bounded verification attempt under
   the same valid plan, never a new issuance. Offline observation or expired
   plan stops the transition with unknown health/intervention as appropriate.

The observer/application service remains trusted code. This route proves the
declared server-observed application scope and key/session use, not device
hardware state or arbitrary consumer behavior. Endpoint identity, NAT path,
gateway trust and loss/replay behavior must be tested by KD-029.

## Effective withdrawal and failure checkpoints

Withdrawal first writes an exact previous-generation/leaf/key deny policy
under the current target binding and server revision. It then terminates all
live network connections belonging to that previous principal, invalidates or
fences its resumption credentials, verifies authoritative connection state
and explicit denial on a new old-credential connection/access attempt,
and freshly observes the current application. Late connections and reconnect
races must be fenced by the deny policy; a ClientID-wide disconnect that also
kicks the target cannot claim selective withdrawal.

Policy acceptance, durability, session termination, reconnect denial, live
current application and CA revocation are separate evidence. A returned
boolean, local expiry, zero packets, timeout, closed socket or generic HTTP
error cannot establish withdrawal. If connection inventory/termination cannot
be authoritatively reconciled, remain unknown and keep the previous artifact.
Authorization remains denied after service restart; target and unrelated
clients remain usable under the scoped profile. The reference whole-broker
restart remains an explicitly disruptive lab mechanism, excluded from the
second shared-deployment gate.

Withdrawal does not require deleting durable application backlog merely
because it was queued while the previous key was active. A declared/tested
application-session transfer policy may preserve it for the target's newly
authenticated connection. Record that policy and its exact device/application
scope, recheck resumed subscriptions/permissions, and verify that the old key
cannot reconnect or resume access. A retained session ID/backlog is never
evidence that an old-key live connection was terminated or that fresh target
verification occurred. Without an approved transfer policy, do not silently
reuse state or delete it to claim continuity; report the capability gap.

For valid previous credentials, require an explicit protocol access refusal
from the authenticated service. For expired previous credentials, an adapter
may use a narrowly declared authenticated peer TLS refusal plus durable
enforcement/session evidence. Its TLS implementation/version and refusal
classification must be tested; unknown alerts and network failure stay unknown.
The current pinned Go negative-observation implementation is a reference
capability, not a universal transport requirement. Neither local expiry nor
CA revoke removes the session/deny evidence requirement.

Persist intent before each mutation and persist evidence before advancing
its checkpoint. Preserve the existing checkpoint names in v1alpha1. In the
new alpha representation, the historical `broker-retire-*` names map explicitly
to Withdrawal role intent/result; schema naming must not imply MQTT is universal.

| Failure gap / checkpoint | Reconciliation and stop rule |
| --- | --- |
| Planned / key staging / key-ready | Reconcile journal, immutable profile/public-trust snapshot, manifest, handle and counter; no orphan deletion or generation/key reuse |
| Issue-intent / server reservation / CA success before stored result | Query exact durable reservation; unknown raw CA result needs validated public import or intervention; no second issue |
| Issued / chain storage / register-intent | Revalidate profile, chain and actual signer; reconcile exact candidate mapping, never register an unrelated same-CN credential |
| Registered / verified / activate-intent | Check current authorization and fresh candidate/application evidence; failed candidate preserves previous pointer/key/access and closes only its own session |
| Application switch / activated / server CAS / pointer before committed | Read application durable status, server binding and local pointer; reconcile the exact target; fresh live observation before effects, no local-only commit |
| Committed / withdrawal intent / durable deny before session termination | Reconcile policy revision and exact old session scope; keep target active and previous artifact; deny precedes reconnect races |
| Session termination / lost withdrawal response | Query bound policy/session status, explicitly observe old denial and freshly observe target; timeout leaves retirement unknown |
| Access withdrawn / CA-revoke-intent / CA result lost | Preserve durable withdrawal; reconcile revocation capability or require intervention; do not restore old access or infer CA effect |
| CA-revoked / destroy-intent / tombstone or deletion before receipt | Reconcile exact old handle, tombstone and pointer; never delete target or revive old binding; last usable authorized target stays protected |
| Any failed write, untrusted clock, changed trust or expired unfinished plan | Stop further effects, preserve intent/counter/uncertainty; read-only reconciliation only where authenticated; no digest edits or automatic superseding recovery plan |

Completed expired plans keep their historical outcome without new effects;
health is unknown until a separate current observation. Recovery when the
previous certificate has expired follows the same verified-target/withdrawal
order. No historical certificate validation reauthorizes the expired key.

## Compatibility, schemas and storage

No delivered v1alpha1 file or digest changes in KD-027. KD-028 must retain the
strict reference default, its current canonical struct JSON digests, schema-1
journal, manifest/binding version 1, pointers/tombstones and existing evidence
meaning. Shared-root v1alpha1 is an explicit legacy composition with its
existing limitations; it cannot claim new separated-trust conformance.

Introduce `knowndevice/v1alpha2` explicitly for new profile-aware plans,
configuration and receipts. Do not accept new fields silently in v1alpha1.
The first implementation uses freshly initialized schema-2 journals,
version-2 slot metadata and version-2 server reservations. Existing schema-1
state is never rewritten on open or opt-in. Upgrading an existing identity,
changing profile in place, import/export of state and interrupted migration
remain a separately reviewed migration task. Initializing another store with
an existing device identity is not a migration or clone-safe workaround.

| Surface | Required KD-028 change and refusal |
| --- | --- |
| Configuration / examples | Explicit credential profile and deployment composition; role roots/expected identities/issuer and caller policies; generic endpoint/session/observation/withdrawal fields; retain a separately tested v1alpha1 example |
| Plan | Bind API/digest encoding version, immutable profile/composition/public trust snapshot references and full existing plan fields; reject unknown versions or mismatched config/trust |
| Handle / CSR / credential validation | Persist profile/policy and public SPKI/CSR/plan binding; signer/handle remains opaque; same validation on new CSR, store reload, adapter entry and server |
| Journal / slots / pointer / tombstones | Version 2 records include immutable plan/profile/config/trust references, CSR/key/leaf binding and neutral evidence; WAL/FULL, lock, revision/fence, sync and intent ordering remain; tombstones retain profile plus device/generation/key identity |
| Server registry/reservation | Namespace, unique tuples/counters, exact expected/candidate/active certificate-key bindings, recovery pins, trust-policy allowlist and role/evidence revisions survive restart |
| Receipt / schemas | Public profile/composition/trust digests and observed credential/action scope, separate uncertainty/unsupported/intervention, outcome/checkpoint/health; bounded metadata, no raw tokens/keys/application payloads |
| SDK / process contracts | KD-013 negotiates role capabilities, neutral evidence schemas and profile/trust versions; legacy wrappers only advertise facts the reference adapters can establish |

Old binaries refuse newer API/storage before mutation. New binaries choose
the legacy path only for explicit v1alpha1/schema-1 inputs; they never guess
a missing profile in version 2. New state cannot be opened by a downgrade.
Rollback eligibility requires a future tested migration; it cannot revive
retired/revoked material or shrink counters. Preserve WAL/SHM refusal and
software-key/clock/disk-snapshot limitations. This RFC specifies new-store
versioning, not a backup, rollback or migration tool.

Schema and example changes happen with implemented behavior, compatibility
tests and generated CLI reference in KD-028. All JSON/YAML/process inputs
retain duplicate/unknown-field, nesting and size refusal. Proposed names in
this RFC are not available flags, commands or vendor operations.

## Acceptance and concrete negative tests

The table specifies future tests, not observed KD-027 results. Exercise both
profiles using real generated-data services where an external effect is
claimed; fixtures/unit peers cover parser and binding rules with their scope
reported. Record actual operation counts, policy revisions and server/session
observations before and after each injected failure.

| Test | Input / failure | Required observation |
| --- | --- | --- |
| P1: strict profile | Wrong profile/version; stable CN presented as reference; extra/duplicate CN or SAN/attribute | Refused at every CSR/store/controller/authority/platform boundary; no issue/registration effect |
| P2: key binding | CSR signed by another key; cert for another CSR; altered SPKI; same key reused on later generation | Refused; current key/pointer preserved; consumed counter never reused |
| P3: same stable CN | Valid second leaf with the correct stable CN but unreserved key/cert; payload claims target generation | Exact data-plane mapping denies access; no activation CAS; server records the real peer key |
| P4: trust roles | Valid wrong-role service/observer/recovery leaf, wrong issuer/SAN/EKU, extra root from another role | Role validator denies even if generic chain validation succeeds; no shared-root fallback |
| P5: digest content | Replace root/pin/issuer/profile/adapter/session policy at same path; mutate it after planning or between validation and dial | Config/plan mismatch stops effects; TLS uses immutable validated snapshot; original uncertainty remains |
| P6: fencing | Concurrent operations for one device; same operation with changed CSR/digest; reused target/counter; late activation/withdrawal response | Durable uniqueness/CAS conflict; no overwritten active binding, reused key/generation or withdrawal of target/unrelated device |
| P7: issuance unknown | CA actually issues, response or control result-storage is lost; CA error after effect; restart | Unknown; raw /sign count unchanged by reconcile; exact validated import completes only its reservation |
| P8: import denial | Wrong leaf/key/profile/issuer/device; expired target; different existing result; multiple candidate certs | Denied or intervention; no reissue, slot recycling or activation |
| P9: recovery | Revoked/retired registry, stale entitlement, expired/missing recovery, wrong device, operational-as-recovery, recovery-as-application | No issue or application/withdrawal access; authorization checked on server, no TLS bypass |
| P10: application refusal | TLS succeeds but application ACL/actual candidate use fails; successful staged challenge followed by activation persistence failure | No commit/CAS or old retirement; candidate-verified evidence cannot supply activated status; old authorized pointer/key/access remains; failed candidate connection closes |
| P11: observation forgery | Device self-ACK or activated field, wrong status/observer role, staged/replayed nonce, wrong activation revision, old connection/cert/digest or endpoint | No activation CAS; distinct authenticated durable status and new post-activation observer evidence required; persisted status cannot claim live health |
| P12: outbound topology | Inbound access disabled; lost/duplicate/out-of-order observer records; untrusted gateway peer headers | Legitimate outbound server-observed activation works; forged/late evidence denied; loss remains unknown |
| P13: activation gaps | SIGKILL after staging before durable switch, after application switch, server CAS, pointer sync and before journal acknowledgment | Staging alone never advances CAS; exact application/server/pointer reconciled; new post-activation challenge; no issuance retry, local-only commit or premature retirement |
| P14: selective withdrawal | Old live session plus target and unrelated clients; lost deny/termination response; racing reconnect | Deny durable before kill; all old sessions verified terminated; old new access explicitly denied; target fresh app and unrelated traffic pass |
| P15: restart/resumption | Service restarts after deny; old TLS ticket or old-key MQTT resume; authorized target reuses ClientID/backlog under declared transfer policy | Deny survives restart/resumption; old connection never relabeled target; new target-key authorization enforced; backlog preserved only under tested policy, with duplicate/loss/interruption evidence |
| P16: false denial | Local old expiry, network blackhole, unknown TLS alert, disconnect ACK or CA revoke without session evidence | Withdrawal remains unknown; no previous key destruction; target health measured separately |
| P17: clock/offline | Rollback, unknown/stale clock, nonzero-uncertainty interval crossing NotBefore/NotAfter, activation margin, nonce/plan/entitlement deadline; reboot; offline return with changed entitlement | Refuse at both interval boundaries; reassess after restart; stop effects/intervention as appropriate; exact intent/counter retained; no cached authorization or expired evidence use |
| P18: storage/version | ENOSPC/read-only, two writers, stale fence, manifest/profile/pointer mismatch, version-2 state opened by old binary | Refuse protected writes and further effects; no migration/downgrade mutation; target/previous lifecycle preserved |
| P19: compatibility/redaction | Existing v1alpha1 vectors/failure matrix and new schema examples; corrupt public snapshots; tokens/keys/payloads in errors | Legacy digests/behavior remain; unsupported data denied; bounded metadata only and explicit unknown health/outcome |

KD-028 acceptance requires strict reference compatibility and the new
profile/trust/binding/failure tests with named services. Repeat the existing
reference failure matrix on both recorded architectures after relevant code
changes; emulation stays labeled. Parser vectors and local stable-subject
enforcement tests establish KD-028 behavior, not the independent KD-029 gate.

### A second real profile: KD-029 and KD-030

Before a stable-contract proposal, an author outside the initial
implementation must use public alpha contracts/docs and the same core to
deliver a named, real stable-identity application profile. Changing just
the CA under the reference CN/topics/session assumptions is insufficient.
No author, platform account, equipment or independent deployment is assumed.

- Name CA, platform/broker, transport, application and adapter versions,
  profile/policy/artifact digests, role trust, permissions, peer/key mapping,
  ClientID/session policy, coexistence/staging route and acceptance scope.
- Use the actual application and consumers. Where offered, test telemetry,
  downlink, offline backlog, duplicates, delayed/out-of-order traffic, disconnect
  and reconnect during rotation/recovery. Measure loss, duplicate handling,
  backlog delivery and interruption; explicitly report unsupported application
  features. Fresh challenge success alone cannot establish those properties.
- Exercise NAT/no inbound device reachability and an independent authenticated
  observer. Retained application data and ordinary queued messages cannot
  become fresh verification or extend an expired plan. Offline return requires
  new entitlement/time assessment, reconciliation and live observation.
- Test durable withdrawal of one old credential generation, all its live
  connections and old-key resumption rights; preserve application backlog only
  under the declared target transfer policy. Require explicit old reconnect denial, current application
  health and unrelated-client availability without restarting every broker
  client. KD-030 must supply this tested capability.
- Retain redacted real-service conformance, failures, unknown effects, revisions
  and operator actions. Local generated services may establish a real-stack
  integration; they do not become a pilot deployment, hardware power-cut
  evidence or a 30-day independent operation report.

Selection of the stack and author remains open for KD-029. Platform accounts,
costs and production access require their own authorized scope. Named hardware,
external security review and remaining 0.1 publication gates are separate.

## Primary interface observations

Checked on 12 October 2026. Pinned-source observations constrain this design;
they are not vendor conformance or new runtime results.

- step-ca v0.29.0 `/sign` accepts CSR plus OTT; its request does not supply a
  Known Device operation lookup/idempotency contract. Certificate creation can
  precede a storage error, so a failed response cannot prove no certificate.
  Use `/sign` for the reference profile and preserve unknown-result rules.
  [Sign handler](https://raw.githubusercontent.com/smallstep/certificates/v0.29.0/api/sign.go),
  [authority signing/storage source](https://raw.githubusercontent.com/smallstep/certificates/v0.29.0/authority/tls.go).
- `/rekey` passes the old authenticated certificate and new CSR public key;
  the authority preserves subject/attributes. Stable subject makes rekey
  conceivable, but it does not add entitlement, operation lookup or exactly-once
  semantics. KD-028 does not require a rekey mechanism; `/sign` can be reused
  only with a tested issuance template that meets the selected profile.
  [Rekey handler](https://raw.githubusercontent.com/smallstep/certificates/v0.29.0/api/rekey.go),
  [authority renewal/rekey source](https://raw.githubusercontent.com/smallstep/certificates/v0.29.0/authority/tls.go).
- The pinned `/revoke` handler implements passive revocation; its success
  cannot prove platform policy persistence or live-session removal.
  [Revoke handler](https://raw.githubusercontent.com/smallstep/certificates/v0.29.0/api/revoke.go).
- Mosquitto v2.0.22 `use_identity_as_username` replaces the MQTT username
  with certificate CN. A stable CN therefore collapses generations for that
  ACL mapping; changing MQTT username cannot repair it. This is a design
  inference from the source, not a tested stable-profile broker capability.
  [Pinned CONNECT source](https://raw.githubusercontent.com/eclipse-mosquitto/mosquitto/v2.0.22/src/handle_connect.c),
  [configuration manual](https://mosquitto.org/man/mosquitto-conf-5.html).
- Dynamic-security `disableClient` selects a username, kicks that username
  and calls config save. This does not establish exact leaf/generation mapping,
  verified persistence or selective removal under a shared stable CN. A custom
  enforcement plugin or another stack would need named-version evidence in
  KD-030; neither is selected or delivered here.
  [Pinned dynamic-security client source](https://raw.githubusercontent.com/eclipse-mosquitto/mosquitto/v2.0.22/plugins/dynamic-security/clients.c).
- Microsoft's third-party IoT Hub X.509 page specifies device CN=deviceId,
  illustrating a stable identity requirement. It now points to a superseding
  Azure Device Registry certificate-management preview. These pages motivate
  the profile; they do not establish Azure support, API/version selection or
  permission to provision a service. Recheck both before selecting that stack.
  [IoT Hub X.509](https://learn.microsoft.com/en-us/azure/iot-hub/authenticate-authorize-x509),
  [certificate-management preview](https://learn.microsoft.com/en-us/azure/iot/iot-certificate-management-overview).

## Review decision, open questions and KD-028 handoff

Two independent read-only review rounds completed on 12 October 2026. Round 1
found two P2 issues (staging evidence could satisfy activation CAS; clock
uncertainty lacked a boundary rule) and one P3 issue (network connection binding
was conflated with durable session/backlog state). The corrections require
authenticated durable activation plus new post-switch observation, conservative
time intervals, and explicit target-authorized backlog transfer; P10/P11/P13,
P15 and P17 cover their refusal cases.

Round 2 confirmed all findings closed and found no regression or unresolved
security/function finding in the evaluated design. The selected alternative
stands. These two design reviews establish neither runtime conformance nor an
external PKI/security audit. KD-028 implementation review and observed P1–P19
results have separate evidence and explicitly recorded limits.

The selected design fixes identity, role trust, immutable binding, capability
refusal, reconciliation and retirement requirements. The following choices
remain bounded follow-up work rather than permission to weaken those rules:

| Question | Task and required resolution |
| --- | --- |
| Exact stable-profile authority template and issuance lifetime values | KD-028 pins local step-ca 0.29.0/templates, requests 1200 seconds with a 30-second backdate, and validates actual no-SAN CN/clientAuth issuance; the profile reference records the accepted time limits |
| Final Go method names and complete process negotiation schemas | KD-013/014 derive them from these roles and conformance cases; remain alpha until independent profile evidence |
| Second application/observer topology, session policy and scoped enforcer | KD-029/KD-030 select a named stack/author and verify its actual peer/session interfaces; unsupported mapping or observation blocks that profile |
| Legacy identity migration, trust rollover, durable plan reauthorization/cancel | Separate reviewed protocols/migration work; preserve refusal and intervention behavior until delivered |

KD-028 requires profile validation at every existing identity boundary,
explicit role trust snapshots/digests, exact control/platform binding and
neutral evidence behind an opt-in v1alpha2 on new generated state. The
v1alpha1 path and its strict default remain available. Schemas, examples,
compatibility and reference must change together. Acceptance requires P1–P19
and the real reference matrix to pass, with skips and unknown results
retained, and independent review. No existing lab identity/state migration
is implied. SDK publication, a real second profile, selective shared-deployment
withdrawal and hardware evidence remain separate tasks.

## Local implementation scope

The fresh `local-http-lab/2` composition adds an explicit
`authorityLifetimeSeconds` request bound to the snapshot and composition digest.
Its accepted range is 300–1200 seconds of total validity with the same
30-second backdate; the shared profile, accepted lifetime/backdate limits,
120-second activation margin and 600-second maximum plan remain unchanged.
This enables real expiry/import observations within a valid original plan.
`local-http-lab/1` keeps its fixed 1200-second request and existing digests;
no existing snapshot, plan or store is rewritten. Changing a live composition
still requires new generated state, rather than a plan edit or migration.

The observer-only `/session-inventory` lab endpoint returns a bounded snapshot
of actual transport connections, peer leaf/SPKI and immutable connection bindings.
Authentication here means a completed verified handshake, not current validity
or accepted access on that connection.
It performs no durable writes or access changes. A live socket, its absence or
this inventory alone cannot establish application health or effective withdrawal.

KD-028 delivers both profile validators, immutable public trust/composition
snapshots, exact durable server bindings, transport-neutral internal roles and
evidence, and explicit v1alpha2 on fresh version-2 stores. Legacy v1alpha1
digests, strict reference defaults and failure semantics remain available.
The [profile reference](../reference/credential-profiles.md) records the pinned
authority template, limits, role ownership and available lab commands.

Both named local composition versions use an authenticated Application
callback, `new-connection-no-state-transfer`, disabled TLS tickets and
`whole-service-lab` withdrawal. Unsupported topology/session/scope capabilities
are refused or remain unknown; they do not become permissive fallbacks.
P1–P19 includes additional cases beyond that composition. Outbound-only/NAT and
queued-observer delivery, backlog transfer, selective shared-deployment
withdrawal are not established by these local results. Fresh short-lived local
labs observed real V2 expiry and passive CA revoke for both profiles; neither
effect supplied effective-withdrawal proof. Exact expired issuance import was
refused within a valid original plan, separately from later deadline refusal.
Actual offline return after a fixture entitlement change to retired or revoked
also refused fresh current authorization and exact known-result lookup,
preserving the original unresolved intent/CSR/SPKI/counter without another sign
or activation. The fixture statuses were not restored to authorized.
The [local alpha SDK/process contracts](../reference/alpha-sdk.md) and
[adapter tooling](../reference/adapter-tooling.md) are implemented separately.
SDK publication, KD-029, KD-030, hardware and the remaining 0.1 release gates
remain open.
