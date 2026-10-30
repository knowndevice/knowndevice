# RFC 0004: First device path

Status: internal alpha contract reviewed on 12 October 2026. This profile is
a local reference lab, not a stable SDK. Runtime evidence remains required.

The controller keeps one logical device identifier and monotonic credential
generations. An operation has a random immutable identifier, expected active
generation, reserved target generation, slot, configuration digest, mode and
deadline. Its canonical JSON digest binds authorization to that exact plan.
Generation numbers are never reused, including after a failed operation.

## Storage and failure checkpoints

Use a stable-inode exclusive process lock for the lifetime of the journal.
SQLite uses schema version 1, one connection, FULL synchronization and WAL;
every update compares the previous revision and the current writer fence.
Unknown/newer storage versions are refused without mutation. Failed writes
stop further effects. A durable wall-time floor detects clock rollback under
the explicit trusted-system-clock assumption of this lab.

Slots A/B contain an immutable manifest binding device, operation, generation
and public-key fingerprint, a software signing key and a public certificate
chain. Create in a temporary directory with exclusive files, mode 0600/0700,
sync files and directory, rename and sync the parent. Confine every path and
reject symlinks. An active pointer is atomically replaced and synchronized.
Journal and slot storage do not share a transaction: restart validates the
manifest, CSR, stored chain and pointer before proceeding. Never delete an
orphan or reuse a slot merely because an acknowledgment was not journaled.

Checkpoints are planned, key-ready, issue-intent, issued, register-intent,
registered, verified, activate-intent, activated, committed,
broker-retire-intent, broker-retired, ca-revoke-intent, ca-revoked,
destroy-intent and retired. Persist each intent before its effect. A killed
process at an intent reconciles the remote status; it does not infer failure.
Execution outcome and device health are separate from these checkpoints.
Read-only inspection refuses a WAL without its shared-memory sidecar; no
automatic migration, backup/restore or disk rollback resistance is delivered.

## Authority, authorization and recovery

The reference control service holds the CA provisioner and broker control
privileges. The device never receives those privileges. It authenticates
using its current operational signer or a separately provisioned, unique
device recovery signer. Recovery certificates have no MQTT ACL permissions.
The service checks its current entitlement registry, exact device, mode,
expected/target generation, plan digest, CSR public key, expiry and one-issue
budget. Before issuance the server atomically reserves the tuple of device,
target generation, operation ID, plan digest and CSR key fingerprint. A second
or late binding is denied even if it carries a different operation ID. Server
generation reservations survive restart and are never reused. Activation and
retirement compare the expected current generation using server-side CAS.
Revoked/retired devices, missing/expired recovery and untrusted time
are denied. A client-side allowlist or receipt is not server authorization.

Use step-ca /sign with a service-issued token. /rekey preserves Subject/SAN
and therefore cannot change the generation-specific CN in this profile.
Do not assume an operation-id or certificate lookup API. The control service
persists issuance intent before /sign and stores the public result before
replying. Loss between CA success and that storage is unknown. No second
issuance for that operation is permitted. The only continuation is importing
the recovered public chain, after chain/key/identity/EKU/validity checks and
a fresh server entitlement check, or operator intervention. Do not silently
supersede unknown issuance or recycle the target key.

Certificates use the exact generation subject gN.DEVICE.known-device.invalid;
the logical device ID stays unchanged. Verify the configured trust chain,
CSR/signing key, CN and DNS identity, client-auth usage and wall-time validity.
CA revocation blocks renewal; it does not prove broker access withdrawal.

An unfinished plan past its deadline requires operator intervention; the
alpha does not reauthorize, cancel or supersede that operation in place.
It refuses further effects and a replacement recovery plan while preserving
the recorded active generation and uncertainty. The receipt uses
`intervention_required` with `plan-expired-intervention-required`.

## MQTT, application activation and retirement

Mutual TLS verifies the server and presents the target signer. Separate
request/reply topics are scoped to the device and generation. A separately
running responder returns a fresh challenge with exact operation, generation,
endpoint, nonce and deadline. Reject retained, replayed, wrong-topic and
mismatched messages; transport success alone cannot authorize commit.

The application is an independent device-side MQTT worker with read-only
access to the software signer slots and a mutually authenticated control
endpoint. The application activation endpoint must reconnect using the target signer
and return its observed generation with the same operation/digest binding.
Reconcile that acknowledgment and the durable pointer before committing.
Its live acknowledgment binds application ID, device, operation, digest,
certificate fingerprint, an ephemeral session ID and a fresh external probe.
The application keeps the old connection while creating/verifying the candidate;
only successful durable activation permits switching and closing the old one.
The control service independently queries the application's mTLS observation
endpoint, restricted to its pinned control certificate. A device-supplied ACK
cannot establish that observation or advance server authority.
Verification is repeated
after restart and before retirement. A failed probe
keeps the previous authorized generation and never retires it.

Broker retirement must persist a generation-specific deny policy before
withdrawing access, terminate existing sessions and verify reconnect/app
denial. Dynamic-security disableClient alone is insufficient with CN-mTLS;
its response also does not establish durable configuration. The initial lab
may use an atomic synced ACL file and a controlled broker restart, with the
explicit cost of reconnecting all lab clients. Denial survives broker restart.
Report TLS acceptance, new MQTT access denial and existing-session termination
separately. Only observed effective withdrawal advances broker-retired.
The broker restart also disconnects the new generation. Re-observe the
independent application on the target with its own fresh external probe
after that restart and before CA revocation or key destruction. A timeout
does not prove old access denial or that a session was terminated.
Then request CA revocation, reconcile uncertainty and destroy the previous
slot only after all required retirement evidence is durable.

Retirement/revocation authenticate with the current target signer. The previous
handle and public chain are withdrawal artifacts, not authentication. An
expired previous certificate is validated historically only for that artifact
and a negative access observation. It cannot be activated or used as fallback.
Still-valid previous credentials require explicit MQTT ACL denial. Expired
ones require a real peer TLS certificate refusal after verifying the broker's
server certificate; local expiry, transport failure and timeout are not remote
evidence. The current application must still pass a fresh live probe.

The demo step-ca logger uses the supported common format. Its JSON logger
includes the OTT and is unsuitable for the report/log redaction requirement.
The failure matrix can ask the real CA for a 30-second certificate under an
explicit demo-only duration profile, then wait for real expiry without changing
the system clock. This is not a production certificate policy.

## Scope and alternatives

A pinned maintained Go MQTT client is preferred. If its source/dependencies
cannot be obtained, that adapter remains blocked; do not fake transport
success. Journal, signer, controller contract tests and strict CLI planning
can proceed independently. A custom broker fingerprint plugin would retain
rekey but adds a trust-critical plugin and is deferred. Shared generation CNs
and treating CA revoke as broker retirement are rejected.

The reference control/application service is trusted lab code and runs as
an independent process. It is not OS isolation, hardware attestation, a
production registry or a universal application integration. Recovery uses
existing mTLS and CA token mechanisms, not a new signed-time or trust protocol.

## Required evidence

Use real services for enrollment/rotation/ACL denial/retirement and a real
killed controller process at every checkpoint, including success-before-ack
gaps. Separately test SQLite/disk-full/read-only errors, two writers, stale
fences, recovery denials, replay and receipt redaction. Run the full local
gate on a clean checkout of the public tree. Missing containers, dependencies
or hardware block those checks and remain visible in the README.

API evidence: [step-ca sign](https://raw.githubusercontent.com/smallstep/certificates/v0.29.0/api/sign.go),
[step-ca rekey](https://raw.githubusercontent.com/smallstep/certificates/v0.29.0/api/rekey.go),
[step-ca common logger](https://raw.githubusercontent.com/smallstep/certificates/v0.29.0/logging/clf.go),
[Mosquitto CONNECT](https://raw.githubusercontent.com/eclipse-mosquitto/mosquitto/v2.0.22/src/handle_connect.c),
[dynamic security ACL](https://raw.githubusercontent.com/eclipse-mosquitto/mosquitto/v2.0.22/plugins/dynamic-security/acl.c),
[dynamic security persistence](https://raw.githubusercontent.com/eclipse-mosquitto/mosquitto/v2.0.22/plugins/dynamic-security/plugin.c).
These are source/documentation observations, not lab test results.
