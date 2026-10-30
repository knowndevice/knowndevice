# Threat model

This is a design baseline, not a completed security audit. Revisit it when
an adapter, recovery path, storage format, or deployment profile changes.

## Assets and trust boundaries

Protect operational and recovery private keys, identity/ownership bindings,
CA and platform authorization, active-generation pointers, journal integrity,
and the freshness of verification. Public fingerprints and device IDs can
still be sensitive deployment metadata.

Boundaries separate application/controller, controller/key store,
device/authority, device/platform, extension process/host, fleet/operator,
and diagnostic client/framework. The device administrator, CA operator,
and authorized extension code have substantial trust. A software file
key store cannot protect keys from a fully privileged device attacker.

| Threat / failure | Required response | Remaining limitation |
| --- | --- | --- |
| Loss of power during transition | Durable intent and reconcile both journal and slots | Actual media guarantees need power-cut tests |
| Lost CA/platform response | Query or idempotent retry under declared capability | Some authorities cannot establish exactly-once effects |
| TLS succeeds but ACL/application fails | No commit; preserve last usable authorized generation | Probe covers only configured application scope |
| Replay of a successful probe | Nonce, generation, endpoint, deadline and retained-message checks | A compromised authorized responder can lie |
| Stolen software key / cloned disk | Report software protection; enforce registry revocation | Without another trusted signal, clones can look legitimate |
| Revoked device uses recovery | Fresh server entitlement check before issuance | Offline devices cannot observe every new revocation |
| Recovery credential expires or is lost | Preflight and explicit operator intervention | No recovery guarantee without remaining trust |
| Clock rollback / stale snapshot | Trusted-time assessment and fencing/preconditions | Disk rollback resistance may require hardware |
| Malicious or compromised plugin | Trusted pinned artifact, scoped brokered operations, size/time limits | A normal subprocess is not an OS sandbox |
| Traversal / symlink in adapter artifact | Resolve in owned directory; reject symlink escape; verify size/digest | OS isolation remains separate |
| Compromised fleet coordinator | Local scope and plan verification; signed bounded commands | Coordinator and policy-update trust need later RFC |
| Secret leakage in logs/receipts/MCP | Metadata allowlist and explicit redaction tests | Debug output from third-party code needs review |
| Device forges its own activation ACK | Control queries the independent application via mTLS | The reference application remains trusted code |
| Failed candidate activation closes the old session | Verify/persist candidate before replacing the old application session | Demo ACL updates intentionally restart all broker clients |
| Operational signer attempts recovery | Require the exact separately pinned recovery certificate for that mode | Compromise of the trusted registry/control service is outside device isolation |
| Denial of service / fleet return burst | Backoff, jitter, resource limits, bounded flash writes | Endpoint limits and real throughput vary |

## Invariants

Never disable TLS certificate validation to recover. Never automatically
roll back to expired, revoked, retired, or compromised material. Never
destroy the last authorized usable generation before the new generation
is verified and actually active. A local receipt cannot grant remote
authority. A client agent cannot approve its own fleet mutation.

Use established cryptographic primitives and protocols. Verify CSR/cert
bindings and identity constraints. Do not accept a MAC address or serial
number as authentication. Attestation needs a separate verifier, freshness,
and policy; using a TPM signer is not itself attestation.

The implemented reference profile is defined in
[RFC 0004](../decisions/0004-first-device-path.md). It uses a current fixture
registry, server-side generation reservation, software signer slots and a
trusted-system-clock assumption with a durable floor. A restored disk snapshot
or privileged key copy is not prevented. The shared-memory WAL refusal needs
operator intervention; no backup/migration tool is provided.

The step-ca common logger excludes OTT fields; the JSON logger is unsuitable.
The lab verifies log/report redaction independently of receipt field limits.
Existing MQTT sessions are terminated by a whole-broker restart, then current
application health and old reconnect denial are separately observed.

## Review evidence before 1.0

Review recovery scope, key custody, CA and broker revocation effects,
clock assumptions, slot/journal crash consistency, extension permissions,
MCP aliases/profiles, redaction, dependency provenance, and upgrade rollback.
Record tested hardware, filesystem, firmware, broker, CA, and adapter
versions. Publish findings and fixes at an appropriate level after any
private vulnerability disclosure is complete.

## Explicit profile-aware scope

The fresh V2 HTTP lab implements [RFC 0005](../decisions/0005-credential-profiles.md).
A stable subject is an identity label; exact TLS leaf/SPKI, original CSR,
reservation, plan and namespace determine access. Wrong-role leaves, stale
revisions, changed public trust content and missing capabilities fail closed.
A separate Application-role durable status and a fresh post-switch observation
are required; staged success cannot grant activation CAS.

Role snapshots bind the selected service/issuer roots, peer/caller identities,
artifacts and limits. The named CA backend deliberately shares its issuer PKI
through a separate explicit HTTPS SAN/serverAuth policy, never a root fallback.
Recovery has no operational/application/withdrawal permission. Unknown issuance
consumes its one-send budget; recovery/import cannot release that generation.

The full conservative interval governs validity and deadlines. Restart needs
fresh assessment/challenges; historic evidence grants no live health. Connection
identity is separate from any durable application state. The local policy has
no backlog transfer and allows whole-service removal of unbound sockets.
Timeout, absent traffic, TLS uncertainty and CA revocation remain insufficient
withdrawal evidence. Hardware, trusted time, disk rollback protection, shared
withdrawal and independent application deployment still need their own evidence.

## Process extension scope

[RFC 0006](../decisions/0006-alpha-sdk-process-adapters.md) adds trusted selected
stdio adapters. Pin bounded executable bytes, stage a private immutable copy,
negotiate exact schema/version/capability/permission/snapshot scope, and reject
uninitialized, duplicate, unsolicited, malformed or oversized messages. Only an
active parent call may grant bounded signer callbacks; revoke the temporary
grant on completion/cancel. Never serialize the signer-bearing Credential.

Timeout/cancel/crash/lost responses preserve unknown effects and exact intent;
transport never blindly retries a mutation. Error correlation must prove full
scope and the permitted code/kind/outcome combination before a status can mean
not-started. Raw child stderr is not forwarded. Local rooted artifact checks
restrict host accesses but do not restrict bind mounts or direct child syscalls.
The process is trusted operator-selected code, without an OS isolation claim.
