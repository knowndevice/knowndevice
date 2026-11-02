# Credential profiles

Explicit `knowndevice/v1alpha2` selects a reviewed credential policy and the
selected local generated-data HTTP composition. The existing v1alpha1 Linux/step-ca/
Mosquitto path remains available with its original digest encoding and shared
root limitation. Both paths are unreleased alpha implementations. This is not
a published stable SDK, a migration tool or independent deployment evidence.
The [alpha Go SDK](alpha-sdk.md) exposes these same strict contracts, with the
separate fresh process composition defined in
[RFC 0006](../decisions/0006-alpha-sdk-process-adapters.md).

| Policy | Operational identity | Generation authority |
| --- | --- | --- |
| reference-generation-cn/1 | One CN `gN.DEVICE.known-device.invalid` and one matching DNS SAN | Exact registered leaf/SPKI plus reserved generation |
| stable-device-cn/1 | One CN exactly equal to the registry device ID; absent SAN | Actual authenticated peer leaf/SPKI mapped to the durable server reservation |

Both policies require a distinct ECDSA P-256 key, SHA-256 CSR signature, exact
single-CN RDN, strict attributes/extensions, non-CA digitalSignature/clientAuth
leaf and bounded public material. Stable CSR attributes are empty and stable
certificates have only clientAuth EKU. Reference CSR contains only the one SAN
extension request; reference leaves retain acceptance of additional specific
EKUs. Unknown SAN GeneralNames, duplicate subjects/attributes, other key
algorithms and undeclared identity/authorization extensions are refused.
CSR is limited to 16 KiB; chains to 64 KiB and eight certificates.

The shared validator is used at CSR creation, controller, slot reload, control,
authority and platform boundaries. Exact CSR DER is retained because a new
ECDSA signature could produce a different request. Reservations permanently
bind namespace, device, operation, full plan, CSR, SPKI, certificate, generation
and revision. Stable CN, request generation and application/session identifiers
cannot select an authenticated principal. Unreserved same-CN certificates have
no application access. Consumed generations and uncertain issuance are not reused.

## New generated-data lab

Build first and select the architecture of the controller and helper actually
run. This example uses Linux arm64; amd64 execution on an arm64 host is emulation.

```sh
make check
bin/kd-profilelab seed --dir .work/new-profile-lab --profile stable-device-cn --service-artifact bin/kd-profilelab-linux-arm64 --controller-artifact bin/knowndevice-linux-arm64
export KNOWNDEVICE_PROFILE_DIR="$PWD/.work/new-profile-lab"
export KNOWNDEVICE_PROFILE_ARCH=arm64
export KNOWNDEVICE_PROFILE_BIN_DIR="$PWD/.work/new-profile-lab/artifacts"
export KNOWNDEVICE_LAB_USER="$(id -u):$(id -g)"
cp bin/kd-adapter-linux-arm64 "$KNOWNDEVICE_PROFILE_BIN_DIR/"
docker compose -f lab/profiles/compose.yaml -p new-profile-lab up -d
docker compose -f lab/profiles/compose.yaml -p new-profile-lab run --rm checks
docker compose -f lab/profiles/compose.yaml -p new-profile-lab down
```

The checks service mounts the adapter from the artifacts directory. Copy
`bin/kd-adapter-linux-<arch>` there. With rootless Docker, leave
`KNOWNDEVICE_LAB_USER` unset. Rootless Docker is not tested.

Seed refuses an existing directory and creates a new random namespace/device,
private demo keys and separate public role trust. Use `--profile
reference-generation-cn` for the other V2 policy on another fresh directory and
project. The selected service/controller executable hashes and template bytes
are bound into the composition. Rebuilding either executable changes that
binding; a pending operation cannot silently use the replacement. Retain its
state and start a separately generated identity for another disposable test.
Creating a second store for an existing identity is refused by current server
preflight/reservation fencing and is not an upgrade procedure.
Seed copies and syncs those artifacts into the fresh lab directory. Keep them
immutable while that run is active. Rebuilding
`bin/` must not replace a live lab's selected artifacts.

The lab uses real step-ca 0.30.2 `/sign` through an authenticated local issuance
endpoint, a peer-derived HTTP/TLS enforcer and a separate application process.
[Compose](../../lab/profiles/compose.yaml) pins the image. The
[stable template](../../lab/profiles/stable-client.tpl) specifies a single
CN, no SAN, digitalSignature, non-CA and clientAuth only; the
[reference template](../../lab/profiles/reference-client.tpl) retains the
matching DNS SAN. Template variables use `toJson`, as required by the
[Smallstep template documentation](https://smallstep.com/docs/step-ca/templates/).
A template alone is not issuance evidence: inspect the actual local certificate
and the retained check report before making that claim.

The authority requests 1200 seconds of total operational validity with a
30-second backdate. The accepted public policy is 300–1260 seconds, maximum
60-second backdate and at least 120 seconds remaining at activation. Zero
maximum backdate is unsupported in this selected local policy. A bound request
budget allows one `/sign`; no uncertain response or status query grants another.
Import is an explicit authenticated operation for that exact unknown reservation.
Multiple candidate leaves, a different key/profile/issuer, expired target or
changed CSR are refused. step-ca has no assumed Known Device operation lookup
or idempotent issuance contract.
[The pinned sign handler](https://github.com/smallstep/certificates/blob/v0.30.2/api/sign.go)
and [authority source](https://github.com/smallstep/certificates/blob/v0.30.2/authority/tls.go)
separate issuance from storage/response success.

For a new short-lived evidence lab, seed with
`--authority-lifetime-seconds 300`. A value other than the default 1200 selects
`local-http-lab/2` and binds its explicit 300–1200-second total request to the
snapshot before initialization. The 30-second backdate, accepted shared limits,
120-second activation margin and 600-second maximum plan remain unchanged.
This permits actual expiry before the original plan deadline without changing
the clock or relaxing validation. The [short-lived configuration example](../../api/examples/device-config-v1alpha2-short-lived.json)
is illustrative public metadata; generate fresh material for actual use.

The pinned Observer principal may read `/session-inventory` over the Control
role channel for the exact active plan. The bounded result includes actual
transport connection IDs, authenticated peer leaf/SPKI and immutable bindings;
unbound sockets are explicit. `authenticated` records a completed verified TLS
handshake; it does not assert current certificate validity or accepted requests.
This endpoint makes no durable writes. It supplies neither live application
acceptance nor effective withdrawal by itself.

## Trust, evidence and time

Control, application, transport and recovery use distinct role domains.
Issuance server trust, operational issuer trust and the exact authority caller
have separate inputs and permissions. The named backend step-ca HTTPS hop has
an explicit `authority-transport` origin, SAN, serverAuth and DER-root policy;
this one backend deliberately uses the operational issuer PKI. That explicit
choice does not supply another role's roots or admit a device operational or
recovery signer as an authority administrator. The observer is a pinned client
principal with application read/observe permission, not a fictional listener.

Public DER, role labels, expected peers, caller pins, issuer constraints,
profile policy, adapter versions/artifacts, composition, session policy and
limits enter a canonical public snapshot and its digest. Plans carry explicit
profile/composition/snapshot and role digests. The server independently pins its
allowed snapshot. Requests use the retained validated bytes; changed file
content, even at the same path, prevents further effects. There are no ambient
roots, proxy settings, redirects or missing-role shared-root fallbacks.

Application staging produces `candidate-verified`. Activation requires a
separate durable `activated` status and selection revision from the
Application role, then a new independent challenge observation of the target's
actual authenticated connection. Staging, a switch ACK or a device-provided
phase cannot satisfy control CAS. After restart, pointer/server/application
state is reconciled and live observations are obtained again.

The trusted-system-clock assumption produces a closed interval, normally
one second on each side of the sample. The configured maximum uncertainty is
a half-width of two seconds, so the entire propagated interval is at most four
seconds wide. Assessment age is at most ten seconds and assumed drift at most
50 ppm. Monotonic elapsed time advances and widens the bounds. A restart needs
a new assessment against the durable lower-bound floor. Both ends must fit
chain validity; the latest bound governs remaining lifetime, plan, entitlement
and challenge deadlines. Challenges last at most thirty seconds here (the
hard limit is sixty) and cannot exceed plan expiry. A slow effect is reassessed;
an expired unfinished plan requires intervention without digest edits.
These are declared clock assumptions, not trusted time or disk rollback protection.
The configured half-width must include the actual one-second uncertainty plus
maximum assessment-age drift; default age/drift needs at least 1001 ms. Lower
unsupported limits are refused before reservations or issuance.

## Sessions, withdrawal and remaining scope

Each network connection retains its actual peer binding and a distinct ID;
TLS tickets are disabled. The selected application declares
`new-connection-no-state-transfer`: it has no durable MQTT subscriptions,
telemetry/downlink backlog or transfer promise. No old connection is relabeled
as target. A future transfer policy must authorize the new target-key
connection explicitly and test the application data behavior.

The `authenticated-application-callback` route requires a reachable Application
endpoint. It does not implement an outbound-only device behind NAT, gateway
forwarding or queued observer records. Those P12 topology cases are unsupported
in this composition and remain separate from its authenticated callback tests.

Withdrawal persists the exact previous deny before session removal. The
whole-service lab may close unbound sockets as well as bound old connections;
this is an explicitly disruptive local scope. An actual old-signer reconnect
must receive bound explicit denial, and the target application must be freshly
observed before CA revoke or previous key destruction. A socket timeout, local
expiry, unknown TLS error or passive CA revoke cannot establish removal.
Unsupported expired-old negative observation remains unknown and preserves the
previous artifact. This new HTTP scope is separate from the reference
whole-Mosquitto restart and does not establish shared-deployment KD-030 withdrawal.

Authority revocation status is also bound to the exact previous generation,
including its original CSR, operation, plan, namespace, SPKI and leaf fingerprint.
A durable `not-started` status permits the first revoke request. A persisted
sent intent with no known result remains unknown after restart and does not
permit replay. Neither result substitutes for effective transport/application
withdrawal evidence.

[Schema/slot/server version 2](../compatibility.md) is for fresh identities and
stores only. v1alpha1 digests/defaults/checkpoints remain legacy contracts;
new alpha receipts use neutral withdrawal checkpoint names. There is no
identity reinterpretation, automatic migration, clone-safe import/export,
root rollover or pending-plan reauthorization. The [local Go generator and
public conformance suite](adapter-tooling.md) use the same reviewed roles.
SDK publication, independent KD-029 application profile, KD-030 shared
withdrawal, hardware power cuts and remaining 0.1 release gates are separate work.

## Observed local verification

On 13 October 2026 the final generated-data reference matrix completed 42 PASS
on Linux arm64 and 42 PASS on Linux amd64 emulated on an aarch64 Docker host.
Both V2 profiles completed 37 PASS on each architecture, including 25 actual
CLI SIGKILL checkpoints. The issued stable leaves were independently inspected
for exact device CN, absent SAN and clientAuth-only EKU on both architectures.
Separate external service SIGKILL/restart observations covered Application
staging/switch, control CAS/durable deny, fresh target observation and old-key
reconnect refusal. These are local container process results.

The service restart test reused one client session cache across full handshakes.
With tickets disabled, `DidResume=false` establishes a full reconnect under that
configuration; it is not evidence of an old-ticket rejection or MQTT resume.
Actual Linux filesystem ENOSPC/FULL/EROFS checks and version/refusal tests also
passed. The full local and public-only source gates passed.

Separate fresh labs on Linux arm64 also exercised actual 300-second expiry
and passive CA revoke before withdrawal for both profiles. After expiry the
original old socket remained in inventory, while requests received generic
refusal and new connections failed without authenticated exact denial.
Reconciliation persisted deny and terminated sessions but retained unknown
withdrawal and the old key. Target generation 2 had a separate fresh observation.
After the real passive CA revoke, both the original session and a full old-key
reconnect still accepted requests. Controller withdrawal remained not-started;
CA HTTP success supplied no effective-withdrawal evidence.

Actual expired unknown-issuance import was refused for both profiles while the
unchanged original plan was still valid, using the exact original CSR/SPKI,
scope, operation, plan and generation. A later original-plan deadline refusal
was recorded separately. One CA issuance remained reserved without registration,
activation, reissue or generation reuse.

Fresh offline-return tests changed the fixture registry from authorized to
retired or revoked while the actual controller container was disconnected.
After reconnect, fresh authenticated entitlement and exact lookup requests
were denied; CLI reconciliation remained unknown with the original issue
intent, CSR/SPKI, counter 2 and active generation 1. The server retained its
already known issuance result without registration or activation. No cached
permit or additional `/sign` was used, and neither identity was reauthorized.
This tests the current fixture entitlement, separately from the durable
registry's historical registration status; it supplies no NAT or queued-delivery
capability claim.

The P1–P19 record distinguishes these observations from parser/unit/fixture
coverage. It does not declare all RFC variants conformant. Outbound-only/NAT/
queued observation, selective unrelated-client preservation and backlog transfer
are unsupported here. Independent KD-029, scoped KD-030, SDK/process contracts,
hardware and remaining 0.1 release gates remain separate. The local alpha
SDK/process implementation has its own verification and publication scope.
