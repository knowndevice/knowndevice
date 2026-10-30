# Reference adapters

These packages implement the public alpha Go roles and explicit versioned
device contracts. They are not a stable SDK. The adapter unit tests use real TLS over `net.Pipe`
and a protocol peer; those tests do not establish Mosquitto, step-ca server,
device hardware, power-cut, or process isolation compatibility.

`stepca` uses the pinned step-ca `v0.29.0` `/sign` and passive `/revoke` API.
The trusted control service supplies scoped one-time tokens through an
in-memory callback. The client never returns a token or raw remote body in
an error. It validates the CSR signature, exact CN and DNS identity, public
key, configured issuer chain, client-auth usage and validity before returning
an issued chain. Issuance and revocation status are `unknown`: step-ca has no
operation-ID lookup in this profile. The client sends no blind retry.
[`/sign` source](https://github.com/smallstep/certificates/blob/v0.29.0/api/sign.go),
[`/revoke` source](https://github.com/smallstep/certificates/blob/v0.29.0/api/revoke.go).

The profile uses `/sign` for each generation-specific subject.
`/rekey` supplies the new public key while preserving the existing identity,
so it cannot implement this profile's changing CN.
[`/rekey` source](https://github.com/smallstep/certificates/blob/v0.29.0/api/rekey.go).

`RevokeCertificate` accepts public material in the control service, which
does not possess the device signer. Historical certificate validation is
limited to binding an already-issued artifact for revocation; it cannot
authorize TLS, restore a revoked device or revive an expired generation.
The control service must check its current entitlement and exact operation
reservation before supplying a token.

`controlhttp` keeps separate HTTPS origins and trust profiles for control
and application activation. Every request carries the exact plan, and every
accepted response binds its operation ID, device, plan digest and generation.
Status `not-found` is accepted only on a status endpoint, in a bound JSON
response. HTTP 404, lost responses, invalid bodies, redirects and server
errors cannot establish that a mutation did not happen.
Every unconfirmed `/sign` result, including HTTP 403 after certificate
creation, remains `unknown`; only a local validation or token-provider
refusal before sending the CA request can establish a local denial.

| Control endpoint | Additional public fields | Result |
| --- | --- | --- |
| `/v1/authorize` | None | Scoped entitlement |
| `/v1/issue`, `/v1/issue/status` | `csr` | Verified `certificate` |
| `/v1/issue/import` | `csr`, `certificate` | Bounded public-chain reconciliation |
| `/v1/register`, `/v1/registration` | Target `handle`, `certificate` | Registration |
| `/v1/activated`, `/v1/activation-status` | Target `handle`, `certificate`, `activation` | Control generation CAS or its status |
| `/v1/retire`, `/v1/retirement` | Previous `handle`, `certificate` | Durable policy and session evidence |
| `/v1/revoke`, `/v1/revocation` | Previous `handle`, `certificate` | CA retirement or its status |

All endpoints use POST with JSON. CSR and certificate fields are PEM bytes
encoded as JSON base64 strings. `Import` validates the recovered public
chain locally before making a request; the service must accept it only for
an existing exact unknown issuance reservation and must not call `/sign`
again. Recovery credentials have a separate device scope and may access
only authorization, issuance and import for `enroll` or `recover`.
Retire, revoke and their status requests authenticate with the current
target signer. The previous handle and public chain only select the artifact
being withdrawn; an expired previous signer cannot authorize control requests.

The application endpoints are `/v1/activate` and `/v1/activation`. The client
checks the acknowledgment's application ID, operation, digest, device,
generation, certificate fingerprint and fresh external probe before sending
it to the control service. Status checks read the service's existing
activation record; they do not implicitly advance the control generation.

`mqttprobe` uses Eclipse Paho Go `v0.23.0`, MQTT 5, verified mutual TLS and
the supplied target signer. It uses a fresh clean session, QoS 1, a fresh
nonce and exact topics `kd/DEVICE/gGEN/request` and `kd/DEVICE/gGEN/response`.
It disables retained requests and retained-message delivery at subscribe,
preserves the retain bit for rejection, and rejects mismatched or stale
responses. `OpenTLS` supports an independently running lab responder with
its own client-auth certificate; no device slot is invented for that service.
[`Paho client` source](https://github.com/eclipse/paho.golang/blob/v0.23.0/paho/client.go).

The broker retirement response must establish a durable policy and old
session termination. For a still-valid previous certificate, the client
separately connects with the old signer and requires an explicit MQTT
SUBACK or PUBACK `0x87` denial. That observation sets `applicationAccessDenied`
and `tlsObservation: accepted`.

For an expired previous certificate, `ObserveDenial` performs a separate
negative TLS 1.3 diagnostic. It still validates the configured server roots
and hostname and requires a completed, authenticated server handshake before
reading a protected peer certificate alert (42, 45 or 46). It sends no MQTT
application request and cannot authorize use of the old key. Only that alert
sets `tlsObservation: denied`. Local expiry checks, timeouts, untrusted servers,
TLS 1.2, missing alerts and ordinary errors cannot replace the evidence.
Go 1.27.2 uses a private `crypto/tls.alert` numeric error for TCP. The observer
accepts only the exact package, type and numeric kind under a typed remote
`net.OpError`; changed representations return `unknown`. It uses no unsafe
access or text matching.

The controller must still re-observe the target application after broker
restart before destroying the previous key.

HTTPS requests and responses are limited to 256 KiB, public chains to 64 KiB,
CSRs to 16 KiB, MQTT frames to 16 KiB and application payloads to 4 KiB.
JSON responses reject duplicate keys, extra documents, unknown fields and
excessive nesting. MQTT framing is capped before the maintained client's
decoder allocates a packet body. Adapters require configured roots, TLS 1.2
or newer and bounded deadlines; HTTPS requests never follow redirects or
use environment proxy settings.

## Explicit V2 composition

`profilehttp` supplies the internal generated-data HTTP composition, keeping
entitlement, authority, platform, transport, application, clock and withdrawal
interfaces separate. The same types are importable through `sdk/device`.
It consumes an immutable public snapshot and verifies
role roots/SAN/EKU/pins, issuer constraints, full intervals and bound evidence.
Its selected server/control/template artifacts are pinned in each plan.
The [profile reference](../docs/reference/credential-profiles.md) lists actual
seed/check commands, no-transfer session policy and whole-service limits.

The actual TLS peer leaf/SPKI selects access. Application switch and activation
CAS require durable authenticated status/revision plus a new post-switch
observation. Withdrawal first persists exact deny and session inventory, then
uses the previous signer for an explicit authenticated denial and reads a fresh
target application observation. Timeout, generic HTTP errors, local expiry or
CA revoke alone stay unknown. Known issuance status validates the immutable
original issuance interval and current validity, instead of treating backdate
as an artifact's current age. Unconfirmed issuance consumes its one-send budget.

These are alpha roles on fresh version-2 stores. The [local Go generator and
public conformance suite](../docs/reference/adapter-tooling.md) compose these
public roles into a working fixture/reference adapter. Persistent backlog
transfer, independent second integration, shared-deployment withdrawal and
hardware evidence remain separate.

## Process execution

`process` and `cmd/kd-adapter` expose those same selected roles over initialized
bounded JSON-RPC NDJSON. See [RFC 0006](../docs/decisions/0006-alpha-sdk-process-adapters.md),
[protocol](../protocol/README.md) and [SDK reference](../docs/reference/alpha-sdk.md).
The fresh process composition pins the wrapper separately from underlying role
artifacts. Exact versions/schema digest, capabilities, permissions and limits
must agree before domain calls. Only request-scoped opaque signing references
cross the boundary; private bytes and host key lifecycle operations do not.

Timeout/cancel/lost response after dispatch remains unknown. A new initialized
session reconciles the original reservation; transport performs no automatic
mutation retry. Lookup/import reflects the real authenticated backend and never
manufactures raw CA lookup/idempotency. Code/kind/outcome/scope mismatches and
unsolicited requests fail closed. Stderr is drained without forwarding raw
bytes. Artifact confinement and scoped brokerage are local checks; selected
process code still has direct syscall authority and is not OS isolation.
