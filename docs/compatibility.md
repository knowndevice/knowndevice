# Compatibility

The reference implementation is `0.0.0-dev`, without a supported device release
or stable SDK. Alpha changes require matching decisions, code, schemas,
examples and tests.

[RFC 0005](decisions/0005-credential-profiles.md) defines the implemented opt-in profile-aware
v1alpha2 on fresh version-2 device/server stores. It preserves the legacy
v1alpha1 path and digest rules. Opening existing state does not authorize
migration, profile change, cloning or downgrade. See the
[profile reference](reference/credential-profiles.md) for the named local scope.

| Surface | Delivered development contract | Future 1.0 promise |
| --- | --- | --- |
| CLI | Cobra, JSON reports, generated command reference | Versioned JSON; human text can change |
| Configuration / plan / receipt | Explicit knowndevice/v1alpha1 or v1alpha2; JSON Schema 2020-12 | Explicit compatibility and migrations |
| Journal | Explicit SQLite user_version 1 or fresh 2, WAL/FULL, lock, fence/revision | Tested migration and rollback eligibility |
| Slots | Explicit version 1 or fresh 2, A/B, pointer, tombstones | Versioned lifecycle and upgrade rules |
| Alpha Go SDK / built-in adapters | Public sdk/device and sdk/credentialprofile, same strict types/policy; `github.com/knowndevice/knowndevice` without a published version | Freeze after independent external use/conformance |
| Process adapters | knowndevice-process/0.1-alpha.1, exact embedded schema/error versions, pinned artifact and capabilities | Reviewed version negotiation guarantees |
| Adapter tooling | Go generator and public sdk/conformance for the selected fixture/reference backend; explicit local SDK replace | Freeze only after independent external implementation and interoperability |
| Hardware | Software keys only | Named model/firmware and measured protection |

Unknown/newer storage versions fail before protected transitions. There is no
automatic migration. A WAL without its shared-memory sidecar is refused because
read-only version inspection cannot safely reconstruct it. Keep journal,
sidecars, slots, pointer and tombstones together. No backup/restore tool or
clone resistance is delivered.

Go 1.27.3 builds Linux amd64/arm64. Runtime evidence must state architecture and
emulation; cross-compilation is not hardware evidence. Negative expired-client
TLS observation depends on the tested alert shape; unknown shapes fail closed.

The module path is `github.com/knowndevice/knowndevice`; no module version is
published yet. Stable contracts, interrupted upgrades, alpha migrations and
external conformance remain release work. Rollback must never revive retired,
revoked, expired or compromised credentials.

V2 requires profile ID/version/policy digest, deployment namespace, explicit
composition/capabilities, separate role trust, canonical public snapshots and
plan digest encoding version 2. Missing or unknown fields/versions are refused.
The role evidence is transport-neutral. The alpha SDK and process transport
use the same typed roles. The [local generator and public conformance suite](reference/adapter-tooling.md)
operate on those contracts; SDK publication and independent external acceptance
remain separate work. The named HTTP composition has an
explicit new-connection/no-state-transfer policy and whole-service lab withdrawal;
it establishes no MQTT backlog or shared-deployment continuity guarantee.
Its authenticated callback also requires a reachable Application endpoint;
outbound-only/NAT and queued-observer topologies are unsupported.

Version-1 APIs/stores are selected only for explicit v1alpha1 inputs. Version-2
open/read paths refuse schema/slot 1 before mutation, and legacy open paths
refuse 2. No missing identity marker, alternate state directory or reused device
identity is an upgrade workaround. Fresh V2 init checks current server scope and
reservation counters. New profile/trust content cannot rewrite an unfinished
plan; a root rollover, profile change or state migration needs separate review.
Previous public CSR/chain, target bindings and role evidence survive restart;
private keys stay behind handles. V2 public receipts map the historical
broker-retire phases to withdrawal-intent/withdrawn; v1 checkpoint names persist.
An exact completed V2 plan returns its validated stored history with health
unknown and no writes or effects. Changed or expired current trust cannot
rewrite that outcome; a history report grants no authentication or activation.

The fresh `local-http-lab/2` composition requires an explicit
`authorityLifetimeSeconds` (300–1200) in its immutable snapshot. Composition 1
retains its original encoding and fixed 1200-second request. The shared profile,
strict certificate validation, 600-second plan bound and activation margin
are unchanged. A binary that supports only composition 1 refuses 2; this is
not a state migration. The observer-only bounded session inventory is an
instantaneous lab read and cannot substitute for withdrawal or live health.

KD-014 adds local Go generation and public conformance without changing storage,
process versions/schema bytes, profile policy or existing composition IDs. Native
HTTP success now passes the same complete activation/retirement validators as the
process host before returning to the controller. Incomplete or stale proof is
refused earlier; controller time checks, authority and durable ordering remain.

The system audit tightens existing interval and proof rules without changing
schema bytes, profile policy digests, process versions, storage or transition
ordering. One allowed X.509 path must cover the entire assessed interval;
separate endpoint paths cannot conceal a trust gap. The core also rechecks
fresh Application proof and the retained activation revision before later
effects, and stores each consumed fresh observation before the dependent effect.
New observations advance their timestamp and use different nonce/request IDs
from persisted activation and retirement proof; a recent replay is refused.
Native HTTP refuses contradictory role/status evidence, including
unproven absence. Lab registry paths preserve literal URI characters, and new
lab checks distinguish sign dispatch attempts from received responses.
Missing lab counter files or fields block dispatch; only fresh seed creates
their initial values. Retained labs are not upgraded or resumed by these checks.

Diagnostic corrections retain the existing storage, profile and process versions
and schema bytes. A failed V1 checkpoint write returns the last confirmed phase;
the receipt can report the current attempt's error while its durable outcome
remains unchanged if the error-result write also fails. Recovery-scope checks
require a bound authenticated denial or the tested protected TLS 1.3 recovery
issuer refusal after server verification. Network, timeout and trust uncertainty
cannot earn a denial PASS.

The V2 CLI active probe requires the original plan for that exact credential.
During a pending rotation the previous active plan is no longer retained, so
the CLI reports unavailability with exit 3 and unknown device health before
opening an adapter. Both HTTP and process adapters still require the exact
target plan. This corrects the diagnostic and documentation; active probing
during that window remains unsupported. Support beyond the existing plan and
deadline contract requires a separate RFC.
