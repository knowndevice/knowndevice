# Alpha data contracts

The reference profile uses JSON Schema 2020-12 and `knowndevice/v1alpha1`.
These are development contracts, without a stable SDK or migration guarantee.

[RFC 0005](../docs/decisions/0005-credential-profiles.md) defines the implemented explicit
v1alpha2 profile/composition and role-trust bindings for KD-028. Legacy schemas
and digest encoding stay unchanged. V2 requires fresh version-2 state and
explicit selection; it has no implicit conversion.

| Schema | Produced or consumed by |
| --- | --- |
| [Device configuration](schemas/device-config.schema.json) | All device CLI commands; JSON or a strict YAML subset |
| [Plan](schemas/plan.schema.json) | `plan` and `apply --plan` |
| [Transition receipt](schemas/transition-receipt.schema.json) | `init`, `status`, `apply`, `reconcile` |
| [Simulation report](schemas/simulation-report.schema.json) | `simulate` only |

The [adapter manifest schema](../sdk/adaptergen/adapter.schema.json), also exported
as `sdk/adaptergen.ManifestSchema`, validates the generator's unbound template
and concrete snapshot/artifact manifest. The [template example](examples/adapter-template.json)
lists implemented contracts and how exact permissions will be derived; it has
no executable, endpoint selection or authority. The generated manifest command
verifies a selected executable and canonical snapshot before binding those values.
See [adapter tooling](../docs/reference/adapter-tooling.md).

The host additionally checks endpoint syntax, exact field spelling, input
limits, generation preconditions, digest, deadline, clock and authorization.
Schema validation alone cannot grant permission or establish device health.
The plan digest is SHA-256 of Go's canonical struct JSON with `digest` set to
an empty string. Generate plans with the CLI; editing a plan invalidates it.

The [configuration](examples/device-config.json) and
[blocked receipt](examples/transition-receipt.json) are illustrative public
metadata. Generate unique keys and trust roots with the
[quickstart](../docs/quickstart.md); the configuration example has no credentials.

The explicit V2 contracts are [configuration](schemas/device-config-v1alpha2.schema.json),
[plan](schemas/plan-v1alpha2.schema.json), [receipt](schemas/transition-receipt-v1alpha2.schema.json)
and [internal role evidence](schemas/evidence-v1alpha2.schema.json).
[Configuration](examples/device-config-v1alpha2.json) and
[idle receipt](examples/transition-receipt-v1alpha2.json) and
[authority status evidence](examples/evidence-v1alpha2.json) examples contain public
metadata only; zero/example pins are illustrative and grant no trust.
Example plan and binding digests are placeholders, not executable plans.
[Generate fresh material](../docs/reference/credential-profiles.md) for actual use.
V1 rejects the presence of V2 fields, including empty, zero and null values.

V2 uses digest encoding version 2, fixed-struct JSON with an empty digest field,
canonical role/anchor/pin ordering and exact loaded public DER. Its profile,
composition, trust and snapshot references are part of the plan. Snapshot
content changes at the same path change the digest. The service independently
allows the snapshot; neither a schema nor device-supplied evidence authorizes it.
Internal evidence separates role/action, request/operation, exact subject key,
server revision, fresh observation, application activation and withdrawal.
The evidence schema describes usable public results. Its application definition
requires observation fields as well as durable activation. A status-only
Application envelope uses the generic evidence definition and cannot satisfy
the combined application evidence; incomplete error payloads grant no effect.
Revocation status concerns the exact previous generation, including its original
CSR digest; `not-started` establishes absence only when an authenticated authority
response matches that complete binding. A sent request with an unknown result
does not become another revocation request.
The same types and strict policy are public alpha Go contracts under
`sdk/device` and `sdk/credentialprofile`. The complete
[process schema](schemas/process-v1alpha1.schema.json) and
[RFC 0006](../docs/decisions/0006-alpha-sdk-process-adapters.md) define initialized
JSON-RPC NDJSON role calls, bounded public-only credentials, exact scope/results,
temporary signer grants and versioned safe errors. The
[unknown error example](examples/process-error.json) uses placeholder public
digests and grants no authority. The [local Go generator and public conformance
suite](../docs/reference/adapter-tooling.md) use these same contracts; public SDK
publication remains separate.

The [short-lived V2 example](examples/device-config-v1alpha2-short-lived.json)
selects fresh `local-http-lab/2` with explicit snapshot-bound
`authorityLifetimeSeconds`. Version 1 keeps its fixed 1200-second request and
encoding. The evidence schema also defines the observer-only `sessionInventory`
and its bounded actual-peer connection records. Inventory alone grants no
health, activation or withdrawal authority; it remains an instantaneous lab read.

[The process configuration example](examples/device-config-v1alpha2-process.json)
selects a separate fresh `local-http-process-lab/1` and required wrapper digest.
Native compositions omit and refuse that field. Its illustrative pins do not
identify an executable or authorize a migration. Protocol schemas narrow complete
activation/withdrawal success to activated/live evidence; candidate-verified
cannot satisfy them. Domain error code/kind/outcome/message and exact scope
must agree before the host accepts authoritative not-started on a declared
status/lookup. Contradictory or unbound results remain unknown, without replay.
