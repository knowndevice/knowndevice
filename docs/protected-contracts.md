# Protected contracts

There is no stable 1.0 contract. Changes to these alpha surfaces require code,
tests, schemas, examples and compatibility notes together:

- Brand Known Device, CLI knowndevice, explicit namespaces knowndevice/v1alpha1 and v1alpha2.
- CamelCase JSON; logical identity, credential generation, execution outcome,
  checkpoint and device health are distinct.
- `in-memory-model` for fixtures and `reference-device-path` for real transitions.
- Bounded plans with immutable operation ID, expected/target generation, mode,
  slot, configuration digest, deadline and digest.
- Durable intent before effects; stage → register → verify → activate → commit
  → broker withdrawal → CA revoke → key destruction.
- Failed probe/activation preserves the previous authorized generation.
- Signer/handle APIs; no private keys or CA tokens in journal, receipts or logs.
- Scope-bound adapter requests; unknown remote outcomes require reconciliation.
- Independent application observation; a client receipt grants no authority.
- SQLite schema 1, revision/fence/lock; slot binding/manifest version 1, pointer
  and retirement tombstones; unknown versions are refused.

New trust mechanisms, storage migration and stable-contract changes require an
RFC. [RFC 0004](decisions/0004-first-device-path.md) defines the first internal
profile. The local module path must change before public SDK publication.

[RFC 0005](decisions/0005-credential-profiles.md) defines the implemented opt-in internal
profile/trust/composition contract. It preserves v1alpha1 behavior/digests and
requires fresh version-2 state, immutable public trust snapshots, exact peer
credential binding, durable Application activation/revision plus new observation,
conservative time intervals and verified withdrawal before destruction. Stable
CN never supplies generation authority; implicit migration remains refused.

[RFC 0006](decisions/0006-alpha-sdk-process-adapters.md) exposes the same strict
types as public alpha Go contracts, with internal aliases, and defines the
negotiated stdio extension. Exact artifact/schema/capability/profile/scope/limit
agreement precedes effects. Temporary signer grants contain no key bytes or
key lifecycle authority. Cancellation/session loss cannot undo remote effects,
delete durable intent or authorize issuance replay. Known absence is accepted
only from a matching authoritative status; contradictory/unbound results are
unknown. The process composition uses fresh state and grants no OS isolation.
