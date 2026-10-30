# Changelog

## Unreleased system audit corrections

- Require one allowed certificate path across the complete assessed interval,
  and refuse nil certificates at the public chain-validation boundary.
- Recheck live Application proof and the stored activation revision in the
  controller before pointer changes, withdrawal, revocation and key destruction.
  Persist the new observation before its dependent effect and refuse replay
  after restart, including an observation already used by withdrawal.
- Refuse contradictory native HTTP role/status evidence before interpreting
  completion or authoritative absence.
- Encode literal SQLite registry paths and count lab CA dispatch attempts
  separately from received responses, including attempts with a lost response.

## Unreleased adapter tooling

- Add a Go generator for a working standalone fixture/reference adapter module,
  exact manifest/schema, declared permissions and limits, fixtures and local CI.
  Existing destinations and unsafe paths are refused without overwriting files.
- Add public shared semantic conformance cases for built-in and generated
  process adapters. Controlled TLS fixtures remain distinct from actual service
  effects, independent integrations, SDK publication and hardware evidence.
- Classify strict local HTTP profile/CSR refusals as the same safe ErrDenied
  sentinel used by process adapters, without weakening validation.
- Apply the existing complete process activation/retirement checks to native
  HTTP success as well. Shared negative cases deliver the named malformed proof;
  successful entitlement is checked before valid issuance.

## Unreleased alpha SDK and process contracts

- Expose the reviewed strict Go profile/trust/composition and role contracts
  through public packages, preserving internal compatibility aliases and legacy
  encoding. Local replace proves external importability without publication.
- Add RFC 0006, complete negotiated JSON-RPC NDJSON schemas, safe scoped errors,
  temporary host signer grants and a separately pinned fresh process composition.
  Timeout/cancel/lost responses preserve durable uncertainty and never grant
  blind issuance retry or system isolation.


Versions follow Semantic Versioning. Dates use YYYY-MM-DD.

## Unreleased

- Added the product requirements, research, architecture, roadmap, and
  contribution rules for Known Device.
- Added a development CLI with five in-memory continuity fixtures.
- Added transition-order tests, local quality gates, and prepared
  contributor tooling and GitHub issue definitions.
- Added the unreleased Linux reference controller with strict Cobra commands,
  digest-bound plans, SQLite journaling and two software signer slots.
- Added real step-ca/Mosquitto adapters, an independent application/responder,
  generation-specific withdrawal and separate scoped recovery.
- Added a digest-pinned generated-data lab, killed-process checkpoint tests,
  actual filesystem-fault profiles, unknown issuance import and alpha schemas.
- Added explicit v1alpha2 credential profiles on fresh version-2 stores,
  immutable role trust, exact server/peer key bindings, durable application
  activation evidence and the separate local HTTP profile lab.

No device release has been published. Stable SDK/migrations, release artifacts,
public security channels, hardware protection and power-cut validation remain
outside this development profile.
