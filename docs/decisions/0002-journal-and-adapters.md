# ADR 0002: Journaled transitions with explicit uncertainty

Status: accepted design; the first internal reference implementation is specified
in [RFC 0004](0004-first-device-path.md). The [alpha SDK](../reference/alpha-sdk.md)
and [local adapter tooling](../reference/adapter-tooling.md) now implement the
public Go/process and conformance path without publication or stable guarantees.

Choose a SQLite operation journal, separate credential slots, typed Go
adapters, and a negotiated JSON-RPC process adapter contract. Use the same
conformance rules for built-in and external integrations.

A single state JSON file is smaller but would require rebuilding locking,
querying, migrations and transactional journal behavior. An append-only
custom binary format might reduce footprint but creates unnecessary
storage-protocol maintenance. Neither creates a transaction with the CA
or broker.

Persist intent before effects; query uncertain results before retry. Never
claim exactly-once remote operations without vendor support. A remote
capability gap produces an explicit unknown result and operator procedure.
Test SQLite/file synchronization gaps on actual storage before production.
