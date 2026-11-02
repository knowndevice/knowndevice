# Integration matrix

The delivered profiles use local alpha SDK contracts and the selected reference stack.
It does not establish support for another CA, broker, application or hardware.

| Integration | Version / scope | Status and limits |
| --- | --- | --- |
| Linux file store | ECDSA P-256, PKCS#8, two software slots | Implemented; privileged administrators can copy keys; no hardware erasure claim |
| SQLite | modernc.org/sqlite 1.60.1, schema 1 or fresh 2, WAL/FULL | Implemented; lock/revision/fence; unknown versions refused; no migration tool |
| Smallstep step-ca | 0.30.2, digest-pinned | Actual /sign and passive revoke; no raw issuance lookup; unknown needs evidence or intervention |
| Eclipse Mosquitto | 2.0.22, digest-pinned | mTLS, generational ACL, synced replacement and whole-broker restart |
| MQTT / responder | eclipse/paho.golang 0.23.0, MQTT 5 | External bound nonce; explicit ACL denial for a valid old certificate |
| Reference application | Independent worker | Old session retained until candidate verification and durable activation; control independently observes it |
| Recovery | Unique scoped mTLS signer, current fixture registry | Separate from operational credentials; revoked/retired entitlement denies recovery |
| Reviewed V2 credential/trust profiles | Internal generated HTTP lab, exact TLS peer enforcement | Opt-in fresh version-2 state; distinct Application status/observation, no backlog transfer or shared-deployment claim |
| systemd / renewal scheduler | 0.2 | Planned |
| JSON-RPC process adapter | knowndevice-process/0.1-alpha.1 | Local initialized stdio implementation, exact negotiation and scoped signing; no OS isolation |
| Go adapter tooling | Local alpha generator and public conformance | Working fixture/reference wrapper through public imports; local replace, controlled fixtures and real service evidence have separate scopes |
| Read-only MCP | 0.2 | Planned |
| EST / pilot platform | 1.0 | Selection and real tests remain |
| TPM 2.0 | 1.0 | Named hardware selection remains |
| PKCS#11, FDO/BRSKI, OTA, MCU, fleet coordinator | Later RFCs | Unavailable |

Image digests and mounts are in [Compose](../lab/compose.yaml). Requests, status,
authorization and limits are in [adapters](../adapters/README.md) and
[RFC 0004](decisions/0004-first-device-path.md).
The [alpha SDK](reference/alpha-sdk.md) and [adapter tooling](reference/adapter-tooling.md)
describe the delivered local extension path. Public SDK publication, an independent
KD-029 author/integration and selective KD-030 withdrawal remain separate.

Expired previous certificates require verified server TLS and a protected
remote certificate alert during negative access observation. This uses the
pinned Go/TLS profile; an unfamiliar alert/version, timeout or network failure
stays unknown. Local expiry is insufficient. CA revoke, broker denial and
live-session termination are separate observations.
