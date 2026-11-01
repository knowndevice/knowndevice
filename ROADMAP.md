# Roadmap

Updated 1 November 2026. Dates below are planning estimates, not release
commitments. A milestone ships when its acceptance criteria pass.

The estimate assumes work starts on 12 October, roughly two experienced
engineers' capacity, access to Linux amd64 and arm64 hardware, a pilot
operator, and PKI/security review. More parallel coding cannot replace
power-cycle tests, operator feedback, or a sustained pilot. With one
maintainer, reserve 8–12 weeks for the first useful preview and reassess
the later dates after that release. Linux hardware, a pilot operator and
PKI/security review are not available yet, so the 0.2.0 and later dates depend
on them.

| Milestone | Estimate | Calendar window | Acceptance |
| --- | --- | --- | --- |
| Foundation | Done | 11 October 2026 | Research, rules, bootstrap model, local checks, issue backlog |
| 0.1.0: useful reference lab | 4–6 weeks | 9–23 November 2026 | Real Linux rotation and recovery in the local PKI/MQTT stack; journal recovery; negative cases; release artifacts; Cloudflare website |
| 0.2.0: pilot alpha | 12–16 weeks from start | 4 January–1 February 2027 | Distinct integration profile, alpha adapter tooling/conformance, scoped session withdrawal, offline and hardware evidence, read-only MCP |
| 0.9.0: release candidate | 20–28 weeks from start | 1 March–26 April 2027 | Contract freeze proposed, migration rehearsal, two pilot reports, security findings addressed |
| 1.0.0: stable Linux framework | 24–36 weeks from start | 29 March–21 June 2027 | All 1.0 gates below; stable schemas and documented compatibility guarantees |

The original design's 12–16 week alpha remains the estimate for a pilot
alpha. The earlier 0.1 preview deliberately covers one reference stack.
It will not claim all adapter, fleet, or hardware features from that design.

## 0.1: a real, narrow end-to-end path

1. Strict configuration, plan digest, bounded device-scoped authorization,
   durable operation identifiers, and a single local writer.
2. Two software credential slots, file and directory synchronization,
   a SQLite journal, and reconciliation after process termination.
3. `step-ca` issuance through `/sign` and Mosquitto registration, application
   confirmation, activation, and effective retirement verification.
4. Separate recovery authorization checked against a current fixture
   registry. Deny revoked devices, missing recovery, and untrusted time.
5. A no-account quickstart that runs in under 30 minutes on a clean machine.
6. Tests for every checkpoint, lost issuance response, disk-full/read-only
   storage, concurrent writers, wrong-generation probe, and rejected MQTT ACL,
   all run in CI on native amd64 and arm64 runners.
7. Linux amd64/arm64 binaries, checksums, signed provenance, SBOM, published
   alpha schemas, private vulnerability reporting, and release notes.
8. A static Cloudflare website with the same status, tested quickstart,
   integration matrix, limitations, and documentation as the release.

A restart demo must use an actual killed process and persistent state.
The current in-memory fixtures do not meet that criterion. Hardware power
loss remains a separate pilot-alpha gate.

The first unreleased implementation now supplies the Linux reference path,
SQLite/software slots, real PKI/MQTT adapters and a process-kill failure driver.
See [quickstart](docs/quickstart.md) for the delivered profile. This does not
complete 0.1. Remaining release gates:

- Passing Quality runs (`make check`, `make demo` and the lab matrix) on
  native amd64 and arm64 runners.
- A timed quickstart by a contributor on a clean machine.
- Filesystem-fault suites in CI.
- Private vulnerability reporting verified.
- Rulesets for `main` and version tags.
- A hosted release run with signed provenance and SBOM.
- Release notes.
- The website.
- Separately authorized publication.

`/sign` replaces the proposed `/rekey` for this profile because each generation
needs a distinct subject; see
[RFC 0004](docs/decisions/0004-first-device-path.md).

## 0.2: prove that it extends beyond the reference lab

The reference path is one Linux/X.509/MQTT profile. Internal interfaces and
an additional CA using the same conventions do not establish portability
across IoT deployments. Complete the following before the stable-contract
proposal; the 0.2 SDK remains alpha.

1. Approve an RFC for credential profiles and adapter composition. Separate
   CSR construction and certificate identity validation from the reference
   generation-specific CN/DNS convention. Support a reviewed profile with a
   stable device subject and explicit server-side generation/key binding.
   Preserve device, operation, plan digest, public-key and generation fencing.
   Define entitlement, authority, platform, transport, application, clock and
   withdrawal responsibilities without making MQTT observations a universal
   transport contract.
   [RFC 0005](docs/decisions/0005-credential-profiles.md) records the reviewed
   KD-027 design; [KD-028 internal implementation](docs/reference/credential-profiles.md)
   adds explicit fresh V2 profiles/trust without satisfying the independent
   second-profile or shared-deployment gates.
2. Implement role-specific trust configuration for control, application,
   certificate issuance/recovery and MQTT. Bind profile versions, expected
   identities and trust material to the configuration/plan digest. Reject
   wrong-role credentials and changed trust; keep keys behind signer handles.
   The existing reference profile must continue to pass its failure matrix.
3. Publish usable alpha Go contracts, the negotiated process protocol,
   generator and conformance suite. Built-in and external adapters use the
   same rules for capability gaps, uncertain effects, deadlines, cancellation,
   stale generations, restart and redaction. Process adapters and read-only
   MCP remain distinct from device network protocols.
   [The local alpha SDK/process implementation](docs/reference/alpha-sdk.md)
   exposes the reviewed strict contracts and a separately pinned fresh stdio
   composition. Local replace proves importability; public SDK publication
   and independent profile acceptance remain. The [local Go generator and
   public conformance suite](docs/reference/adapter-tooling.md) create a working
   selected fixture/reference adapter through public imports and the same
   process protocol. Local SDK replace and controlled fixtures establish no
   publication, independent author or real second integration acceptance.
4. Have an author outside the initial implementation deliver a second real
   profile using only public code and docs. It must exercise stable certificate
   identity, separate trust domains and an actual application without a private
   core fork. Test telemetry, downlink and offline backlog where the selected
   application provides them; report the application's exact acceptance scope.
   Declare ClientID/session policy and whether candidate and current sessions
   can coexist. Preserve fresh, non-retained verification independently of
   ordinary application messages.
5. Provide scoped durable access withdrawal and old-session termination for
   a shared deployment. A generation change must not require restarting every
   broker client. Observe old reconnect denial and the current application;
   CA revoke and network failure cannot substitute for this evidence. Exercise
   an observation route suitable for the selected topology, including NAT and
   devices without inbound reachability, without accepting a self-issued ACK.
6. Add a systemd controller and bounded renewal scheduling: expiry margin,
   backoff/jitter, traffic/attempt/write budgets, reconnect and offline return.
   Document and test intervention when an unfinished plan expires or a remote
   effect cannot be reconciled. Reauthorization/cancellation, if implemented,
   needs a separately reviewed protocol; never edit a digest, delete intent or
   reuse an unknown key to continue. Measure application interruption separately
   from preservation of the authorized generation.
7. Run real power-cut and storage-failure tests on named hardware, with pilot
   runbooks and scoped receipts. Add read-only MCP diagnostics. Retain exact
   hardware, filesystem, service/profile versions, failures and operator actions;
   process-kill and emulated runs do not replace these checks.

Choose the second profile before revising estimates for its implementation.
These requirements refine the pilot-alpha scope; they do not add gates to
the narrow 0.1 reference preview or promise universal IoT support.

## IoT integration choices

Support requires a named version/profile, declared trust and failure semantics,
and real interoperability evidence. Using MQTT, HTTPS or JSON Schema alone does
not establish an IoT application model or device-management implementation.

| Integration | Planned scope |
| --- | --- |
| MQTT | MQTT 5 over mTLS is delivered in the reference profile. Other versions, WebSocket transport and session policies require a selected deployment and tests. [OASIS MQTT 5](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) |
| EST | Required against a named server for 1.0. The step-ca and reference control APIs do not implement EST. [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030.html) |
| CoAP / LwM2M | Demand-driven future profiles for constrained networks/device management; no implementation or release commitment. [CoAP](https://www.rfc-editor.org/rfc/rfc7252.html), [OMA LwM2M](https://www.openmobilealliance.org/RELEASE/LightweightM2M/V1_2_2-20240613-A/HTML-Version/OMA-TS-LightweightM2M_Core-V1_2_2-20240613-A.html) |
| Sparkplug / WoT / OPC UA | Candidates when a pilot needs industrial MQTT semantics, interface descriptions or industrial application/certificate management. Select an existing stack and an RFC-defined integration scope; none is currently supported. [Sparkplug](https://sparkplug.eclipse.org/specification/version/3.0/), [WoT](https://www.w3.org/TR/wot-thing-description11/), [OPC UA Part 12](https://reference.opcfoundation.org/specs/OPC-10000-12/7.10) |
| BRSKI / FDO | After 1.0, subject to demand and separate trust/ownership RFCs. The reference recovery signer does not implement manufacturing bootstrap or ownership transfer. [BRSKI](https://www.rfc-editor.org/rfc/rfc8995.html), [FDO](https://fidoalliance.org/fido-device-onboarding/) |

Known Device owns credential continuity and its integration boundaries.
Device management, software updates, radios and application data models stay
with the selected product stack unless a separately scoped integration is
approved. This roadmap does not require implementing every listed standard.

## 1.0 release gates

- Stable configuration, receipt, CLI JSON, storage migration, and adapter
  contracts have an approved RFC and compatibility tests, informed by the
  independent second profile and its conformance results.
- `step-ca`, EST against a named server, Mosquitto, and one pilot-selected
  platform adapter pass their documented conformance profiles. Each declares
  credential identity, trust domains, application/session semantics, uncertain
  effects and effective withdrawal; reference CN/topics are not universal rules.
- One named Linux TPM 2.0 configuration is tested. Its protection level and
  attestation limitations are explicit; software keys remain supported.
- At least two independent deployments have used the same core for 30 days,
  including rotation, offline return, and operational rollback/recovery drills.
  Their reports measure actual application behavior and interruptions, not only
  fresh probe success, and cover scoped retirement without whole-broker restarts.
- No unresolved critical/high security findings or reproducible violations
  of the continuity invariants remain. External PKI/security review is recorded.
- Native amd64 and arm64 tests, power-cycle evidence, fuzzing, race checks,
  dependency scans, upgrade/restart tests, and redaction tests pass.
- A backup/restore procedure preserves journal/key-store consistency and
  refuses unintended identity cloning.
- A fresh contributor completes the quickstart and builds an adapter.
- Supported versions, security maintenance, artifact verification, and
  incident response responsibilities are published.

## After 1.0

Fleet coordination, PostgreSQL, web UI, commercial hosting, MCU/RTOS,
PKCS#11, FDO/BRSKI, OTA/trust-anchor rollover, ownership transfer, and
additional clouds require demand and separate RFCs. They are not blockers
for a useful Linux continuity framework.

Tasks, dependencies and acceptance criteria are tracked in
[GitHub Issues](https://github.com/knowndevice/knowndevice/issues) under the
0.1.0, 0.2.0, 0.9.0 and 1.0.0
[milestones](https://github.com/knowndevice/knowndevice/milestones). Each issue
names the roadmap ID (KD-0xx) that this roadmap and the design records cite.
