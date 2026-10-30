# Go adapter generator and conformance

`kd-adaptergen` creates a working standalone Go module using only public Known
Device imports. The generated adapter composes the existing `profilehttp` roles
and `SystemClock`, then serves `knowndevice-process/0.1-alpha.1` over stdio.
It is an alpha fixture/reference wrapper for the reviewed local composition.
It does not implement an independent CA, application or connectivity profile.

The module remains `knowndevice.local/knowndevice`. An explicit local `replace`
proves external importability; it is not SDK publication. Go 1.27.2 and the
pinned dependencies in `go.mod`/`go.sum` are required. The
[alpha SDK reference](alpha-sdk.md), [RFC 0005](../decisions/0005-credential-profiles.md)
and [process contract](../../protocol/README.md) still govern behavior.

## Create and test a module

From a local SDK checkout, select an existing absolute directory without symlink
components and a new directory name beneath it:

```sh
make check
mkdir -p .work/adapter-examples
bin/kd-adaptergen --root "$PWD/.work/adapter-examples" --dir sample-adapter --name sample-adapter --module example.invalid/sample-adapter --sdk-replace "$PWD"
cd .work/adapter-examples/sample-adapter
./scripts/ci.sh
```

The `.invalid` module name is a local example, not a hosted repository. The
generator refuses an existing destination, including an empty directory or
symlink. It accepts one directory component, a lowercase adapter name and a
restricted Go module path. Absolute paths, traversal, separators in names,
reserved portable names and code/module injection are refused. Rooted exclusive
creation prevents overwriting a collision. Partial output from a failed or
interrupted generation is retained; select another new directory for a retry.
Identical options produce identical file bytes and requested modes.

The module contains `adapter.go`, process, manifest and conformance commands,
an unbound manifest template, its strict schema, semantic fixture expectations,
tests, dependency pins and executable `scripts/ci.sh`. CI verifies modules,
builds the executable, runs race tests and invokes the public conformance suite.
It needs the selected local SDK path and pinned dependencies. It neither
publishes a module nor starts Docker or accesses a hosted account.

The process command writes protocol messages only to stdout. Its private keys
remain in the host's signer handles. The generated name is module metadata;
it does not add a composition, role ID, profile or trust rule to the SDK.
Only the existing `local-http-process-lab/1` with `local-http-lab-ROLE` adapters
is supported. No Python or TypeScript generator is exposed.

## Exact manifest

`adapter-template.json` is explicitly unbound. It lists the implemented versions,
schema digest, methods, semantic capabilities, both reviewed profiles, fixed
limits and the rule for deriving permissions. It contains no executable pin or
invented network origins. The canonical
[manifest schema](../../sdk/adaptergen/adapter.schema.json) covers both template
and concrete manifest; `sdk/adaptergen.ManifestSchema` exports the same bytes.

After building and pinning an executable in a separately generated process
snapshot, emit its concrete manifest from the generated module:

```sh
go run ./cmd/manifest --snapshot /absolute/fresh/public-snapshot.json --adapter /absolute/pinned/adapter
```

The command validates the canonical public snapshot and exact executable digest
without contacting services. The manifest binds profile, snapshot, composition,
artifact and schema; permissions contain the exact normalized selected control,
application, issuance and transport HTTPS origins. Read/write filesystem lists
are empty, and signer brokerage is explicit. Initialize independently negotiates
these same values. Declarations grant no authority and impose no OS sandbox.

`sdk/adaptergen.Describe` produces the template; `Bind` requires a validated
process snapshot and matching digest. A caller of `Bind` must separately verify
the selected executable bytes, as the generated manifest command does.

## Public conformance

`sdk/conformance.Run(context, Factory)` runs the same cases for both reviewed
profiles. `Factory.Open` must create a fresh isolated identity/backend for each
request. Its `Harness` supplies public SDK adapters, original CSR and signer
vectors, explicit fault controls, observed backend counters and adapter-session
restart. Missing hooks or unsupported setup fail the case. `Cases()` lists the
exact case names used by generated fixture expectations. Reports use fixed safe
reasons and return `ErrNonconformant` if any case fails.

The suite checks success, lost/late issuance responses, exact duplicate
issuance, adapter restart, cancellation before dispatch and after effect, scope,
stale generation, wrong credential/trust profile, unavailable lookup, application
activation and effective retirement. It requires explicit denied, conflict,
unsupported or unknown outcomes as appropriate, with observed effect counts.
It checks the original CSR/SPKI/leaf binding and complete Application/Withdrawal
evidence, including revision, new observation, denial and target ordering.
Candidate verification and a nil adapter error cannot establish activation.

Named Application/Withdrawal faults deliver distinct authenticated malformed
proofs to the tested adapter. The suite requires observed delivery of the named
fault and explicit refusal without prohibited effects. These adversarial test
services deliberately return inconsistent evidence; a generic refusal before
the proof arrives cannot satisfy that check. Positive entitlement must succeed
for the current peer/scope before issuance, without issuance or activation effects.

The public `sdk/conformance/fixture` factory starts generated local TLS HTTP
listeners and signs real fixture X.509 certificates. The same cases run through
the built-in connector and the generated process connector. The backend effect
ledger lives in memory. Restart replaces the adapter/process session over that
same ledger; it does not restart a durable service. Controlled faults, counters
and fixture status are test inputs. Reports use `scope: in-memory-model`.

To rerun the generated command explicitly after its CI build:

```sh
go run ./cmd/conformance --adapter "$PWD/.cache/adapter"
```

A separate harness may instrument real services through the same public
interface. `service-harness` identifies supplied observations, not an independent
certification. The harness author is responsible for authenticated observations,
actual backend counters and accurate declared capability gaps. The suite
imports neither `internal` packages nor local planning/client files.

## Unknown effects and actual services

The selected control service owns durable reservations and authenticated
status/import. Raw step-ca has no invented operation lookup or issuance
idempotency. The generated wrapper performs no automatic mutation retry.
Timeout, cancellation after dispatch, a lost/late reply or session loss leaves
attempted effects unknown. Cancellation stops work and grants, without undoing
effects, erasing durable intent or releasing a generation. Restart uses the
original plan, CSR, SPKI and reservation; unknown issuance never permits another
`/sign`. An unavailable lookup remains explicitly unsupported or unknown.

For actual step-ca/application/controller evidence, use a new
[process lab](alpha-sdk.md#fresh-process-composition), selecting the generated
executable as `--process-artifact`. Build it for the named Linux architecture
as `kd-adapter-linux-arm64` or `kd-adapter-linux-amd64` before seeding. Keep the
copied pinned artifacts immutable while mounted. The CLI selects `kd-adapter`
beside its executable; the lab mounts the selected generated binary there.
Use fresh directories, projects and generated identities for every new run.
Preserve failed attempts and unknown reservations; never resume them as fresh labs.

Real service matrices remain separate from fixture conformance. Durable
Application status, activation revision and a new independent post-switch
actual-peer observation still precede activation CAS. Exact authenticated leaf
and SPKI determine generation. The whole conservative time interval must fit
validity, deadlines and minimum remaining lifetime, including after restart.
Effective withdrawal requires durable deny, session evidence, explicit old
denial and fresh target use before CA revoke or previous-key destruction.
CA revoke, expiry, TLS alerts, socket closure and timeout alone are insufficient.

Tooling establishes no independent KD-029 author/integration, selective KD-030
withdrawal, outbound/NAT/queued observations, backlog transfer, hardware,
OS isolation, stable SDK freeze or release 0.1/0.2 acceptance.
