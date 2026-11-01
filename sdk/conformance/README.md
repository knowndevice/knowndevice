# Public adapter conformance

`sdk/conformance` runs the same 19 semantic cases for each reviewed credential
profile through public SDK roles. An external Go module can import the runner
and `sdk/conformance/fixture` using
`github.com/knowndevice/knowndevice` with a local `replace` until a version
is published. This proves local importability, without SDK publication or an
independent adapter author.

```go
report, err := conformance.Run(ctx, fixture.Factory{
    Connect: fixture.Builtin,
})
if err != nil {
    // Retain report.Results; each failed case has a fixed, safe reason.
}
```

The generated module's executable CI example runs this suite for its native
adapter and its built process executable. A process connector supplies
`fixture.Factory.ProcessArtifactDigest` and initializes a new pinned host
session for each snapshot. The fixture uses the existing reviewed compositions;
it does not widen protocol schemas, permissions, capabilities or limits.

`Factory.Open` creates a separate backend and identity for every case. `Harness`
contains the immutable snapshot, exact rotation plan, previous generation,
unissued target CSR/handle/signer, two deliberately invalid credentials, selected
SDK roles and explicit fault, observation, release, restart and cleanup hooks.
The suite accepts the target chain only after a valid issuance or exact lookup
result agrees with its original CSR, SPKI, signer, profile and trust policy.
Typed nil factories and incomplete harnesses fail. Missing hooks are failures;
they are never counted as passing coverage.

Other authors can implement `Factory` to instrument their backend. Hooks must
observe actual effects and authenticated peer/registry bindings. They are
trusted test instrumentation, and the runner cannot authenticate an author's
counters. Such a provider uses the scope `service-harness` and must separately
record the service version, persistence, fault mechanism and evidence. Interface
presence does not establish lookup, idempotency or reconciliation support.

| Cases | Assertions |
| --- | --- |
| Success and duplicate | Positive entitlement for the original active peer/scope without effects, one issuance attempt, bound chain, exact existing result, no extra effects |
| Lost/late response and cancellation after effect | Explicit unknown, retained reservation, ignored late result, fresh session and exact lookup without another issue call |
| Adapter restart | New adapter session over the same backend; lookup retains the original result |
| Cancellation before dispatch | Explicit cancellation/unknown with zero backend calls or effects |
| Scope, stale generation and wrong credential/trust profile | Explicit refusal and no new effects; an old valid peer cannot issue after activation changes generation |
| Unavailable lookup | Unsupported/unknown, never invented absence, success or another issuance attempt |
| Application | Candidate verification grants no activation; complete status, nonzero matching revision, bound actual peer and a new challenge observation are required |
| Effective retirement | Explicit old access denial and later target use with a different nonce; policy/session proof precedes passive CA revocation |
| Incomplete activation/withdrawal | Distinct authenticated malformed proofs must reach the tested adapter; explicit refusal/unknown and preserved generations are required on mutation and on a new session's status read |

The runner verifies full typed Application and Withdrawal evidence independently
of an adapter's nil error. It checks role/source pins, plan/artifact bindings,
revision, scope, live connection/session/instance fields, observation age,
challenge deadline, distinct nonces and target observation ordering. Certificate
validation covers the complete interval returned by the selected adapter clock,
including its assessment age, drift, uncertainty and minimum remaining lifetime.
Each process clock response already includes the host's measured round trip.
Reports contain only case/profile/status and fixed reasons, never adapter error
text, private paths, keys, signer callbacks or response bodies.

The named proof fault cases deliver different typed responses over the actual
fixture mTLS channel. Application faults contain `candidate-verified`, a zero
activation revision, or a complete observation more than five seconds old.
Withdrawal faults omit an explicit denied-access result, set session termination
false, or bind the stale target generation. The source instrumentation records
the specific `InjectedProofFault` and `InjectedProofResponses`; a refusal before
that proof is produced cannot pass the named case. These fields are trusted
harness metadata, not proof that a remote consumer authenticated a response.

For these adversarial vectors the trusted fixture endpoints deliberately supply
inconsistent or false proof content, including a synthetic old-access denial.
They preserve the active generation and change no modeled selection, CAS,
withdrawal policy, session-termination or fresh-observation counter. The same
malformed proof persists on status/read after adapter restart. This fault
injector exercises the adapter's validation boundary; its authenticated envelope
does not establish actual effective withdrawal or an honest durable service.

The supplied fixture creates fresh random device/deployment IDs, separate
role roots, loopback mTLS listeners, P-256 host signers and actual X.509 signatures
at issuance. Access checks map the authenticated peer's exact leaf/SPKI to its
prepared public binding; CN and request payloads do not select generation.
Application observation, selection and withdrawal are explicit model assertions
over that in-memory registry. The fixture's policy/revision fields model the
reviewed evidence shape; they do not prove backend durability or real session
termination. Its reported scope is always `in-memory-model`.

The restart case replaces an adapter session while this one fixture backend
continues running. It does not restart or recover a durable service. No step-ca,
Mosquitto, filesystem journal, controller/key-store destruction, hardware,
power-loss or OS isolation evidence is produced by these fixtures. Separate
service matrices and the independent KD-029 integration remain required.

Run the public package tests from the repository:

```sh
go test -race -count=1 ./sdk/conformance/...
```

Tests also alter successful adapter results and backend errors to verify that
incomplete/replayed proofs, missing effects, arbitrary errors and stale or
excessive clock intervals cannot pass the runner. Separate omission mutants
consume each actual authenticated malformed fixture response, restore only its
named constraint to confirm that the unchanged strict validator would otherwise
accept it, then return the original invalid result as success. The suite must
fail each mutant. An always-denying entitlement mutant must also fail positive
authorization. These checks are separate from post-return proof tampering.
