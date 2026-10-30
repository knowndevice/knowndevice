# Reference quickstart

This development lab uses real `step-ca` and Mosquitto services with unique
generated demo credentials. It exposes no host ports, needs no hosted login
and does not configure production services.

This guide retains the v1alpha1 reference path. The
[explicit credential profile guide](reference/credential-profiles.md) creates a
separate fresh v1alpha2 lab; existing reference identities/stores are not converted.

Install Go 1.27.2, Python 3.11+, Bash, Make and Docker with Compose running Linux
containers. From the repository root:

```sh
make check
bin/kd-reference seed --dir .work/reference
```

Seed refuses an existing directory. It creates unique CA, service and recovery
keys in private directories. Keep them local. Root/service credentials expire
after 48 hours; operational certificates normally last one hour. Start a fresh
disposable lab when its trust expires.

Compose defaults to `arm64`. On an amd64 Docker host:

```sh
export KNOWNDEVICE_LAB_ARCH=amd64
```

Keep each test run's binaries fixed while services or checks are running.
For a new generated lab, copy the built Linux artifacts before startup:

```sh
mkdir -p .work/reference/artifacts
cp bin/kd-reference-linux-* bin/knowndevice-linux-* .work/reference/artifacts/
export KNOWNDEVICE_LAB_BIN_DIR="$PWD/.work/reference/artifacts"
```

Compose uses `bin/` by default. Rebuilding a bind-mounted file during a run can
invalidate the running artifact; use a new directory and fresh seed for another
runtime set. Never replace artifacts in a retained profile-aware lab.

Start the pinned stack:

```sh
docker compose -f lab/compose.yaml up -d
docker compose -f lab/compose.yaml run --rm device validate --config /lab/device.json
docker compose -f lab/compose.yaml run --rm device init --config /lab/device.json
docker compose -f lab/compose.yaml run --rm device doctor --config /lab/device.json
docker compose -f lab/compose.yaml run --rm device recover --preflight --config /lab/device.json
```

The control service owns the fixture registry, CA provisioner and broker ACL.
The device mounts its state and separate recovery signer. The application has
read-only access to slots; the responder has its own certificate. Broker policy
changes restart all MQTT clients. A probe during reconnect can return `unknown`;
a later fresh observation is required.

## Enrollment and rotation

```sh
docker compose -f lab/compose.yaml run --rm device plan --mode enroll --config /lab/device.json > .work/reference/device/plan.json
docker compose -f lab/compose.yaml run --rm device apply --plan /lab/device/plan.json --config /lab/device.json
docker compose -f lab/compose.yaml run --rm device status --config /lab/device.json
docker compose -f lab/compose.yaml run --rm device probe --config /lab/device.json
```

Plans expire after ten minutes here. Do not edit their fields or digests.
`status` reads metadata and reports health as `unknown`; `probe` sends a new
external MQTT challenge. Receipts separate checkpoint, outcome and health.

For rotation, generate a fresh plan and use the same apply command:

```sh
docker compose -f lab/compose.yaml run --rm device plan --mode rotate --config /lab/device.json > .work/reference/device/plan.json
docker compose -f lab/compose.yaml run --rm device apply --plan /lab/device/plan.json --config /lab/device.json
```

Reconcile an unfinished operation before another plan:

```sh
docker compose -f lab/compose.yaml run --rm device reconcile --config /lab/device.json
```

At `issue-intent`, uncertain issuance requires recovered public evidence or
intervention. Reconcile does not repeat an unconfirmed CA request.
`reconcile --certificate /lab/device/recovered.pem` validates the chain, CSR
key, identity, usage, validity and current server authorization before importing
explicitly recovered evidence. A timeout never proves no certificate was issued.

An unfinished plan past its deadline returns
`intervention_required` / `plan-expired-intervention-required`. This alpha has
no in-place reauthorization or cancellation. The operation remains recorded,
blocks a new recovery plan and requires operator intervention. Do not edit the
deadline or delete its state to force continuation.
For an already completed exact plan, reconcile after its deadline returns the
historical successful outcome with health unknown and performs no new effects.

## Kill and resume

After a completed operation, generate another rotation plan. In one terminal:

```sh
docker compose -f lab/compose.yaml run --rm --name knowndevice-reference-interrupted -e KNOWNDEVICE_REFERENCE_LAB=1 -e KNOWNDEVICE_LAB_PAUSE_AT=registered device apply --plan /lab/device/plan.json --config /lab/device.json
```

Wait until `.work/reference/device/checkpoint.marker` contains `registered`.
In another terminal:

```sh
docker kill --signal KILL knowndevice-reference-interrupted
docker compose -f lab/compose.yaml run --rm device reconcile --config /lab/device.json
```

Remove only that generated marker before another manual interruption. This is
a killed process using persistent state, not hardware power-loss evidence.

## Recovery and failure matrix

Recovery uses the separate pre-provisioned signer and current entitlement.
An expired operational certificate cannot authorize new application access:

```sh
docker compose -f lab/compose.yaml run --rm device recover --preflight --config /lab/device.json
docker compose -f lab/compose.yaml run --rm device plan --mode recover --config /lab/device.json > .work/reference/device/plan.json
docker compose -f lab/compose.yaml run --rm device apply --plan /lab/device/plan.json --config /lab/device.json
```

Run the complete regression matrix from idle or completed state:

```sh
docker compose -f lab/compose.yaml run --rm checks
```

The trusted tester modifies generated fixtures, executes actual CLI subprocesses
and waits for real certificate expiry without changing the clock. It checks
ACL/nonce/activation failures, forged server requests, recovery denials, lost CA
responses without repeated issuance, and SIGKILL at checkpoints and effects
before acknowledgment. `check-report.json` records observed passes and marks
hardware power-cut as not run. A nonzero tester exit or partial report is not a
full pass.

`make check` separately covers storage fencing, confinement, parsing, protocol
limits and race tests. Linux filesystem-fault tests require an actual fault
mount and are separate from ordinary native tests. CI is configured for this
example on both Linux runners; execution requires an actual CI run.

## Cleanup and separate simulations

```sh
docker compose -f lab/compose.yaml down
```

This stops only the Compose project and retains generated state/evidence.
Delete the generated directory yourself only when no longer needed. Do not
remove a live journal, WAL, slot or recovery key independently.

`make demo` and `simulate --scenario acl-denied` remain in-memory fixtures.
Their `fixturePassed` field does not establish device health.
