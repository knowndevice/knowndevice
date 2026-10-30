# Local credential-profile lab

This generated-data lab exercises both RFC 0005 credential profiles through
the same controller and local HTTP roles, either built in or behind the
negotiated stdio adapter. It runs step-ca 0.29.0,
an exact TLS-peer enforcer, and a separate Application process. It does not
establish the independent KD-029 profile, shared-deployment KD-030 withdrawal,
hardware behavior or a released SDK.

Build with `make build`. Choose a new private directory and a unique Compose
project name. The seed generates a new device and deployment identifier;
it cannot reuse an existing identity or migrate a store. The selected executable
bytes are bound to the composition and checked at startup.

```sh
bin/kd-profilelab seed \
  --dir .work/profile-example-arm64 \
  --profile stable-device-cn \
  --service-artifact bin/kd-profilelab-linux-arm64 \
  --controller-artifact bin/knowndevice-linux-arm64
export KNOWNDEVICE_PROFILE_DIR="$PWD/.work/profile-example-arm64"
export KNOWNDEVICE_PROFILE_ARCH=arm64
export KNOWNDEVICE_PROFILE_BIN_DIR="$KNOWNDEVICE_PROFILE_DIR/artifacts"
export KNOWNDEVICE_PROFILE_RUNTIME=linux-arm64-on-arm64-docker-host
cp bin/kd-adapter-linux-arm64 "$KNOWNDEVICE_PROFILE_BIN_DIR/"
docker compose -p kd-profile-example-arm64 -f lab/profiles/compose.yaml up -d
docker compose -p kd-profile-example-arm64 -f lab/profiles/compose.yaml run --rm checks
docker compose -p kd-profile-example-arm64 -f lab/profiles/compose.yaml down
```

Use `--profile reference-generation-cn` with another new directory to exercise
the reference identity policy through this composition. The legacy v1alpha1
Mosquitto reference remains in [the original Compose file](../compose.yaml).
On an amd64 host select `amd64` binaries and label the runtime accordingly.
If amd64 runs on an arm64 Docker host, explicitly label emulation in
`KNOWNDEVICE_PROFILE_RUNTIME`; cross-builds and emulation supply no hardware
evidence.

For the process path, add `--process-artifact bin/kd-adapter-linux-arm64` to
the seed on another fresh directory/project. Seed copies and pins that wrapper
as `local-http-process-lab/1`; the separate copy command above is then
unnecessary. The checks mount the wrapper in both modes, but the native
composition neither selects nor invokes it. See the
[alpha SDK reference](../../docs/reference/alpha-sdk.md) for negotiation and
public import usage. Keep all copied executables unchanged while mounted.

The check driver stops at the first failed criterion. It uses actual CLI
processes, real issuance and the independent service channels, preserves
per-operation generations, and exercises process kills and a 45-second
known-result issuance restart. Its final fencing case intentionally retains
one server-side unknown reservation. That reservation supplies no activation
or application rights; no new generation replaces it. Keep the generated
directory, report, counts and service logs for inspection. Cleanup removes
only the named Compose project's containers and network.

The composition separates Control, Application, operational issuance,
Recovery, Transport and Observer trust. The issuance wrapper admits only its
separately pinned Authority caller. The actual CA HTTPS backend has a separate
`authority-transport` endpoint, hostname, roots and issuer policy. Its explicitly
declared operational-root reuse does not supply a fallback for another role.
All network validation uses the immutable public snapshot and verifies the
whole assessed time interval.

The [stable template](stable-client.tpl) emits the exact device CN, no SAN and
only clientAuth. The [reference template](reference-client.tpl) emits the
generation CN and matching DNS SAN. The control service validates the original
signed CSR, SPKI, leaf, issuer and lifetime before storing a result. The
templates use the pinned [step-ca template interface](https://smallstep.com/docs/step-ca/templates/).
The CA's nominal lifetime is 1200 seconds with 30-second backdate. Explicit
requests select a 1200-second total validity interval. Accepted lifetime is
300–1260 seconds; initial backdate is at most 60 seconds against the persisted
send interval, and activation requires at least 120 seconds remaining.

For a new evidence lab, `seed --authority-lifetime-seconds 300` selects
`local-http-lab/2` before snapshot creation. The explicit request is 300 seconds
total with the same backdate and unchanged strict shared limits. Composition 1
keeps the default 1200-second request and existing digest encoding. The original
plan limit remains 600 seconds; no pending plan is edited to wait for expiry.

An exact pinned Observer caller can read the bounded `/session-inventory`
Control endpoint for the current activated plan. It reports actual transport
sockets and immutable authenticated peer bindings without durable writes.
Inventory, TLS refusal and CA revoke remain separate from withdrawal evidence.

HTTP connection identity is separate from Application selection and session
metadata. Each reconnect gets a fresh connection ID; TLS tickets are disabled.
The declared session policy transfers no backlog or other durable application
state. Withdrawal first persists an exact previous-credential deny, closes
its bound connections and all sockets without a known binding, then requires
an actual old-key denied request and new target Application observation.
Unbound sockets may belong to unrelated clients; the declared scope is this
whole generated lab service. Timeout, generic socket errors and passive CA
revocation cannot supply effective withdrawal.
