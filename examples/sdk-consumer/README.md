# External alpha SDK consumer

This standalone Go module imports only the public alpha SDK and adapters. Its
local `replace ../..` proves workspace importability. The module path is local;
this example establishes no publication, stable SDK or device hardware support.

Run the in-memory proof from this directory:

```sh
go test -race ./...
go run .
```

It creates ephemeral `crypto.Signer` keys, constructs and validates CSRs under
both explicit credential policies, and prints only public digests and scoped
metadata. Compile-time assignments check the native HTTP role interfaces and
SystemClock. Tests additionally refuse the wrong policy, a changed CSR/signer
SPKI, an issued chain with the wrong key, and credential JSON serialization.
No device store or remote issuance occurs in this mode.

Inspect an actual selected process using a newly generated canonical snapshot
for `local-http-process-lab/1` whose composition pins that executable:

```sh
go run . --adapter /absolute/path/kd-adapter \
  --snapshot /absolute/path/public-snapshot.json \
  --work-dir /absolute/path/controlled-work
```

The process path initializes the negotiated session, checks typed role presence,
calls Clock.Assess, validates its fresh local interval, checks session health and
closes the session. It performs no issuance, registration, activation, withdrawal
or device-store write. Session health does not establish device/application
health. Clock trust reports the selected system-clock assumption, without time
attestation. Trusted process code remains able to use its direct system permissions;
this example establishes no OS isolation.

Staging uses a fresh directory under the selected WorkDir, or the local ignored
`.cache/sdk-consumer` by default. Failure artifacts remain local. Errors omit
raw process bytes, key material and private paths. Real transitions and durable
reconciliation use the controller and separately retained service evidence.
