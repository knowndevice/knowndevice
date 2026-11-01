# CLI reference

Version: 0.0.0-dev. Device commands select explicit v1alpha1 reference or
v1alpha2 credential profiles; fixtures report their separate in-memory scope.

## `knowndevice apply`

Apply the exact authorized plan through real adapters.

```text
      --config string   Device profile path (default "device.json")
      --plan string     Exact plan JSON path

```

## `knowndevice doctor`

Check local trust and recovery prerequisites.

```text
      --config string   Device profile path (default "device.json")

```

## `knowndevice init`

Initialize a private journal and two-slot store.

```text
      --config string   Device profile path (default "device.json")

```

## `knowndevice plan`

Print a side-effect-free bounded transition plan.

```text
      --config string   Device profile path (default "device.json")
      --mode string     enroll, rotate or recover (default "rotate")

```

## `knowndevice probe`

Probe the active generation against the external responder.

V2 requires the retained original plan for that exact active credential and its
remaining authorization lifetime. During a pending rotation, the previous active
plan is no longer retained; probe exits 3 with an explicit unavailability reason
and unknown device health. This limitation applies to HTTP and process adapters.

```text
      --config string   Device profile path (default "device.json")

```

## `knowndevice reconcile`

Resume the persisted operation through status lookups.

```text
      --certificate string   Explicit recovered public certificate chain for an unknown issuance
      --config string        Device profile path (default "device.json")

```

## `knowndevice recover`

Check separate device recovery authorization.

```text
      --config string   Device profile path (default "device.json")
      --preflight       Read current server entitlement without issuance

```

## `knowndevice reference`

Print the CLI reference from this command tree.

```text
  -h, --help   help for reference

```

## `knowndevice simulate`

Run a deterministic in-memory fixture.

```text
      --scenario string   Fixture: rotation, acl-denied, clock-untrusted, revoked, missing-recovery (default "rotation")

```

## `knowndevice status`

Read persisted metadata without a device health claim.

```text
      --config string   Device profile path (default "device.json")

```

## `knowndevice validate`

Validate strict JSON/YAML configuration.

```text
      --config string   Device profile path (default "device.json")

```

## `knowndevice version`

Print the build version.

```text

```

Exit codes: 0 completed; 2 input/usage error; 3 transition blocked or unknown;
4 local storage/output failure. JSON reports use stdout; errors use stderr.
A fixture passing does not establish device or hardware success.
