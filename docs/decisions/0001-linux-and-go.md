# ADR 0001: Linux gateways and Go first

Status: accepted for the foundation; review after the first pilot.

Choose Go 1.27.2 for Linux amd64 and arm64.
Later change: the toolchain is pinned in `.go-version` and is now
Go 1.27.3. Deliver one domain engine,
controller, CLI, and Go SDK. Use established cryptography, JSON Schema
2020-12, strict YAML configuration, and Cobra for the device CLI. The
bootstrap fixture CLI uses standard-library flags so it can run offline;
replace it in the first device implementation.

Rust would be a good alternative where memory limits and embedded targets
lead the design. C would integrate with many RTOS stacks but would increase
the memory-safety burden of a new gateway controller. Go fits the supplied
portfolio conventions and the first Linux audience. It does not imply
Go is appropriate for every MCU.

Avoid a web UI, coordinator, multi-language SDKs, and universal cloud
integration until the device transitions work. A gateway can later speak
a bounded MCU contract without requiring the daemon on the MCU.
