# Security

The current foundation is a development model. It is not released device
software and provides no production security guarantee.

Do not publish private keys, recovery credentials, identifying fleet logs,
or an exploitable vulnerability in a public issue.

When the public repository is connected, use its **Security → Report a
vulnerability** form. Private vulnerability reporting must be enabled and
tested before a device release. No private intake channel is active in this
local workspace; during setup, report concerns directly to the maintainer
through the existing private conversation.

Include affected versions, reproduction steps, expected and actual behavior,
the trust boundary crossed, and a redacted example if possible. The project
will aim to acknowledge reports within three working days and give a
substantive update within seven. These are maintenance targets, not an SLA.
Disclosure timing is agreed with the reporter according to impact and patch
availability. There is no standing bounty program.

Until 1.0, security patches target the latest preview release. At 1.0,
publish the supported release lines and end-of-support policy before tagging
the release. Dependency scans and signed artifacts support the process;
they do not replace review of the device's complete deployment.

See the [threat model](docs/security/threat-model.md) and
[release requirements](docs/ops/release.md).
