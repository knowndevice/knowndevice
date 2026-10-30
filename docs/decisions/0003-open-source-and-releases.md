# ADR 0003: Local Apache-2.0 framework and staged publication

Status: accepted.

Use Apache-2.0 for code, schemas, SDK, generators, conformance, and original
documentation. Review new dependency licenses and preserve notices. Use
the Developer Certificate of Origin for contributions rather than a CLA.

Keep rotation, recovery, local scheduling, diagnostics and extension tests
usable without a hosted account. A hosted coordinator may follow demand;
its outage must not disable local policy. Fleet coordination is after 1.0.

Publish the repository foundation when its owner is supplied. Publish a
usable 0.1 lab preview only after its release gates pass. Launch the static
Cloudflare website with that first useful release, not during setup.
Stabilize contracts after real integration and pilot evidence.
