# Release process

The current foundation can be shared as development work once repository
and community contacts are configured. It is not the first useful device
release. Follow the acceptance gates in [ROADMAP](../../ROADMAP.md).

## Prepare

Match every README/website claim to available code and the tested scope.
Update changelog, integration versions, hardware matrix, schemas, CLI
reference, migration notes, supported versions and known limitations.
Run `make check`, publication checks, real reference-stack CI, fuzzing,
redaction, interruption and native/hardware tests appropriate to the release.
An unrun required gate blocks the release; it does not block unrelated work.

Pin direct/transitive dependencies through module checksums and dependency
locks. Pin external images by reviewed digest and workflow actions by full
commit. Verify license notices and vulnerability scans. Review recovery,
storage and key changes independently before release.

## Artifacts and provenance

Build reproducibly with a pinned toolchain and recorded source commit.
Publish Linux amd64/arm64 archives, checksums, SBOM and provenance bound
to their digests. Use a release workflow with least privilege and OIDC
for signing/attestation. Verify downloaded artifacts through an independent
consumer path and document that verification. No release workflow is
implemented in the foundation.

## Publish within the approved scope

Confirm the tag and artifact digests. Publish GitHub release notes describing
the exact available scope, changes, upgrade steps and limitations. Update
the issue milestone using completed acceptance evidence, not elapsed time.
Remote release/push/deploy is separate from local preparation and follows
the maintainer's existing authorized scope.

## Cloudflare launch

Launch the site with 0.1.0 after its gates pass. Use a static site generated
from maintained/versioned repository docs; choose the generator after
comparing build size, Mermaid rendering and contributor setup.
The site does not host fleet credentials, device APIs, or the coordinator.

Build and review locally/private preview first. Publish to Cloudflare Pages
or Workers Static Assets using the supplied account/domain and a reviewed
build command. Cloudflare supports static HTML assets; confirm the chosen
deployment method and account configuration before writing a workflow.
[Cloudflare static site guide](https://developers.cloudflare.com/pages/framework-guides/deploy-anything/).

Configure canonical URLs, sitemap, robots, social metadata, accessible
navigation, release links, and visible current/planned capability status.
Verify domain/TLS, rendered diagrams, mobile/keyboard navigation, links,
cache behavior and rollback. The repository workflow does not deploy
automatically before the launch scope is authorized.
