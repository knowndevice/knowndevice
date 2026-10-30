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

[`release.yml`](../../.github/workflows/release.yml) runs when a tag
`vX.Y.Z` or `vX.Y.Z-prerelease` is pushed for a commit on `main`. A manual
run builds `0.0.0-dev` files without attestations. Neither creates a GitHub
release; the files stay workflow artifacts. No run has happened yet because
the hosted repository is not connected.

1. Build jobs on native amd64 and arm64 runners, with read-only repository
   access, run `make check` and `scripts/release_build.py`.
2. The script refuses a dirty tree, a Go toolchain other than `.go-version`,
   and a release version without the matching tag on HEAD. It builds the
   five commands for linux/amd64 and linux/arm64 with `CGO_ENABLED=0`,
   `-trimpath` and `-X main.version`, and checks each binary's build info for
   the commit, a clean tree, the target, the toolchain and, for a release,
   the tagged module version. On Linux it also runs the native
   `knowndevice version`.
3. A verify job requires byte-identical files from both runners.
4. For tags only, the attest job, the only job with `id-token: write` and
   `attestations: write`, signs a SLSA build provenance attestation for every
   file in `SHA256SUMS` and an SBOM attestation for each archive.

| File | Content |
| --- | --- |
| `knowndevice_<version>_linux_<arch>.tar.gz` | `bin/` with the five commands, LICENSE, NOTICE, README, CHANGELOG, `schemas/` and `third_party/licenses/`; commit time as mtime, root owner, fixed modes and order |
| `knowndevice_<version>_linux_<arch>.cdx.json` | CycloneDX 1.6 SBOM from the binaries' own build info: binaries with SHA-256, Go modules with purl and `go.sum` hash, the standard library |
| `SHA256SUMS` | SHA-256 of the four files above |

Artifact attestations work in public repositories, and in private ones only
on GitHub Enterprise Cloud ([actions/attest](https://github.com/actions/attest#readme)).
A public repository signs through the public-good Sigstore instance, so each
tag run writes a permanent public transparency-log entry. Treat pushing a
release tag as publication.

Build the same files locally from a clean checkout with the pinned toolchain:

```sh
python3 scripts/release_build.py --version 0.0.0-dev --out dist
```

Go caches the pseudo-version of a commit in `GOMODCACHE` and keeps using it
after the commit is tagged. If the tagged commit was built before, a local
release build is refused; point `GOMODCACHE` at an empty directory.

After a tag run, a consumer verifies a downloaded archive with checksums and
the [GitHub CLI](https://cli.github.com/manual/gh_attestation_verify):

```sh
sha256sum --check --strict --ignore-missing SHA256SUMS
gh attestation verify knowndevice_0.1.0_linux_amd64.tar.gz --repo knowndevice/knowndevice \
  --signer-workflow knowndevice/knowndevice/.github/workflows/release.yml
gh attestation verify knowndevice_0.1.0_linux_amd64.tar.gz --repo knowndevice/knowndevice \
  --predicate-type https://cyclonedx.org/bom
```

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
