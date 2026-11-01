# Release process

The current foundation can be shared as development work once repository
and community contacts are configured. It is not the first useful device
release. Follow the acceptance gates in [ROADMAP](../../ROADMAP.md).

## Prepare

Match every README/website claim to available code and the tested scope.
Update changelog, integration versions, hardware matrix, schemas, CLI
reference, migration notes, supported versions and known limitations.
Run `make check`, `python3 scripts/check_repository.py --publication` (with a
Python 3.11+ interpreter), real reference-stack CI, fuzzing,
redaction, interruption and native/hardware tests appropriate to the release.
An unrun required gate blocks the release; it does not block unrelated work.

Pin direct/transitive dependencies through module checksums and dependency
locks. Pin external images by reviewed digest and workflow actions by full
commit. Verify license notices and vulnerability scans. Review recovery,
storage and key changes independently before release.

## Artifacts and provenance

[`release.yml`](../../.github/workflows/release.yml) runs when a tag
`vX.Y.Z` or `vX.Y.Z-prerelease` is pushed and stops unless the tagged commit
is on `main`. A manual run on any ref builds `0.0.0-dev` files without
attestations. Neither creates a GitHub release; the files stay workflow
artifacts, which expire with the repository's artifact retention (90 days by
default) and need a signed-in account to download.

GitHub runs `release.yml` from the tagged commit, so someone who can push a
tag can also push a changed workflow that skips the `main` check and still
gets attestations from the same workflow path. The signature shows which
workflow and ref ran, not that the commit is on `main`. The control is a tag
ruleset that lets only maintainers create, move or delete `v*` tags.

1. Build jobs on native amd64 and arm64 runners, with read-only repository
   access, run `make check` and `scripts/release_build.py`. `make check`
   includes the govulncheck scan, which needs vuln.go.dev, the Go module
   proxy and the checksum database. A newly published vulnerability in a
   function the code calls fails the release run until a dependency or Go
   update fixes it, or a reviewed row in
   [the accepted list](../security/vulnerability-exceptions.md) covers it.
2. The script refuses a dirty tree, a Go toolchain other than `.go-version`,
   and a release version without the matching tag on HEAD. It builds the
   five commands for linux/amd64 and linux/arm64 with `CGO_ENABLED=0`,
   `-trimpath` and `-X main.version`, and checks each binary's build info for
   the commit, a clean tree, the target, the toolchain and, for a release,
   the tagged module version. On Linux it also runs the native
   `knowndevice version`. Output appears only after every step passes.
3. A verify job requires byte-identical files from both runners.
4. For pushed tags only, the attest job, the only job with `id-token: write` and
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

Build the same files locally from a clean checkout with the pinned toolchain.
Identical bytes also need the same tags, an empty or matching `GOMODCACHE`,
and a Python whose zlib produces the same deflate output; zlib-ng does not:

```sh
python3 scripts/release_build.py --version 0.0.0-dev --out dist
```

Go caches the pseudo-version of a commit in `GOMODCACHE` and keeps using it
after the commit is tagged. If the tagged commit was built before, a local
release build is refused; point `GOMODCACHE` at an empty directory. When one
commit carries several version tags, Go records the highest, so only that
version builds.

Once the files are published after a tag run, a consumer verifies a
downloaded archive with checksums and the
[GitHub CLI](https://cli.github.com/manual/gh_attestation_verify):

```sh
sha256sum --check --strict --ignore-missing SHA256SUMS
gh attestation verify knowndevice_0.1.0_linux_amd64.tar.gz --repo knowndevice/knowndevice \
  --signer-workflow knowndevice/knowndevice/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0
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
