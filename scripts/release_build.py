#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build reproducible Linux release archives, CycloneDX SBOMs and SHA256SUMS from a clean checkout."""

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import quote
import uuid

ROOT = Path(__file__).resolve().parents[1]
MODULE = "github.com/knowndevice/knowndevice"
COMMANDS = ("knowndevice", "kd-reference", "kd-profilelab", "kd-adapter", "kd-adaptergen")
ARCHES = ("amd64", "arm64")
DOCUMENTS = ("LICENSE", "NOTICE", "README.md", "CHANGELOG.md")
DEV_VERSION = "0.0.0-dev"
SEMVER = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
GO_KEEP = {"GOPATH", "GOCACHE", "GOMODCACHE", "GOPROXY", "GOSUMDB", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOINSECURE"}


class ReleaseError(Exception):
    pass


def run(command, env=None):
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    if result.returncode:
        raise ReleaseError(f"{' '.join(command)} exited {result.returncode}: {result.stderr.strip()}")
    return result.stdout


def go_env(arch=None):
    """Return an environment where only the pinned toolchain, target and caches select the build.

    Inherited GOFLAGS, GOAMD64, GOEXPERIMENT and similar settings, including `go env -w`
    values, would change the binaries without appearing in the release inputs.
    """
    env = {key: value for key, value in os.environ.items() if key in GO_KEEP or not key.startswith(("GO", "CGO_"))}
    env.setdefault("GOCACHE", str(ROOT / ".cache/go-build"))
    env.setdefault("GOMODCACHE", str(ROOT / ".cache/go-mod"))
    env.update(GOENV="off", GOTOOLCHAIN="local", GOWORK="off", CGO_ENABLED="0")
    if arch:
        env.update(GOOS="linux", GOARCH=arch)
    return env


def check_version(version):
    if version != DEV_VERSION and not SEMVER.fullmatch(version):
        raise ReleaseError(f"version {version!r} is not X.Y.Z[-prerelease] without a leading v")


def check_build(info, arch, commit, toolchain, module_version=None):
    settings = {item["Key"]: item["Value"] for item in info.get("Settings", [])}
    expected = {"-trimpath": "true", "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": arch, "vcs.revision": commit, "vcs.modified": "false"}
    wrong = sorted(key for key, value in expected.items() if settings.get(key) != value)
    if info.get("GoVersion") != toolchain:
        wrong.append("GoVersion")
    if info.get("Main", {}).get("Path") != MODULE:
        wrong.append("Main.Path")
    if wrong:
        raise ReleaseError(f"{info.get('Path')} for {arch} has unexpected build info: {', '.join(wrong)}")
    actual = info["Main"].get("Version")
    if module_version and actual != module_version:
        # Go reuses a pseudo-version cached in GOMODCACHE for this commit, even after the commit is tagged.
        raise ReleaseError(f"{info.get('Path')} records module version {actual}, expected {module_version}; build with an empty GOMODCACHE")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_archive(path, items, epoch):
    """Write a gzip tar whose bytes depend only on member names, contents, modes and epoch."""
    members = {name: (source, mode) for name, source, mode in items}
    for name in list(members):
        for parent in PurePosixPath(name).parents:
            if str(parent) != ".":
                members.setdefault(str(parent), (None, 0o755))
    with path.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for name in sorted(members):
                source, mode = members[name]
                info = tarfile.TarInfo(name)
                info.mode, info.mtime = mode, epoch
                if source is None:
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                    continue
                data = source if isinstance(source, bytes) else source.read_bytes()
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))


def purl(path, version):
    return "pkg:golang/" + "/".join(quote(part, safe="") for part in path.split("/")) + "@" + quote(version, safe="")


def sbom(archive_name, version, commit, epoch, binaries):
    """Describe the binaries in one archive and the modules recorded in their build info.

    The standard library uses the stdlib name and purl that syft emits for Go binaries.
    """
    components, modules, dependencies = [], {}, []
    for name, digest, info in binaries:
        ref = f"file:bin/{name}"
        refs = set()
        for module in [info["Main"], *info.get("Deps", [])]:
            module = module.get("Replace") or module
            key = purl(module["Path"], module["Version"])
            entry = {"type": "library", "bom-ref": key, "name": module["Path"], "version": module["Version"], "purl": key}
            if module.get("Sum"):
                entry["properties"] = [{"name": "go:sum", "value": module["Sum"]}]
            modules[key] = entry
            refs.add(key)
        stdlib = "pkg:golang/stdlib@" + info["GoVersion"].removeprefix("go")
        modules[stdlib] = {"type": "library", "bom-ref": stdlib, "name": "stdlib", "version": info["GoVersion"], "purl": stdlib}
        refs.add(stdlib)
        components.append({"type": "application", "bom-ref": ref, "name": name, "version": version, "hashes": [{"alg": "SHA-256", "content": digest}], "properties": [{"name": "go:package", "value": info["Path"]}]})
        dependencies.append({"ref": ref, "dependsOn": sorted(refs)})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'https://{MODULE}/{commit}/{archive_name}')}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "bom-ref": archive_name, "name": "knowndevice", "version": version, "properties": [{"name": "knowndevice:archive", "value": archive_name}, {"name": "knowndevice:source-commit", "value": commit}]},
        },
        "components": components + [modules[key] for key in sorted(modules)],
        "dependencies": [{"ref": archive_name, "dependsOn": [component["bom-ref"] for component in components]}, *dependencies],
    }


def write_checksums(out):
    names = sorted(path.name for path in out.iterdir() if path.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text("".join(f"{sha256((out / name).read_bytes())}  {name}\n" for name in names))


def release(version, out):
    check_version(version)
    if out.exists() and any(out.iterdir()):
        raise ReleaseError(f"{out} is not empty")
    if run(["git", "status", "--porcelain"]):
        raise ReleaseError("the working tree has uncommitted or untracked files")
    commit = run(["git", "rev-parse", "HEAD"]).strip()
    epoch = int(run(["git", "log", "-1", "--format=%ct", "HEAD"]))
    if version != DEV_VERSION and f"v{version}" not in run(["git", "tag", "--points-at", "HEAD"]).split():
        raise ReleaseError(f"tag v{version} does not point at HEAD")
    toolchain = "go" + (ROOT / ".go-version").read_text().strip()
    host = run(["go", "env", "GOVERSION", "GOHOSTOS", "GOHOSTARCH"], env=go_env()).split()
    if host[0] != toolchain:
        raise ReleaseError(f"go is {host[0]}; .go-version requires {toolchain}")
    tracked = run(["git", "ls-files", "-z", "--", "api/schemas/*.schema.json", "third_party/licenses"]).split("\0")
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as scratch:
        for arch in ARCHES:
            prefix = f"knowndevice_{version}_linux_{arch}"
            items, binaries = [], []
            for name in COMMANDS:
                binary = Path(scratch) / arch / name
                run(["go", "build", "-trimpath", f"-ldflags=-X main.version={version}", "-o", str(binary), f"./cmd/{name}"], env=go_env(arch))
                info = json.loads(run(["go", "version", "-m", "-json", str(binary)], env=go_env()))
                check_build(info, arch, commit, toolchain, None if version == DEV_VERSION else f"v{version}")
                binaries.append((name, sha256(binary.read_bytes()), info))
                items.append((f"{prefix}/bin/{name}", binary, 0o755))
            # -trimpath omits -ldflags from build info, so only a native run shows the injected version.
            if host[1:] == ["linux", arch]:
                printed = run([str(Path(scratch) / arch / "knowndevice"), "version"]).strip()
                if printed != version:
                    raise ReleaseError(f"knowndevice version printed {printed!r}, expected {version!r}")
            items += [(f"{prefix}/{name}", ROOT / name, 0o644) for name in DOCUMENTS]
            for rel in filter(None, tracked):
                target = f"schemas/{Path(rel).name}" if rel.startswith("api/schemas/") else rel
                items.append((f"{prefix}/{target}", ROOT / rel, 0o644))
            archive = out / f"{prefix}.tar.gz"
            write_archive(archive, items, epoch)
            document = sbom(archive.name, version, commit, epoch, binaries)
            (out / f"{prefix}.cdx.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    write_checksums(out)
    return sorted(out.iterdir())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help=f"X.Y.Z[-prerelease] with tag vX.Y.Z[-prerelease] on HEAD, or {DEV_VERSION}")
    parser.add_argument("--out", required=True, type=Path, help="new or empty output directory")
    args = parser.parse_args(argv)
    try:
        paths = release(args.version, args.out.resolve())
    except ReleaseError as error:
        print(f"release build refused: {error}", file=sys.stderr)
        return 1
    print("\n".join(str(path) for path in paths))
    return 0


if __name__ == "__main__":
    sys.exit(main())
