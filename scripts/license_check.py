#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check that NOTICE and third_party/licenses cover exactly what the maintained go.mod files require.

Read-only; no network or Go toolchain. Exit codes: 0 covered, 1 missing, stale or mismatched entries.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
GO_MODS = ("go.mod", "examples/sdk-consumer/go.mod")
LICENSES = "third_party/licenses"
STDLIB = "go"
STDLIB_LABEL = "Go standard library and runtime"
NOTICE_LINE = re.compile(rf"({re.escape(STDLIB_LABEL)}|\S+) (v\d+\.\d+\.\d+\S*|go\d+\.\d+\.\d+)(?: .*)?")
README_ROW = re.compile(rf"\| (?:`([^`]+)`|{re.escape(STDLIB_LABEL)}) \| `([^`]+)` \|.*")
README_COUNT = re.compile(r"\bthe\s+(\d+)\s+Go\s+module\s+versions\b")
README_LINK = re.compile(r"\]\(([^)\s]+)\)")
GO_VERSION_TOKEN = re.compile(r"\bgo\d+\.\d+\.\d+\b")


def parse_go_mod(path):
    """Return the go.mod requirements as (module, version) pairs, without local replace targets.

    A replace to another module changes which license applies, so it is an error until handled.
    """
    requires, local, errors = set(), [], []
    block = None
    for raw in path.read_text().splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block:
            if line == ")":
                block = None
                continue
            verb, fields = block, line.split()
        elif match := re.fullmatch(r"(\w+)\s*\(", line):
            block = match[1]
            continue
        else:
            verb, *fields = line.split()
        if verb == "require":
            if len(fields) != 2:
                errors.append(f"unreadable require: {line}")
                continue
            requires.add(tuple(fields))
        elif verb == "replace":
            if "=>" not in fields:
                errors.append(f"unreadable replace: {line}")
                continue
            arrow = fields.index("=>")
            old, target = fields[:arrow], fields[arrow + 1:]
            if target and target[0].startswith(("./", "../", "/")):
                local.append(old)
            else:
                errors.append(f"replace to a module is not supported: {line}")
    return {pair for pair in requires if not any(pair[0] == old[0] and old[1:] in ([], [pair[1]]) for old in local)}, errors


def directory_name(module, version):
    return f"{module}@{version}"


def label(module, version):
    return f"{STDLIB_LABEL if module == STDLIB else module} {version}"


def source_archive(module, version):
    if module == STDLIB:
        return f"https://go.dev/dl/{version}.src.tar.gz"
    escaped = re.sub("[A-Z]", lambda match: "!" + match[0].lower(), module)
    return f"https://proxy.golang.org/{escaped}/@v/{version}.zip"


def compare(errors, kind, found, required):
    for pair in sorted(required - set(found)):
        errors.append(f"missing {kind}: {label(*pair)}")
    for pair in sorted(set(found) - required):
        errors.append(f"stale {kind}: {label(*pair)}")
    for pair in sorted({pair for pair in found if found.count(pair) > 1}):
        errors.append(f"duplicate {kind}: {label(*pair)}")


def scan_licenses(licenses):
    """Return the version directories with their files, relative to licenses, and any stray files."""
    directories, stray = {}, []
    for directory, subdirectories, names in os.walk(licenses):
        current = Path(directory)
        for name in [name for name in subdirectories if "@" in name]:
            subdirectories.remove(name)
            rel = (current / name).relative_to(licenses).as_posix()
            directories[tuple(rel.rsplit("@", 1))] = sorted(path.relative_to(licenses).as_posix() for path in (current / name).rglob("*") if path.is_file())
        stray += [(current / name).relative_to(licenses).as_posix() for name in names if current != licenses or name not in {"README.md", "manifest.json"}]
    return directories, sorted(stray)


def check_manifest(errors, licenses, manifest, required, directories):
    recorded = {}
    for entry in manifest.get("files", []):
        module = entry.get("module") or (STDLIB if entry.get("component") == STDLIB_LABEL else None)
        pair, file = (module, entry.get("version")), entry.get("file")
        if pair not in required:
            errors.append(f"stale manifest entry: {file}")
            continue
        prefix = directory_name(*pair) + "/"
        if not isinstance(file, str) or not file.startswith(prefix) or entry.get("upstreamFile") != file.removeprefix(prefix):
            errors.append(f"manifest entry names the wrong file: {label(*pair)}: file {file}, upstreamFile {entry.get('upstreamFile')}")
            continue
        if entry.get("sourceArchive") != source_archive(*pair):
            errors.append(f"wrong manifest sourceArchive: {file}: {entry.get('sourceArchive')}")
        if file in recorded:
            errors.append(f"duplicate manifest entry: {file}")
        recorded[file] = entry.get("sha256")

    copied = {file for pair in required for file in directories.get(pair, [])}
    for file in sorted(copied - set(recorded)):
        errors.append(f"missing manifest entry: {file}")
    for file in sorted(set(recorded) - copied):
        errors.append(f"manifest entry without a file: {file}")
    for file in sorted(copied & set(recorded)):
        actual = hashlib.sha256((licenses / file).read_bytes()).hexdigest()
        if actual != recorded[file]:
            errors.append(f"digest mismatch: {file}: manifest {recorded[file]}, file {actual}")


def check(root):
    errors, required = [], set()
    for rel in GO_MODS:
        try:
            pairs, problems = parse_go_mod(root / rel)
        except (OSError, ValueError) as error:
            errors.append(f"cannot read {rel}: {error}")
            continue
        required |= pairs
        errors += [f"{rel}: {problem}" for problem in problems]
    modules = len(required)

    try:
        go_version = (root / ".go-version").read_text().strip()
        notice = (root / "NOTICE").read_text()
        readme = (root / LICENSES / "README.md").read_text()
        manifest = json.loads((root / LICENSES / "manifest.json").read_text())
    except (OSError, ValueError) as error:
        return errors + [f"cannot read coverage files: {error}"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", go_version):
        return errors + [f".go-version must hold one Go release, found {go_version!r}"]
    stdlib = (STDLIB, f"go{go_version}")
    required.add(stdlib)

    notice_lines = []
    for line in notice.splitlines():
        if match := NOTICE_LINE.fullmatch(line):
            notice_lines.append((STDLIB if match[1] == STDLIB_LABEL else match[1], match[2]))
    compare(errors, "NOTICE line", notice_lines, required)

    rows, row_keys = {}, []
    for line in readme.splitlines():
        if match := README_ROW.fullmatch(line):
            pair = (match[1] or STDLIB, match[2])
            row_keys.append(pair)
            rows[pair] = set(README_LINK.findall(line))
    compare(errors, "README row", row_keys, required)

    licenses = root / LICENSES
    directories, stray = scan_licenses(licenses)
    for pair in sorted(required - set(directories)):
        errors.append(f"missing license directory: {LICENSES}/{directory_name(*pair)}/")
    for pair in sorted(required & set(directories)):
        if not directories[pair]:
            errors.append(f"empty license directory: {LICENSES}/{directory_name(*pair)}/")
    for pair in sorted(set(directories) - required):
        errors.append(f"stale license directory: {LICENSES}/{directory_name(*pair)}/")
    errors += [f"license file outside a module version directory: {LICENSES}/{file}" for file in stray]

    for pair in sorted(required & set(rows) & set(directories)):
        for file in sorted(set(directories[pair]) - rows[pair]):
            errors.append(f"README row does not link copied file: {file}")
        for link in sorted(rows[pair] - set(directories[pair])):
            errors.append(f"README row links a file outside its license directory: {label(*pair)}: {link}")

    check_manifest(errors, licenses, manifest, required, directories)

    count = README_COUNT.search(readme)
    if not count or int(count[1]) != modules:
        errors.append(f"README module count: expected the {modules} Go module versions, found {' '.join(count[0].split()) if count else 'no count'}")
    for name, text in (("NOTICE", notice), ("README", readme)):
        for token in sorted(set(GO_VERSION_TOKEN.findall(text)) - {stdlib[1]}):
            errors.append(f"stale Go version in {name}: {token}")

    # Apache-2.0 section 4(d) requires upstream NOTICE text to travel with the project NOTICE.
    for pair in sorted(required & set(directories)):
        for file in directories[pair]:
            if Path(file).name == "NOTICE" and (licenses / file).read_text().strip() not in notice:
                errors.append(f"project NOTICE does not reproduce {LICENSES}/{file}")
    return errors


def main(root=ROOT):
    errors = check(root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("License coverage matches go.mod, examples/sdk-consumer/go.mod and .go-version.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
