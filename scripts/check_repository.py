#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check local links, contributor setup, operation coverage and publication metadata."""

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tomllib

EXCLUDED = {".git", ".cache", ".work", ".private", ".venv", "bin", "dist", "__pycache__", ".agents", ".codex"}


def files(root):
    for directory, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDED]
        for name in names:
            yield Path(directory) / name


def frontmatter(path):
    """Parse the scalar/JSON-array YAML subset used by this project's metadata.

    Other YAML forms are rejected instead of silently misparsed. Client startup
    checks cover the actual clients' parsers; this is a deterministic local gate.
    """
    text = path.read_text()
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise ValueError(f"{path}: missing frontmatter")
    header = text[4:].split("\n---\n", 1)[0]
    result = {}
    for line in header.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_-]*): (.+)", line)
        if not match:
            raise ValueError(f"{path}: unsupported metadata line: {line}")
        key, value = match.groups()
        if key in result:
            raise ValueError(f"{path}: duplicate metadata key {key}")
        if value[0] in '[{"' or value in {"true", "false"} or value.isdecimal():
            value = json.loads(value)
        elif not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError(f"{path}: quote the metadata value for {key}")
        result[key] = value
    return result


def check(root, publication=False):
    errors = []
    paths = list(files(root))
    internal_setup = (root / "AGENTS.md").exists() or (root / "CLAUDE.md").exists() or (root / ".claude").exists()
    required = ["README.md", "LICENSE", "NOTICE", "CONTRIBUTING.md", "GOVERNANCE.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md", "ROADMAP.md"]
    if internal_setup:
        required += ["AGENTS.md", "CLAUDE.md"]
    for name in required:
        if not (root / name).is_file():
            errors.append(f"missing {name}")
    for path in paths:
        rel = path.relative_to(root).as_posix()
        try:
            if path.suffix == ".json":
                json.loads(path.read_text())
            if path.suffix == ".toml":
                with path.open("rb") as stream:
                    tomllib.load(stream)
            if path.suffix == ".md":
                text = path.read_text()
                for target in re.findall(r"(?<!!)\[[^\]\n]+\]\(([^)\n]+)\)", text):
                    if target.startswith(("https://", "http://", "mailto:", "#")):
                        continue
                    target = target.split("#", 1)[0]
                    if target and not (path.parent / target).exists():
                        errors.append(f"{rel}: missing link target {target}")
                if rel not in {"docs/style.md"} and re.search(r"\b(?:seamlessly|revolutionary|game-changing|delve into|unlock the power)\b", text, re.I):
                    errors.append(f"{rel}: replace promotional filler with concrete behavior")
                if re.search(r"(?:generated|written|built) (?:by|with) (?:codex|claude)|co-authored-by:.*(?:codex|claude|openai|anthropic)", text, re.I):
                    errors.append(f"{rel}: helper authorship credit")
        except (ValueError, OSError) as error:
            errors.append(f"{rel}: {error}")

    for name in ("AGENTS.md", "CLAUDE.md"):
        if (root / name).exists() and len((root / name).read_text().splitlines()) > 150:
            errors.append(f"{name}: startup instructions exceed 150 lines")
    for path in (root / ".claude").rglob("*.md"):
        if "/rules/" in path.as_posix() or path.name == "SKILL.md" or "/agents/" in path.as_posix():
            try:
                data = frontmatter(path)
                if "/rules/" in path.as_posix():
                    globs = data.get("paths", [])
                    if not isinstance(globs, list) or not globs:
                        raise ValueError("scoped rule needs paths")
                    for glob in globs:
                        if not list(root.glob(glob)):
                            raise ValueError(f"rule glob matches no file: {glob}")
                else:
                    if not isinstance(data.get("name"), str) or not isinstance(data.get("description"), str):
                        raise ValueError("name and description must be strings")
                    if path.name == "SKILL.md" and path.parent.name != data["name"]:
                        raise ValueError("skill name must match its directory")
                    if "/agents/" in path.as_posix() and data.get("model") not in {"haiku", "sonnet", "opus", "inherit"}:
                        raise ValueError("unapproved agent model alias")
            except (ValueError, OSError) as error:
                errors.append(f"{path.relative_to(root)}: {error}")
    for path in (root / "tools/agent-config/codex/agents").glob("*.toml"):
        try:
            data = tomllib.loads(path.read_text())
            for key in ("name", "description", "developer_instructions"):
                if not isinstance(data.get(key), str) or not data[key]:
                    raise ValueError(f"missing {key}")
            if data["name"] != path.stem:
                raise ValueError("agent name must match filename")
        except ValueError as error:
            errors.append(f"{path.relative_to(root)}: {error}")
    settings_path = root / ".claude/settings.json"
    if settings_path.exists():
        settings = json.loads(settings_path.read_text())
        for groups in settings.get("hooks", {}).values():
            for group in groups:
                for hook in group.get("hooks", []):
                    for reference in re.findall(r"scripts/[A-Za-z0-9_./-]+", hook["command"]):
                        if not (root / reference).is_file():
                            errors.append(f"hook target missing: {reference}")
    catalogue_path = root / "docs/ops/catalogue.json"
    if catalogue_path.exists():
        catalogue = json.loads(catalogue_path.read_text())
        recorded = [entry["path"] for entry in catalogue]
        actual = {p.relative_to(root).as_posix() for p in (root / "scripts").iterdir() if p.is_file() and p.suffix in {".py", ".sh"}}
        if len(recorded) != len(set(recorded)) or set(recorded) != actual:
            errors.append("operation catalogue differs from scripts on disk")
        for entry in catalogue:
            if any(key not in entry for key in ("purpose", "reads", "writes", "executionFlag", "paidModel", "credentials")):
                errors.append(f"incomplete operation catalogue: {entry['path']}")
    elif internal_setup:
        errors.append("missing operation catalogue")
    issues_path = root / "planning/github/issues.json"
    if issues_path.exists():
        issues = json.loads(issues_path.read_text())
        ids = [issue["id"] for issue in issues]
        if len(ids) != len(set(ids)):
            errors.append("duplicate roadmap issue IDs")
        for issue in issues:
            if not issue.get("acceptance") or any(dep not in ids for dep in issue.get("dependsOn", [])):
                errors.append(f"incomplete roadmap issue {issue['id']}")
    if publication:
        errors += publication_errors(root)
    return errors


def publication_errors(root):
    """Check the public files that outside readers rely on; remote settings need a live check."""
    def text(name):
        path = root / name
        return path.read_text() if path.is_file() else ""

    errors = []
    module = re.search(r"^module github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)$", text("go.mod"), re.M)
    if not module:
        errors.append("publication prerequisite missing: module path github.com/OWNER/REPO in go.mod")
    elif f"https://github.com/{module[1]}/security/advisories/new" not in text("SECURITY.md"):
        errors.append("publication prerequisite missing: private vulnerability reporting link in SECURITY.md")
    contact = re.compile(r"https://\S+|[\w.+-]+@[\w-]+\.[\w.-]+")
    if not any("report" in part.lower() and contact.search(part) for part in text("CODE_OF_CONDUCT.md").split("\n\n")):
        errors.append("publication prerequisite missing: private reporting contact in CODE_OF_CONDUCT.md")
    if not (root / ".github/CODEOWNERS").is_file():
        errors.append("publication prerequisite missing: .github/CODEOWNERS")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publication", action="store_true", help="also require the public repository module path and private reporting contacts")
    args = parser.parse_args()
    errors = check(Path(__file__).resolve().parents[1], args.publication)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Repository and local links checked; internal setup validated when present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
