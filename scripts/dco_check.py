#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Require a Signed-off-by trailer on every non-merge commit in BASE..HEAD.

Merge commits are skipped and the sign-off is not compared with the commit
author. Read-only. Exit codes: 0 every commit is signed off, 1 a commit lacks
a valid trailer, 2 the range, git or its output cannot be read.
"""

import argparse
from pathlib import Path
import re
import subprocess
import sys

SIGN_OFF = re.compile(r"[^<>\n]*\S <[^<>\s@]+@[^<>\s]+>")
OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# Commit messages cannot hold NUL bytes, so NUL separates fields and, with -z, commits.
FORMAT = "%H%x00%(trailers:key=Signed-off-by,valueonly,unfold,separator=%x1e)%x00%s"


class GitError(Exception):
    pass


def commits(repo, base, head):
    """Return (sha, subject, sign-offs) for non-merge commits reachable from head but not base."""
    if base.startswith("-") or head.startswith("-"):
        raise GitError("a revision must not start with '-'")
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "log", "-z", "--no-merges", f"--format={FORMAT}", f"{base}..{head}", "--"],
            capture_output=True, check=False,
        )
    except FileNotFoundError as error:
        raise GitError("git is not installed or not on PATH") from error
    if result.returncode:
        raise GitError(result.stderr.decode("utf-8", "replace").strip() or f"git log exited with {result.returncode}")
    output = result.stdout.decode("utf-8", "replace")
    if not output:
        return []
    fields = (output[:-1] if output.endswith("\0") else output).split("\0")
    if len(fields) % 3 or not all(OBJECT_ID.fullmatch(sha) for sha in fields[0::3]):
        raise GitError("unexpected git log output")
    return [
        (sha, subject, [value.strip() for value in trailers.split("\x1e") if value.strip()])
        for sha, trailers, subject in zip(fields[0::3], fields[1::3], fields[2::3])
    ]


def unsigned(entries):
    return [(sha, subject) for sha, subject, sign_offs in entries if not any(SIGN_OFF.fullmatch(value) for value in sign_offs)]


def printable(text):
    """Replace control characters so a commit subject cannot inject terminal or CI log commands."""
    return "".join(char if char.isprintable() else "?" for char in text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", required=True, help="revision the pull request targets, for example the base commit SHA")
    parser.add_argument("--head", required=True, help="last commit of the pull request")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="git repository to read (default: current directory)")
    args = parser.parse_args(argv)
    try:
        entries = commits(args.repo, args.base, args.head)
    except GitError as error:
        print(f"dco: cannot read {args.base}..{args.head}: {error}", file=sys.stderr)
        return 2
    missing = unsigned(entries)
    for sha, subject in missing:
        print(f"dco: {sha[:12]} {printable(subject)}: no 'Signed-off-by: Name <email>' trailer", file=sys.stderr)
    if missing:
        print(f"dco: {len(missing)} of {len(entries)} commit(s) lack a sign-off; amend them with 'git commit --amend -s' or 'git rebase --signoff {args.base}'", file=sys.stderr)
        return 1
    print(f"dco: {len(entries)} non-merge commit(s) in {args.base}..{args.head} are signed off")
    return 0


if __name__ == "__main__":
    sys.exit(main())
