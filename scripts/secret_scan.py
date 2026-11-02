#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Scan files for secret markers before they leave the machine as CI artifacts.

Reports only file names and marker names, never the matched text. Exit codes:
0 no marker found; 1 a marker, symbolic link, special file, unreadable file or
unlistable directory found; 2 usage error or missing path.
"""

import argparse
import os
from pathlib import Path
import re
import stat
import sys

MARKERS = (
    ("pem-private-key", re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("private-key-text", re.compile(rb"PRIVATE KEY")),
    # Base64 DER prefixes of unarmoured keys: PKCS#8 P-256, SEC1 P-256, PKCS#8 RSA-2048.
    ("der-private-key-base64", re.compile(rb"MIGHAgEAMBMGByqGSM49|MHcCAQEE|MIIEv[Qg]IBADANBgkqhkiG9w0BAQEFAASC")),
    ("jwk-private-member", re.compile(rb'\\?"(?:d|p|q|dp|dq|qi|k)\\?"\s*:\s*\\?"[A-Za-z0-9_-]{16,}')),
    ("github-token", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("aws-access-key-id", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(rb"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("bearer-token", re.compile(rb"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
)


def candidates(path, found):
    """Yield entries under path without following symbolic links; record unlistable directories."""
    if path.is_symlink() or not path.is_dir():
        yield path
        return

    def unlistable(error):
        found.append((Path(error.filename), f"directory cannot be listed ({error.strerror})"))

    for directory, dirs, names in os.walk(path, onerror=unlistable, followlinks=False):
        for name in sorted(dirs):
            if (Path(directory) / name).is_symlink():
                yield Path(directory) / name
        for name in sorted(names):
            yield Path(directory) / name


def problems(paths, files=()):
    """Return (file, reason) pairs; a reason names a marker or condition, never content.

    Entries in files are checked as single paths, so a directory there is not a regular file.
    """
    found = []
    entries = [entry for root in paths for entry in candidates(root, found)] + list(files)
    for path in entries:
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            found.append((path, f"cannot be inspected ({error.strerror})"))
            continue
        if stat.S_ISLNK(mode):
            found.append((path, "symbolic link (not followed)"))
            continue
        if not stat.S_ISREG(mode):
            found.append((path, "not a regular file"))
            continue
        try:
            data = path.read_bytes()
        except OSError as error:
            found.append((path, f"unreadable ({error.strerror})"))
            continue
        for name, pattern in MARKERS:
            if pattern.search(data):
                found.append((path, name))
                break
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", type=Path, help="files or directories that must exist; directories are scanned recursively")
    parser.add_argument("--file", action="append", default=[], type=Path, metavar="PATH", help="a path that must be a regular file if it exists; skipped when absent (repeatable)")
    args = parser.parse_args(argv)
    missing = [str(path) for path in args.paths if not path.is_symlink() and not path.exists()]
    if missing:
        print(f"secret scan: path does not exist: {', '.join(missing)}", file=sys.stderr)
        return 2
    files = []
    for path in args.file:
        if path.is_symlink() or path.exists():
            files.append(path)
        else:
            print(f"secret scan: {path} does not exist; skipped")
    if not args.paths and not files:
        print("secret scan: nothing to scan", file=sys.stderr)
        return 2
    found = problems(args.paths, files)
    for path, reason in found:
        print(f"secret scan: {path}: {reason}", file=sys.stderr)
    if found:
        print(f"secret scan: {len(found)} path(s) blocked; nothing may be uploaded", file=sys.stderr)
        return 1
    print("secret scan: no secret markers found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
