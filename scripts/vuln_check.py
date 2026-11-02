#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the pinned govulncheck over ./... and fail on findings that are not accepted.

A finding counts when govulncheck reports that the code calls an affected
symbol, the same rule its text output uses for a failing exit. Accepted
exceptions live in docs/security/vulnerability-exceptions.md and expire 90
days after their review date (UTC). The scan needs network access to the Go
module proxy, checksum database and vuln.go.dev. Read-only apart from the Go
build and module caches. Exit codes: 0 no unaccepted finding, 1 unaccepted
finding, 2 scan error, malformed scan output or invalid exception list.
"""

import argparse
import datetime
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GOVULNCHECK = "golang.org/x/vuln/cmd/govulncheck@v1.9.0"
EXCEPTIONS = ROOT / "docs/security/vulnerability-exceptions.md"
HEADING = "## Accepted findings"
COLUMNS = ["ID", "Package", "Reason", "Reviewed"]
ID_PATTERN = re.compile(r"GO-\d{4}-\d{4,}")
MAX_REVIEW_AGE = datetime.timedelta(days=90)


class CheckError(Exception):
    pass


def utc_today():
    return datetime.datetime.now(datetime.timezone.utc).date()


def parse_stream(text):
    """Decode govulncheck's JSON output, a sequence of concatenated JSON objects."""
    decoder = json.JSONDecoder()
    messages, index = [], 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            break
        try:
            message, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError as error:
            raise CheckError(f"govulncheck output is not JSON: {error}") from error
        if not isinstance(message, dict):
            raise CheckError(f"govulncheck output holds a {type(message).__name__} where an object belongs")
        messages.append(message)
    if not any("config" in message for message in messages):
        raise CheckError("govulncheck output has no config message; the scan did not run")
    return messages


def called_findings(messages):
    """Return {(id, package): fixed_version} for findings whose trace reaches a called function."""
    found = {}
    for message in messages:
        if "finding" not in message:
            continue
        finding = message["finding"]
        trace = finding.get("trace") if isinstance(finding, dict) else None
        if not isinstance(trace, list) or not trace or not all(isinstance(frame, dict) for frame in trace) or not isinstance(finding.get("osv"), str):
            raise CheckError(f"govulncheck finding has no OSV ID or trace: {json.dumps(finding)[:200]}")
        frame = trace[0]
        if frame.get("function"):
            found[(finding["osv"], frame.get("package") or frame.get("module", ""))] = finding.get("fixed_version", "")
    return found


def summaries(messages):
    return {message["osv"].get("id"): message["osv"].get("summary", "") for message in messages if isinstance(message.get("osv"), dict)}


def visible_lines(text):
    """Return Markdown lines outside HTML comments and fenced code blocks."""
    text = re.sub(r"<!--.*?(?:-->|\Z)", "", text, flags=re.S)
    lines, fence = [], None
    for line in text.splitlines():
        marker = re.match(r"\s{0,3}(`{3,}|~{3,})", line)
        if fence:
            if marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence):
                fence = None
            continue
        if marker:
            fence = marker[1]
            continue
        lines.append(line)
    return lines


def load_exceptions(path, today=None):
    """Parse the accepted-findings table; return {(id, package): reviewed date}."""
    today = today or utc_today()
    try:
        lines = visible_lines(path.read_text())
    except OSError as error:
        raise CheckError(f"cannot read {path}: {error.strerror}") from error
    if HEADING not in lines:
        raise CheckError(f"{path}: missing '{HEADING}' heading")
    rows = []
    for line in lines[lines.index(HEADING) + 1:]:
        if line.startswith("#"):
            break
        if line.startswith("|"):
            rows.append([cell.strip() for cell in line.strip().strip("|").split("|")])
    if len(rows) < 2 or rows[0] != COLUMNS or not all(re.fullmatch(r":?-+:?", cell) for cell in rows[1]):
        raise CheckError(f"{path}: the table under '{HEADING}' needs the columns {' | '.join(COLUMNS)}")
    accepted = {}
    for row in rows[2:]:
        if len(row) != len(COLUMNS):
            raise CheckError(f"{path}: row needs {len(COLUMNS)} cells: {' | '.join(row)}")
        osv, package, reason, reviewed = (cell.strip("`") if i < 2 else cell for i, cell in enumerate(row))
        if not ID_PATTERN.fullmatch(osv):
            raise CheckError(f"{path}: {osv!r} is not a Go vulnerability ID such as GO-2024-1234")
        if not package or not reason:
            raise CheckError(f"{path}: {osv} needs an affected package and a reason")
        try:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", reviewed):
                raise ValueError(reviewed)
            date = datetime.date.fromisoformat(reviewed)
        except ValueError as error:
            raise CheckError(f"{path}: {osv} review date {reviewed!r} is not YYYY-MM-DD") from error
        if date > today:
            raise CheckError(f"{path}: {osv} review date {reviewed} is in the future (UTC)")
        if today - date > MAX_REVIEW_AGE:
            raise CheckError(f"{path}: {osv} was reviewed on {reviewed}, more than {MAX_REVIEW_AGE.days} days ago; review it again and update the date or remove the row")
        if (osv, package) in accepted:
            raise CheckError(f"{path}: {osv} for {package} is listed twice")
        accepted[(osv, package)] = reviewed
    return accepted


def run_govulncheck(root, go="go"):
    try:
        result = subprocess.run([go, "run", GOVULNCHECK, "-format", "json", "./..."], cwd=root, capture_output=True, text=True, check=False)
    except FileNotFoundError as error:
        raise CheckError(f"{go} is not installed or not on PATH") from error
    if result.returncode:
        raise CheckError(f"govulncheck exited with {result.returncode}:\n{result.stderr.strip()}")
    return result.stdout


def report(found, titles, accepted):
    """Print the outcome and return the number of unaccepted findings."""
    failures = 0
    for (osv, package), fixed in sorted(found.items()):
        fix = f"fixed in {fixed}" if fixed else "no fixed version"
        if (osv, package) in accepted:
            print(f"accepted {osv} in {package} ({fix}; reviewed {accepted[osv, package]})")
        else:
            failures += 1
            title = f": {titles[osv]}" if titles.get(osv) else ""
            print(f"FINDING {osv} in {package} ({fix}){title}", file=sys.stderr)
    for osv, package in sorted(set(accepted) - set(found)):
        print(f"note: exception {osv} for {package} matches no current finding; remove it")
    if failures:
        print(f"{failures} unaccepted vulnerability finding(s); update the dependency or Go version, or record a reviewed exception in {EXCEPTIONS.relative_to(ROOT)}", file=sys.stderr)
    else:
        print(f"govulncheck: no unaccepted findings ({len(found)} called, {len(accepted)} exception(s) listed)")
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, help="read saved 'govulncheck -format json' output instead of running the scan")
    parser.add_argument("--exceptions", type=Path, default=EXCEPTIONS, help="accepted-findings list (default: %(default)s)")
    args = parser.parse_args(argv)
    try:
        accepted = load_exceptions(args.exceptions)
        messages = parse_stream(args.input.read_text() if args.input else run_govulncheck(ROOT))
        found, titles = called_findings(messages), summaries(messages)
    except (CheckError, OSError, UnicodeDecodeError) as error:
        print(f"vulnerability check: {error}", file=sys.stderr)
        return 2
    return 1 if report(found, titles, accepted) else 0


if __name__ == "__main__":
    sys.exit(main())
