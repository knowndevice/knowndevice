# SPDX-License-Identifier: Apache-2.0
import contextlib
import datetime
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("vuln_check", ROOT / "scripts/vuln_check.py")
vuln = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vuln)

CONFIG = {"config": {"protocol_version": "v1.0.0", "scanner_name": "govulncheck", "scan_level": "symbol"}}
HEADER = "# Exceptions\n\n## Accepted findings\n\n| ID | Package | Reason | Reviewed |\n| --- | --- | --- | --- |\n"


def finding(osv, module, package=None, function=None):
    frame = {"module": module, "version": "v1.0.0"}
    if package:
        frame["package"] = package
    if function:
        frame["function"] = function
    return {"finding": {"osv": osv, "fixed_version": "v1.0.1", "trace": [frame]}}


def stream(*messages):
    # govulncheck writes indented objects back to back, not JSON lines.
    return "".join(json.dumps(message, indent=2) + "\n" for message in messages)


class VulnerabilityCheckTests(unittest.TestCase):
    def write(self, directory, text):
        path = Path(directory) / "exceptions.md"
        path.write_text(text)
        return path

    def run_main(self, directory, output, exceptions=HEADER):
        saved = Path(directory) / "scan.json"
        saved.write_text(output)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = vuln.main(["--input", str(saved), "--exceptions", str(self.write(directory, exceptions))])
        return code, out.getvalue(), err.getvalue()

    def test_only_called_symbols_fail(self):
        messages = vuln.parse_stream(stream(
            CONFIG,
            {"osv": {"id": "GO-2026-0001", "summary": "Panic in parser"}},
            finding("GO-2026-0001", "example.com/m"),
            finding("GO-2026-0001", "example.com/m", "example.com/m/parse"),
            finding("GO-2026-0001", "example.com/m", "example.com/m/parse", "Parse"),
            finding("GO-2026-0002", "example.com/other", "example.com/other/unused"),
        ))
        self.assertEqual(vuln.called_findings(messages), {("GO-2026-0001", "example.com/m/parse"): "v1.0.1"})

    def test_unaccepted_finding_fails_and_names_the_package(self):
        with tempfile.TemporaryDirectory() as directory:
            code, _, err = self.run_main(directory, stream(CONFIG, {"osv": {"id": "GO-2026-0001", "summary": "Panic"}}, finding("GO-2026-0001", "stdlib", "net/http", "Get")))
            self.assertEqual(code, 1)
            self.assertIn("FINDING GO-2026-0001 in net/http (fixed in v1.0.1): Panic", err)

    def test_exception_covers_only_its_package(self):
        output = stream(CONFIG, finding("GO-2026-0001", "stdlib", "net/http", "Get"), finding("GO-2026-0001", "stdlib", "net/url", "Parse"))
        today = vuln.utc_today().isoformat()
        with tempfile.TemporaryDirectory() as directory:
            code, out, err = self.run_main(directory, output, HEADER + f"| GO-2026-0001 | `net/http` | Client never follows untrusted redirects. | {today} |\n")
            self.assertEqual(code, 1)
            self.assertIn("accepted GO-2026-0001 in net/http", out)
            self.assertIn("FINDING GO-2026-0001 in net/url", err)
            code, out, _ = self.run_main(directory, output, HEADER + f"| GO-2026-0001 | net/http | Reviewed. | {today} |\n| GO-2026-0001 | net/url | Reviewed. | {today} |\n")
            self.assertEqual(code, 0)

    def test_stale_exception_is_reported_without_failing(self):
        with tempfile.TemporaryDirectory() as directory:
            reviewed = (vuln.utc_today() - datetime.timedelta(days=10)).isoformat()
            code, out, _ = self.run_main(directory, stream(CONFIG), HEADER + f"| GO-2026-0009 | net/http | Reviewed. | {reviewed} |\n")
            self.assertEqual(code, 0)
            self.assertIn("GO-2026-0009 for net/http matches no current finding", out)

    def test_review_older_than_90_days_is_rejected_with_its_id(self):
        today = datetime.date(2026, 6, 1)
        with tempfile.TemporaryDirectory() as directory:
            row = "| GO-2026-0001 | net/http | Reviewed. | {} |\n"
            self.assertIn(("GO-2026-0001", "net/http"), vuln.load_exceptions(self.write(directory, HEADER + row.format("2026-03-03")), today))
            with self.assertRaisesRegex(vuln.CheckError, "GO-2026-0001 was reviewed on 2026-03-02, more than 90 days ago"):
                vuln.load_exceptions(self.write(directory, HEADER + row.format("2026-03-02")), today)
            stale = HEADER + row.format((vuln.utc_today() - datetime.timedelta(days=91)).isoformat())
            code, _, err = self.run_main(directory, stream(CONFIG, finding("GO-2026-0001", "stdlib", "net/http", "Get")), stale)
            self.assertEqual(code, 2)
            self.assertIn("GO-2026-0001", err)

    def test_rows_in_comments_and_code_fences_are_ignored(self):
        today = datetime.date(2026, 6, 1)
        text = HEADER + (
            "<!--\n| GO-2026-0001 | net/http | Hidden. | 2026-05-30 |\n-->\n"
            "```\n| GO-2026-0002 | net/http | Example. | 2026-05-30 |\n```\n"
            "~~~~md\n| not a row\n~~~~\n"
            "| GO-2026-0003 | net/url | Visible. | 2026-05-30 | <!-- note -->\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(set(vuln.load_exceptions(self.write(directory, text), today)), {("GO-2026-0003", "net/url")})

    def test_malformed_scan_output_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            for output in (
                "",
                '{"progress": {"message": "x"}}',
                '{"config": {}} {broken',
                '{"config": {}} []',
                '{"config": {}} "text"',
                '{"config": {}} {"finding": {"osv": "GO-2026-0001"}}',
                '{"config": {}} {"finding": {"osv": "GO-2026-0001", "trace": []}}',
                '{"config": {}} {"finding": {"trace": [{"function": "F"}]}}',
                '{"config": {}} {"finding": "GO-2026-0001"}',
            ):
                with self.subTest(output=output):
                    self.assertEqual(self.run_main(directory, output)[0], 2)

    def test_invalid_exception_lists_are_rejected(self):
        today = datetime.date(2026, 6, 1)
        cases = {
            "# Exceptions\n": "heading",
            "```\n## Accepted findings\n```\n": "heading",
            "## Accepted findings\n\n| ID | Package | Reason |\n| --- | --- | --- |\n": "columns",
            HEADER + "| CVE-2026-1 | net/http | Reviewed. | 2026-05-20 |\n": "Go vulnerability ID",
            HEADER + "| GO-2026-0001 | net/http |  | 2026-05-20 |\n": "reason",
            HEADER + "| GO-2026-0001 | net/http | Reviewed. | 5 Jan 2026 |\n": "YYYY-MM-DD",
            HEADER + "| GO-2026-0001 | net/http | Reviewed. | 20260520 |\n": "YYYY-MM-DD",
            HEADER + "| GO-2026-0001 | net/http | Reviewed. | 2026-07-01 |\n": "future",
            HEADER + "| GO-2026-0001 | net/http | A. | 2026-05-20 |\n| GO-2026-0001 | net/http | B. | 2026-05-20 |\n": "twice",
            HEADER + "| GO-2026-0001 | net/http | Reviewed. |\n": "cells",
        }
        with tempfile.TemporaryDirectory() as directory:
            for text, message in cases.items():
                with self.subTest(message=message):
                    with self.assertRaisesRegex(vuln.CheckError, message):
                        vuln.load_exceptions(self.write(directory, text), today)

    def test_published_exception_list_parses(self):
        vuln.load_exceptions(vuln.EXCEPTIONS)

    def test_missing_go_command_fails(self):
        with self.assertRaisesRegex(vuln.CheckError, "not installed"):
            vuln.run_govulncheck(ROOT, go="/nonexistent/go")

    def test_tool_version_is_pinned(self):
        self.assertRegex(vuln.GOVULNCHECK, r"@v\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
