# SPDX-License-Identifier: Apache-2.0
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("race_timing", ROOT / "scripts/race_timing.py")
timing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timing)

MODULE = "example.invalid/project"


def event(action, package="pkg", test=None, **fields):
    value = {"Action": action, "Package": f"{MODULE}/{package}"}
    if test:
        value["Test"] = test
    value.update(fields)
    return json.dumps(value)


EVENTS = [
    event("start"),
    event("run", test="TestFast"),
    event("pass", test="TestFast", Elapsed=0.01),
    event("run", test="TestFast"),
    event("pass", test="TestFast", Elapsed=0.03),
    event("run", test="TestSlow"),
    event("output", test="TestSlow", Output="=== RUN   TestSlow\n"),
    event("output", test="TestSlow", Output="    slow_test.go:12: remote outcome unknown\n"),
    event("fail", test="TestSlow", Elapsed=1.25),
    event("run", test="TestSlow/sub"),
    event("skip", test="TestSlow/sub", Elapsed=0),
    event("fail", Elapsed=2.5),
    json.dumps({"Action": "build-output", "ImportPath": f"{MODULE}/broken [{MODULE}/broken.test]", "Output": "broken.go:3: undefined: x\n"}),
    json.dumps({"Action": "build-fail", "ImportPath": f"{MODULE}/broken [{MODULE}/broken.test]"}),
    "not json",
]


class ParseTests(unittest.TestCase):
    def test_folds_repeated_runs_failures_and_build_output(self):
        summary = timing.parse_events(EVENTS, MODULE)
        self.assertEqual(summary["packages"], {"pkg": {"result": "fail", "elapsed": 2.5}})
        tests = {r["test"]: r for r in summary["tests"]}
        self.assertEqual((len(tests["TestFast"]["runs"]), tests["TestFast"]["min"], tests["TestFast"]["max"]), (2, 0.01, 0.03))
        self.assertAlmostEqual(tests["TestFast"]["median"], 0.02)
        self.assertEqual((tests["TestSlow"]["fails"], tests["TestSlow/sub"]["skips"], tests["TestSlow/sub"]["max"]), (1, 1, None))
        self.assertEqual(summary["failures"][0]["test"], "TestSlow")
        self.assertEqual(summary["failures"][0]["run"], 1)
        self.assertIn("remote outcome unknown", summary["failures"][0]["output"][-1])
        self.assertIn("undefined: x", summary["buildOutput"][f"broken [{MODULE}/broken.test]"][0])
        self.assertEqual(summary["nonJSONLines"], 1)

    def test_render_lists_watched_tests_missing_from_a_measured_package(self):
        lines = [event("run", "adapters/process", "TestOther"), event("pass", "adapters/process", "TestOther", Elapsed=0.1), event("pass", "adapters/process", Elapsed=0.2)]
        text = timing.render(timing.parse_events(lines, MODULE))
        self.assertIn("adapters/process TestBlockedServerOutputRespectsContext: not run", text)
        self.assertNotIn("internal/controller", text)
        self.assertIn("failures: 0", text)

    def test_summarize_exit_code_reflects_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("\n".join(EVENTS) + "\n")
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(timing.main(["summarize", str(path), "--module", MODULE]), 1)
            self.assertIn("pkg TestSlow run 1 after 1.25 s", printed.getvalue())
            path.write_text("\n".join(EVENTS[:5] + [event("pass", Elapsed=0.1)]) + "\n")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(timing.main(["summarize", str(path), "--module", MODULE, "--json"]), 0)


FAKE_GO = """#!/bin/sh
case "$1 $2" in
  "env GOVERSION") printf 'go1.27.3\\nlinux\\namd64\\n' ;;
  "list -m") echo example.invalid/project ;;
  *)
    case " $* " in
      *" -json "*) cat "$FAKE_EVENTS"; exit "$FAKE_EXIT" ;;
      *) exit 0 ;;
    esac ;;
esac
"""


class MeasureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        base = Path(self.directory.name)
        bin_dir = base / "bin"
        bin_dir.mkdir()
        go = bin_dir / "go"
        go.write_text(FAKE_GO)
        go.chmod(go.stat().st_mode | stat.S_IXUSR)
        events = base / "events.jsonl"
        events.write_text("\n".join(EVENTS[:12]) + "\n")
        self.out = base / "out"
        patch = mock.patch.dict(os.environ, {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_EVENTS": str(events), "FAKE_EXIT": "1"})
        patch.start()
        self.addCleanup(patch.stop)

    def test_run_writes_events_load_and_summary_and_returns_the_test_status(self):
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            status = timing.main(["run", "--out", str(self.out), "--count", "2", "--sample-seconds", "0.05", "./pkg"])
        self.assertEqual(status, 1)
        for name in ("events.jsonl", "stderr.txt", "load.tsv", "prebuild.log", "summary.json", "summary.txt"):
            self.assertTrue((self.out / name).is_file(), name)
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(summary["environment"]["command"], ["go", "test", "-race", "-json", "-count=2", "-timeout=60m", "./pkg"])
        self.assertEqual((summary["environment"]["exitCode"], summary["environment"]["goVersion"]), (1, "go1.27.3"))
        self.assertGreaterEqual(summary["load"]["samples"], 1)
        self.assertEqual(len(summary["failures"]), 1)
        self.assertIn("load (1-min): start", printed.getvalue())
        self.assertTrue((self.out / "load.tsv").read_text().startswith("unix_time\tload1\tload5\tload15\n"))

    def test_run_refuses_a_non_empty_output_directory(self):
        self.out.mkdir()
        (self.out / "keep.txt").write_text("previous result\n")
        with self.assertRaises(SystemExit):
            timing.main(["run", "--out", str(self.out)])
        self.assertEqual([path.name for path in self.out.iterdir()], ["keep.txt"])


if __name__ == "__main__":
    unittest.main()
