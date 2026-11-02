# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PINNED = "go" + (ROOT / ".go-version").read_text().strip()
STUB_GO = """#!/bin/sh
echo "$*" >> "{calls}"
case "$*" in
  "env GOVERSION") echo {version} ;;
  "env GOROOT") echo /stub/goroot ;;
  *) echo "unexpected go call: $*" >&2; exit 99 ;;
esac
"""


@unittest.skipUnless(shutil.which("bash"), "bash is required")
class GateToolchainTests(unittest.TestCase):
    def run_audit(self, version):
        """Run the audit gates with a stub go and a PATH that holds only the tools the gate needs."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        work = Path(directory.name)
        tools = work / "bin"
        tools.mkdir()
        for name in ("dirname", "tr", "mkdir", "tail"):
            os.symlink(shutil.which(name), tools / name)
        calls = work / "go-calls"
        (tools / "go").write_text(STUB_GO.format(calls=calls, version=version))
        (tools / "go").chmod(0o755)
        env = {
            "PATH": str(tools),
            "HOME": str(work),
            "KNOWNDEVICE_PYTHON": sys.executable,
            "KNOWNDEVICE_CHECK_DIR": str(work / "checks"),
            "KNOWNDEVICE_BIN_DIR": str(work / "out"),
            "GOCACHE": str(work / "go-build"),
            "GOMODCACHE": str(work / "go-mod"),
        }
        result = subprocess.run([shutil.which("bash"), str(ROOT / "scripts/ci_local.sh"), "audit"], env=env, capture_output=True, text=True, timeout=60)
        return result, calls.read_text().split("\n") if calls.exists() else []

    def test_other_go_version_fails_before_any_network_step(self):
        result, calls = self.run_audit("go1.27.2")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("FAIL go-toolchain", result.stderr)
        self.assertIn(f"go go1.27.2 from /stub/goroot; .go-version requires {PINNED}", result.stderr)
        self.assertNotIn("workflows", result.stdout + result.stderr)
        self.assertFalse(any(call.startswith("run") for call in calls), calls)

    def test_workflow_gate_requires_shellcheck_before_go_run(self):
        result, calls = self.run_audit(PINNED)
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertIn("PASS go-toolchain", result.stdout)
        self.assertIn("shellcheck is required on PATH", result.stderr)
        self.assertFalse(any(call.startswith("run") for call in calls), calls)


if __name__ == "__main__":
    unittest.main()
