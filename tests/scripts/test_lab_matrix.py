# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/lab_matrix.sh"

FAKE_DOCKER = """#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
  info)
    case "$*" in
      *SecurityOptions*) echo '["name=seccomp"]' ;;
      *Architecture*) echo x86_64 ;;
      *OperatingSystem*) echo 'Fake OS' ;;
    esac ;;
  compose)
    case "$*" in
      *" run "*) printf 'PASS first\\nPASS second\\n'; exit "${FAKE_CHECKS_EXIT:-0}" ;;
      *" down") echo "down attempt"; exit "${FAKE_DOWN_EXIT:-0}" ;;
    esac ;;
  ps) printf 'kd-left-checks-1\\nunrelated\\n' ;;
  network) printf 'bridge\\nkd-left_default\\n' ;;
esac
"""

FAKE_GO = """#!/bin/sh
echo "fake go build output"
[ "${FAKE_GO_EXIT:-0}" -eq 0 ] || exit "$FAKE_GO_EXIT"
while [ $# -gt 0 ]; do
  case "$1" in -o) : > "$2"; shift ;; esac
  shift
done
"""

FAKE_ADAPTERGEN = """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in --root) root="$2"; shift ;; --dir) dir="$2"; shift ;; esac
  shift
done
mkdir -p "$root/$dir/scripts"
printf '#!/bin/sh\\necho generated checks ran\\nexit %s\\n' "$FAKE_CI_EXIT" > "$root/$dir/scripts/ci.sh"
chmod +x "$root/$dir/scripts/ci.sh"
"""

FAKE_SEED = """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in --dir) mkdir -p "$2/artifacts"; shift ;; esac
  shift
done
"""

CELLS = [
    "legacy-reference-builtin-linux-amd64",
    "reference-generation-cn-builtin-linux-amd64",
    "stable-device-cn-builtin-linux-amd64",
    "reference-generation-cn-generated-process-linux-amd64",
    "stable-device-cn-generated-process-linux-amd64",
]


def executable(path, text):
    path.write_text(text)
    path.chmod(0o755)


class LabMatrixTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)
        fake = self.tmp / "path"
        bin_dir = self.tmp / "bin"
        fake.mkdir()
        bin_dir.mkdir()
        executable(fake / "docker", FAKE_DOCKER)
        executable(fake / "go", FAKE_GO)
        executable(bin_dir / "kd-adaptergen", FAKE_ADAPTERGEN)
        executable(bin_dir / "kd-reference", FAKE_SEED)
        executable(bin_dir / "kd-profilelab", FAKE_SEED)
        for name in ("knowndevice", "kd-reference", "kd-profilelab", "kd-adapter"):
            executable(bin_dir / f"{name}-linux-amd64", "#!/bin/sh\n")
        self.matrix = self.tmp / "matrix"
        self.docker_log = self.tmp / "docker.log"
        self.env = {key: value for key, value in os.environ.items() if not key.startswith(("KNOWNDEVICE_", "FAKE_"))}
        self.env.update(
            PATH=f"{fake}{os.pathsep}{os.environ['PATH']}",
            KNOWNDEVICE_BIN_DIR=str(bin_dir),
            KNOWNDEVICE_MATRIX_DIR=str(self.matrix),
            FAKE_DOCKER_LOG=str(self.docker_log),
            FAKE_CI_EXIT="0",
            GOCACHE=str(self.tmp / "go-build"),
            GOMODCACHE=str(self.tmp / "go-mod"),
        )

    def run_matrix(self, *args, script=SCRIPT, **env):
        return subprocess.run(["bash", str(script), *args], cwd=ROOT, env={**self.env, **env}, capture_output=True, text=True, timeout=120)

    def summary(self):
        return (self.matrix / "summary.txt").read_text().splitlines()

    def results(self):
        return [line for line in self.summary() if line.startswith(("PASS ", "FAIL ", "SKIP "))]

    def docker_calls(self):
        return self.docker_log.read_text().splitlines() if self.docker_log.exists() else []

    def assert_closing_lines(self, lines):
        self.assertRegex(lines[3], r"^load at start: \S")
        self.assertTrue(any(line.startswith("load at end: ") and line != "load at end: " for line in lines))
        self.assertIn("kd-* containers after run: kd-left-checks-1", lines)
        self.assertIn("kd-* networks after run: kd-left_default", lines)
        self.assertTrue(lines[-1].startswith("finished: "))
        self.assertFalse(any("unrecorded step" in line for line in lines))
        listing = [call for call in self.docker_calls() if call.split()[0] in ("ps", "network")]
        self.assertEqual(listing, ["ps -a --format {{.Names}}", "network ls --format {{.Name}}"])

    def test_generated_ci_failure_records_fail_line_and_exit_code(self):
        result = self.run_matrix("amd64", FAKE_CI_EXIT="7")
        self.assertEqual(result.returncode, 7, result.stderr)
        results = self.results()
        self.assertEqual(results[:-1], ["PASS preflight (exit 0)", "PASS artifacts (exit 0)", "PASS adaptergen (exit 0)"])
        self.assertTrue(results[-1].startswith("FAIL generated-ci (exit 7); logs: "))
        self.assertIn("FAIL generated-ci (exit 7)", result.stderr)
        self.assertIn("generated checks ran", result.stderr)
        self.assertIn("Matrix failed; data and logs: ", result.stderr)
        self.assertNotIn("Matrix passed", result.stdout)
        self.assertFalse(any(call.startswith("compose") for call in self.docker_calls()))
        self.assert_closing_lines(self.summary())

    def test_generated_build_failure_records_fail_line_and_exit_code(self):
        result = self.run_matrix("amd64", FAKE_GO_EXIT="4")
        self.assertEqual(result.returncode, 4, result.stderr)
        results = self.results()
        self.assertIn("PASS generated-ci (exit 0)", results)
        self.assertTrue(results[-1].startswith("FAIL generated-build (exit 4); logs: "))
        self.assertIn("fake go build output", result.stderr)
        self.assert_closing_lines(self.summary())

    def test_all_cells_pass_with_one_argument(self):
        result = self.run_matrix("amd64")
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = ["PASS preflight (exit 0)", "PASS artifacts (exit 0)", "PASS adaptergen (exit 0)",
                    "PASS generated-ci (exit 0)", "PASS generated-build (exit 0)"]
        for cell in CELLS:
            expected += [f"PASS {cell} seed (exit 0)", f"PASS {cell} (exit 0, 2 checks)"]
        self.assertEqual(self.results(), expected)
        self.assertIn("cells: all", self.summary())
        self.assertEqual(result.stdout.splitlines()[:-1], expected)
        self.assertTrue(result.stdout.splitlines()[-1].startswith("Matrix passed; data and logs: "))
        downs = [call for call in self.docker_calls() if call.startswith("compose") and call.endswith(" down")]
        self.assertEqual(len(downs), len(CELLS))
        self.assert_closing_lines(self.summary())

    def test_one_cell_skips_the_generated_adapter(self):
        result = self.run_matrix("--cell", "legacy-reference-builtin", "amd64")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = self.summary()
        self.assertIn("cells: legacy-reference-builtin", lines)
        for step in ("adaptergen", "generated-ci", "generated-build"):
            self.assertIn(f"SKIP {step} (no selected cell uses the generated adapter)", lines)
        self.assertIn("PASS legacy-reference-builtin-linux-amd64 seed (exit 0)", lines)
        self.assertIn("PASS legacy-reference-builtin-linux-amd64 (exit 0, 2 checks)", lines)
        self.assertFalse(any("-cn-" in line for line in lines))
        self.assertFalse((self.matrix / "generated").exists())
        self.assertTrue(result.stdout.splitlines()[-1].startswith("Matrix passed; data and logs: "))
        compose = [call for call in self.docker_calls() if call.startswith("compose")]
        self.assertEqual([call.split()[-1] for call in compose if call.split()[-1] in ("-d", "checks", "down")], ["-d", "checks", "down"])
        self.assertTrue(all("lab/compose.yaml" in call for call in compose))
        self.assert_closing_lines(lines)

    def test_cell_failure_stops_its_project_and_records_exit_code(self):
        result = self.run_matrix("--cell=stable-device-cn-builtin", "amd64", FAKE_CHECKS_EXIT="3")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertTrue(self.results()[-1].startswith("FAIL stable-device-cn-builtin-linux-amd64 (exit 3); logs: "))
        self.assertTrue(any(call.startswith("compose") and call.endswith(" down") for call in self.docker_calls()))
        self.assert_closing_lines(self.summary())

    def test_failed_compose_down_is_recorded_and_retried(self):
        result = self.run_matrix("--cell", "legacy-reference-builtin", "amd64", FAKE_DOWN_EXIT="5")
        self.assertEqual(result.returncode, 5, result.stderr)
        results = self.results()
        self.assertFalse(any(line.startswith("PASS legacy-reference-builtin-linux-amd64 (") for line in results))
        self.assertTrue(results[-2].startswith("FAIL legacy-reference-builtin-linux-amd64 cleanup (exit 5); logs: "))
        self.assertRegex(results[-1], r"^FAIL kd-legacy-reference-builtin-linux-amd64-\S+ cleanup at exit \(exit 5\)$")
        downs = [call for call in self.docker_calls() if call.startswith("compose") and call.endswith(" down")]
        self.assertEqual(len(downs), 2)
        (down_log,) = (self.matrix / "logs").glob("kd-legacy-reference-builtin-*-down.log")
        self.assertEqual(down_log.read_text().splitlines(), ["down attempt", "down attempt"])
        self.assert_closing_lines(self.summary())

    def test_repository_without_commits_reports_unknown_commit(self):
        copy = self.tmp / "repository"
        (copy / "scripts").mkdir(parents=True)
        shutil.copy(SCRIPT, copy / "scripts/lab_matrix.sh")
        subprocess.run(["git", "init", "-q", str(copy)], check=True)
        result = self.run_matrix("--cell", "legacy-reference-builtin", "amd64", script=copy / "scripts/lab_matrix.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.summary()[0], "commit: unknown")

    def test_unknown_or_empty_cell_is_a_usage_error(self):
        for args in (["--cell", "stable-device-cn"], ["--cell", ""], ["--cell="], ["--cell"]):
            with self.subTest(args=args):
                result = self.run_matrix(*args, "amd64")
                self.assertEqual(result.returncode, 2)
                self.assertIn("Cells: legacy-reference-builtin reference-generation-cn-builtin", result.stderr)
                self.assertFalse(self.matrix.exists())
                self.assertEqual(self.docker_calls(), [])
        self.assertIn("Unknown cell: stable-device-cn", self.run_matrix("--cell", "stable-device-cn", "amd64").stderr)


if __name__ == "__main__":
    unittest.main()
