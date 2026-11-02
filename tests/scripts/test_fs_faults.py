# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/fs_faults.sh"
WORKFLOW = ROOT / ".github/workflows/quality.yml"

SKIP_REASON = "requires KD_FS_FAULT and an isolated Linux tmpfs or read-only bind mount"

# Container names carry the profile, suite and family, so a test selects one run
# with FAKE_<MODE>. The mount line and test names follow the arguments it receives.
FAKE_DOCKER = """#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
  info)
    [ "${FAKE_INFO_EXIT:-0}" -eq 0 ] || exit "$FAKE_INFO_EXIT"
    case "$*" in
      *SecurityOptions*) echo "${FAKE_SECURITY_OPTIONS:-[\\"name=seccomp\\"]}" ;;
      *Architecture*) echo "${FAKE_ARCH:-x86_64}" ;;
      *OperatingSystem*) echo 'Fake OS' ;;
      *KernelVersion*) echo '9.9.9-fake' ;;
    esac ;;
  ps)
    [ "${FAKE_PS_EXIT:-0}" -eq 0 ] || exit "$FAKE_PS_EXIT"
    printf 'kd-left-1\\nkd-fs-fault-enospc-tmpfs-journal-v1-20000101T000000Z-1\\nunrelated\\n'
    ls "$FAKE_DOCKER_LOG.containers" 2>/dev/null || true ;;
  rm)
    if [ -e "$FAKE_DOCKER_LOG.pid" ] && kill -0 "$(cat "$FAKE_DOCKER_LOG.pid")" 2>/dev/null; then
      echo "$3" >> "$FAKE_DOCKER_LOG.live"
    fi
    [ ! -e "$FAKE_DOCKER_LOG.containers/$3" ] || echo "$3" >> "$FAKE_DOCKER_LOG.existed"
    rm -f "$FAKE_DOCKER_LOG.containers/$3"
    : > "$FAKE_DOCKER_LOG.removed" ;;
  create)
    name=""
    previous=""
    for argument in "$@"; do
      [ "$previous" != --name ] || name="$argument"
      previous="$argument"
    done
    case "$name" in *"${FAKE_CREATE_EXIT_FOR:-no-such-container}"*)
      echo "fake create failure"
      exit 125 ;;
    esac
    case "$name" in *"${FAKE_SIGNAL_IN_CREATE:-no-such-container}"*)
      kill -TERM "$PPID"
      sleep 1 ;;
    esac
    mkdir -p "$FAKE_DOCKER_LOG.containers"
    : > "$FAKE_DOCKER_LOG.containers/$name"
    printf '%s\\n' "$@" > "$FAKE_DOCKER_LOG.args.$name"
    echo fake-container-id ;;
  start)
    name="$3"
    test=""
    fault=""
    mount=""
    previous=""
    while IFS= read -r argument; do
      case "$previous" in
        --tmpfs) case "$argument" in /fault:*) mount="tmpfs /fault tmpfs rw,nosuid,nodev,noexec,size=8192k 0 0" ;; esac ;;
        --mount) case "$argument" in
            *target=/fault,readonly) mount="/host /fault ext4 ro,relatime 0 0" ;;
            *target=/fault) mount="/host /fault ext4 rw,relatime 0 0" ;;
          esac ;;
        -test.run) test="${argument#^}"; test="${test%?}" ;;
        --env) case "$argument" in KD_FS_FAULT=*) fault="${argument#KD_FS_FAULT=}" ;; esac ;;
      esac
      previous="$argument"
    done < "$FAKE_DOCKER_LOG.args.$name"
    matches() { case "$name" in *"$1"*) [ -n "$1" ] ;; *) return 1 ;; esac; }
    # Models --rm: a container that exits is gone; a signalled client leaves it running.
    keep=""
    if matches "${FAKE_KEEP:-}"; then keep=1; fi
    trap '[ -n "$keep" ] || rm -f "$FAKE_DOCKER_LOG.containers/$name"' EXIT
    if matches "${FAKE_SIGNAL:-}"; then
      keep=1
      kill -TERM "$PPID"
      exit 143
    fi
    if matches "${FAKE_HANG:-}"; then
      keep=1
      trap '' HUP INT TERM
      echo $$ > "$FAKE_DOCKER_LOG.pid"
      waited=0
      while [ ! -e "$FAKE_DOCKER_LOG.removed" ] && [ "$waited" -lt 1500 ]; do
        sleep 0.1
        waited=$((waited + 1))
      done
      exit 137
    fi
    if matches "${FAKE_MOUNT_FOR:-}"; then mount="$FAKE_MOUNT_LINE"; fi
    echo "mount: $mount"
    echo "=== RUN   $test"
    if matches "${FAKE_NO_TESTS:-}"; then
      echo "testing: warning: no tests to run"
      echo "PASS"
      exit 0
    fi
    if matches "${FAKE_SKIP:-}"; then
      echo "    filesystem_test.go:22: FAKE_REASON"
      echo "--- SKIP: $test (0.00s)"
      echo "PASS"
      exit 0
    fi
    if matches "${FAKE_SUBTEST_SKIP:-}"; then
      echo "=== RUN   $test/stage"
      echo "    filesystem_test.go:90: subtest needs a slot"
      echo "--- PASS: $test (0.00s)"
      echo "    --- SKIP: $test/stage (0.00s)"
      echo "PASS"
      exit 0
    fi
    if matches "${FAKE_FAIL:-}"; then
      echo "    filesystem_test.go:104: fake test failure"
      echo "--- FAIL: $test (0.00s)"
      exit "${FAKE_FAIL_EXIT:-1}"
    fi
    helper="    filesystem_test.go:93: observed Linux write errno ENOSPC on the bounded tmpfs"
    case "$fault" in
      enospc)
        case "$name" in
          *keystore*)
            for effect in stage certificate; do
              echo "=== RUN   $test/$effect"
              echo "$helper"
              if ! { [ "$effect" = certificate ] && matches "${FAKE_SUBTEST_GAP:-}"; }; then
                echo "    filesystem_test.go:116: observed Linux slot $effect errno ENOSPC"
              fi
            done ;;
          *)
            echo "$helper"
            matches "${FAKE_NO_OBSERVED:-}" || echo "    filesystem_test.go:178: observed SQLite FULL" ;;
        esac ;;
      erofs) matches "${FAKE_NO_OBSERVED:-}" || echo "    filesystem_test.go:137: observed Linux open errno EROFS" ;;
    esac
    if matches "${FAKE_WRONG_TEST:-}"; then test=TestFilesystemFaultMount; fi
    echo "--- PASS: $test (0.00s)"
    echo "PASS" ;;
esac
"""

FAKE_GO = """#!/bin/sh
echo "CGO_ENABLED=$CGO_ENABLED GOOS=$GOOS GOARCH=$GOARCH GOTOOLCHAIN=$GOTOOLCHAIN $*" >> "$FAKE_GO_LOG"
echo "fake go test output"
[ "${FAKE_GO_EXIT:-0}" -eq 0 ] || exit "$FAKE_GO_EXIT"
while [ $# -gt 0 ]; do
  case "$1" in -o) : > "$2"; shift ;; esac
  shift
done
"""

SUITES = ("journal", "keystore")
FAMILIES = {"v1": "TestFilesystemFaultMount", "v2": "TestV2FilesystemFaultMount"}
PAIRS = [f"{profile}/{suite}/{family}" for profile in ("enospc-tmpfs", "erofs-readonly") for suite in SUITES for family in FAMILIES]


def executable(path, text):
    path.write_text(text)
    path.chmod(0o755)


class FilesystemFaultTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)
        fake = self.tmp / "path"
        fake.mkdir()
        executable(fake / "docker", FAKE_DOCKER.replace("FAKE_REASON", SKIP_REASON))
        executable(fake / "go", FAKE_GO)
        self.out = self.tmp / "results"
        self.docker_log = self.tmp / "docker.log"
        self.go_log = self.tmp / "go.log"
        self.env = {key: value for key, value in os.environ.items() if not key.startswith(("KNOWNDEVICE_", "FAKE_"))}
        self.env.update(
            PATH=f"{fake}{os.pathsep}{os.environ['PATH']}",
            KNOWNDEVICE_FS_FAULT_DIR=str(self.out),
            FAKE_DOCKER_LOG=str(self.docker_log),
            FAKE_GO_LOG=str(self.go_log),
            GOCACHE=str(self.tmp / "go-build"),
            GOMODCACHE=str(self.tmp / "go-mod"),
        )

    def run_faults(self, *args, **env):
        return subprocess.run(["bash", str(SCRIPT), *args], cwd=ROOT, env={**self.env, **env}, capture_output=True, text=True, timeout=120)

    def reset(self):
        shutil.rmtree(self.out, ignore_errors=True)
        for path in (self.docker_log, self.go_log):
            path.unlink(missing_ok=True)

    def summary(self):
        return (self.out / "summary.txt").read_text().splitlines()

    def results(self):
        return [line for line in self.summary() if line.startswith(("PASS ", "FAIL ", "SKIP "))]

    def pair_results(self):
        pairs = {}
        for line in self.results():
            verdict, name, detail = line.split(" ", 2)
            if name in PAIRS and not detail.startswith("setup "):
                self.assertNotIn(name, pairs, line)
                pairs[name] = verdict
        return pairs

    def docker_runs(self):
        return [line for line in self.docker_log.read_text().splitlines() if line.startswith("create ")]

    def docker_starts(self):
        return [line for line in self.docker_log.read_text().splitlines() if line.startswith("start ")]

    def run_named(self, fragment):
        (found,) = [line for line in self.docker_runs() if f"--name kd-fs-fault-{fragment}-2" in line]
        return found

    def assert_closing_lines(self):
        lines = self.summary()
        self.assertTrue(any(line.startswith("load at start: ") and line != "load at start: " for line in lines))
        self.assertTrue(any(line.startswith("load at end: ") and line != "load at end: " for line in lines))
        self.assertIn("kd-* containers after run: kd-left-1 kd-fs-fault-enospc-tmpfs-journal-v1-20000101T000000Z-1", lines)
        self.assertTrue(lines[-1].startswith("finished: "))
        self.assertEqual(sorted(self.pair_results()), sorted(PAIRS))

    def test_every_profile_suite_and_family_passes(self):
        result = self.run_faults("--execute")
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = ["PASS preflight (exit 0)", "PASS build journal (exit 0)", "PASS build keystore (exit 0)"]
        expected += [f"PASS enospc-tmpfs/{suite}/{family} (exit 0)" for suite in SUITES for family in FAMILIES]
        for suite in SUITES:
            for family in FAMILIES:
                expected += [f"PASS erofs-readonly/{suite}/{family} setup (exit 0)", f"PASS erofs-readonly/{suite}/{family} (exit 0)"]
        self.assertEqual(self.results(), expected)
        self.assertTrue(result.stdout.splitlines()[-1].startswith("Filesystem faults passed; data and logs: "))
        self.assert_closing_lines()
        self.assertIn("mount enospc-tmpfs/journal/v2: tmpfs /fault tmpfs rw,nosuid,nodev,noexec,size=8192k 0 0", self.summary())
        self.assertIn("mount erofs-readonly/keystore/v1: /host /fault ext4 ro,relatime 0 0", self.summary())

    def test_each_run_uses_its_binary_test_fault_and_fresh_mount(self):
        self.assertEqual(self.run_faults("--execute").returncode, 0)
        self.assertEqual(len(self.docker_runs()), 12)
        out = self.out.resolve()
        for suite in SUITES:
            for family, test in FAMILIES.items():
                binary = f"source={out}/artifacts/{suite}.test,target=/kd/suite.test,readonly"
                selection = f"-test.run ^{test}$ -test.v -test.count=1"

                call = self.run_named(f"enospc-tmpfs-{suite}-{family}")
                self.assertIn("--env KD_FS_FAULT=enospc --env KD_FS_ROOT=/fault", call)
                self.assertRegex(call, rf"--tmpfs /fault:rw,size=8m,mode=0700,uid={os.getuid()},gid={os.getgid()}\b")
                self.assertIn(binary, call)
                self.assertIn(selection, call)

                mount = f"source={out}/mounts/erofs-readonly-{suite}-{family},target=/fault"
                setup = self.run_named(f"erofs-readonly-{suite}-{family}-setup")
                self.assertIn("--env KD_FS_FAULT=setup --env KD_FS_ROOT=/fault", setup)
                self.assertIn(f"{mount} --env", setup)
                self.assertIn(binary, setup)
                self.assertIn(selection, setup)

                read_only = self.run_named(f"erofs-readonly-{suite}-{family}")
                self.assertIn("--env KD_FS_FAULT=erofs --env KD_FS_ROOT=/fault", read_only)
                self.assertIn(f"{mount},readonly --env", read_only)
                self.assertIn(binary, read_only)
                self.assertIn(selection, read_only)

                self.assertEqual((out / f"mounts/erofs-readonly-{suite}-{family}").stat().st_mode & 0o777, 0o700)
        for call in self.docker_runs():
            self.assertIn("--network none --read-only --cap-drop ALL", call)
            self.assertTrue(call.startswith("create --rm --name "), call)
        created = [call.split(" ")[3] for call in self.docker_runs()]
        self.assertEqual(self.docker_starts(), [f"start --attach {name}" for name in created])

    def test_workflow_step_limit_covers_every_run_and_the_builds(self):
        self.assertEqual(self.run_faults("--execute").returncode, 0)
        runs = len(self.docker_runs())
        (test_minutes,) = {int(value) for value in re.findall(r"-test\.timeout=(\d+)m", "\n".join(self.docker_runs()))}
        workflow = WORKFLOW.read_text()
        job = workflow[workflow.index("  filesystem-faults:"):]
        job_minutes = int(re.search(r"timeout-minutes: (\d+)", job).group(1))
        step = job[job.index("name: Run the filesystem-fault profiles"):]
        step_minutes = int(re.search(r"timeout-minutes: (\d+)", step).group(1))
        build_and_pull_minutes = 10
        self.assertLessEqual(runs * test_minutes + build_and_pull_minutes, step_minutes)
        self.assertLess(step_minutes, job_minutes)

    def test_runs_the_image_pinned_in_the_lab_compose_file(self):
        self.assertEqual(self.run_faults("--execute").returncode, 0)
        (pinned,) = set(re.findall(r"eclipse-mosquitto:\S+@sha256:[0-9a-f]{64}", (ROOT / "lab/compose.yaml").read_text()))
        self.assertIn(f"image: {pinned}", self.summary())
        for call in self.docker_runs():
            self.assertIn(f"--entrypoint /bin/sh {pinned} -c", call)

    def test_cross_compiles_static_binaries_for_the_docker_host(self):
        go_version = (ROOT / ".go-version").read_text().strip()
        for host, arch in (("x86_64", "amd64"), ("aarch64", "arm64")):
            with self.subTest(host=host):
                self.reset()
                result = self.run_faults("--execute", FAKE_ARCH=host)
                self.assertEqual(result.returncode, 0, result.stderr)
                builds = self.go_log.read_text().splitlines()
                self.assertEqual(len(builds), 2)
                for build, suite in zip(builds, SUITES):
                    self.assertTrue(build.startswith(f"CGO_ENABLED=0 GOOS=linux GOARCH={arch} GOTOOLCHAIN=go{go_version} test -c -trimpath -o "), build)
                    self.assertTrue(build.endswith(f"./internal/{suite}"), build)
                self.assertTrue(all(f"--platform linux/{arch}" in call for call in self.docker_runs()))
                self.assertTrue(any(line.startswith(f"runtime: linux/{arch} native architecture on {host} ") for line in self.summary()))

    def test_unsupported_host_architecture_fails_without_running_tests(self):
        result = self.run_faults("--execute", FAKE_ARCH="riscv64")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Unsupported Docker host architecture: riscv64", result.stderr)
        self.assertEqual(self.docker_runs(), [])
        self.assertFalse(self.go_log.exists())

    def test_test_failure_exit_code_is_recorded_and_other_runs_continue(self):
        result = self.run_faults("--execute", FAKE_FAIL="enospc-tmpfs-keystore-v2", FAKE_FAIL_EXIT="7")
        self.assertEqual(result.returncode, 7, result.stderr)
        pairs = self.pair_results()
        self.assertEqual(pairs.pop("enospc-tmpfs/keystore/v2"), "FAIL")
        self.assertEqual(set(pairs.values()), {"PASS"})
        log = self.out.resolve() / "logs/enospc-tmpfs-keystore-v2.log"
        self.assertIn(f"FAIL enospc-tmpfs/keystore/v2 (exit 7); log: {log}", self.results())
        self.assertIn("fake test failure", result.stderr)
        self.assertIn("Filesystem faults failed; data and logs: ", result.stderr)
        self.assertNotIn("Filesystem faults passed", result.stdout)
        self.assert_closing_lines()

    def test_first_failure_sets_the_exit_code(self):
        result = self.run_faults("--execute", FAKE_FAIL="-keystore", FAKE_FAIL_EXIT="5")
        self.assertEqual(result.returncode, 5, result.stderr)
        self.assert_closing_lines()

    def test_skip_is_reported_with_its_reason_and_fails_the_run(self):
        result = self.run_faults("--execute", FAKE_SKIP="enospc-tmpfs-journal-v1")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn(f"SKIP enospc-tmpfs/journal/v1 ({SKIP_REASON})", self.results())
        pairs = self.pair_results()
        self.assertEqual(pairs.pop("enospc-tmpfs/journal/v1"), "SKIP")
        self.assertEqual(set(pairs.values()), {"PASS"})
        self.assertIn("A skipped test is not filesystem-fault evidence.", result.stderr)
        self.assertNotIn("Filesystem faults passed", result.stdout)
        self.assert_closing_lines()

    def test_skipped_subtest_fails_the_run(self):
        result = self.run_faults("--execute", FAKE_SUBTEST_SKIP="enospc-tmpfs-keystore-v2")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("SKIP enospc-tmpfs/keystore/v2 (subtest needs a slot)", self.results())
        self.assert_closing_lines()

    def test_failure_exit_code_wins_over_a_skip(self):
        result = self.run_faults("--execute", FAKE_SKIP="enospc-tmpfs-journal-v1", FAKE_FAIL="enospc-tmpfs-keystore-v1", FAKE_FAIL_EXIT="9")
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assert_closing_lines()

    def test_zero_exit_without_a_passing_test_fails(self):
        result = self.run_faults("--execute", FAKE_NO_TESTS="erofs-readonly-keystore-v1-setup")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.pair_results()["enospc-tmpfs/journal/v1"], "PASS")
        self.assertTrue(any(line.startswith("FAIL erofs-readonly/keystore/v1 setup (exit 0 without a passing TestFilesystemFaultMount); log: ") for line in self.results()))
        self.assertIn("FAIL erofs-readonly/keystore/v1 (not run: setup did not pass)", self.results())
        self.assert_closing_lines()

    def test_v1_pass_line_does_not_satisfy_the_v2_family(self):
        result = self.run_faults("--execute", FAKE_WRONG_TEST="enospc-tmpfs-journal-v2")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(any(line.startswith("FAIL enospc-tmpfs/journal/v2 (exit 0 without a passing TestV2FilesystemFaultMount); log: ") for line in self.results()))
        self.assert_closing_lines()

    def test_v1_pass_line_in_v2_setup_blocks_the_read_only_run(self):
        result = self.run_faults("--execute", FAKE_WRONG_TEST="erofs-readonly-keystore-v2-setup")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("FAIL erofs-readonly/keystore/v2 (not run: setup did not pass)", self.results())
        self.assert_closing_lines()

    def test_run_without_its_own_observation_fails(self):
        cases = [
            ("erofs-readonly-journal-v2", "erofs-readonly/journal/v2", "the run"),
            ("enospc-tmpfs-journal-v1", "enospc-tmpfs/journal/v1", "the run"),
        ]
        for fragment, pair, gap in cases:
            with self.subTest(pair=pair):
                self.reset()
                result = self.run_faults("--execute", FAKE_NO_OBSERVED=fragment)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertTrue(any(line.startswith(f"FAIL {pair} (exit 0 without an observed fault for {gap}); log: ") for line in self.results()), self.results())
                self.assert_closing_lines()

    def test_subtest_with_only_the_exhaustion_line_fails(self):
        result = self.run_faults("--execute", FAKE_SUBTEST_GAP="enospc-tmpfs-keystore-v2")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(any(line.startswith("FAIL enospc-tmpfs/keystore/v2 (exit 0 without an observed fault for TestV2FilesystemFaultMount/certificate); log: ") for line in self.results()), self.results())
        self.assert_closing_lines()

    def test_setup_needs_no_observation(self):
        self.assertEqual(self.run_faults("--execute").returncode, 0)
        log = (self.out / "logs/erofs-readonly-journal-v1-setup.log").read_text()
        self.assertNotIn("observed", log)
        self.assertIn("PASS erofs-readonly/journal/v1 setup (exit 0)", self.results())

    def test_unfit_mount_fails_the_run(self):
        cases = [
            ("enospc-tmpfs-journal-v1", "enospc-tmpfs/journal/v1", "enospc", "/host /fault ext4 rw,relatime 0 0"),
            ("enospc-tmpfs-keystore-v2", "enospc-tmpfs/keystore/v2", "enospc", "tmpfs /fault tmpfs ro,size=8192k 0 0"),
            # The trailing "-2" is the run identifier's year, which excludes the setup container.
            ("erofs-readonly-journal-v2-2", "erofs-readonly/journal/v2", "erofs", "/host /fault ext4 rw,relatime 0 0"),
            ("erofs-readonly-keystore-v1-setup", "erofs-readonly/keystore/v1 setup", "setup", "/host /fault ext4 ro,relatime 0 0"),
            ("enospc-tmpfs-journal-v2", "enospc-tmpfs/journal/v2", "enospc", ""),
            ("enospc-tmpfs-keystore-v1", "enospc-tmpfs/keystore/v1", "enospc", "tmpfs /elsewhere tmpfs rw 0 0"),
        ]
        for fragment, name, fault, line in cases:
            with self.subTest(name=name):
                self.reset()
                result = self.run_faults("--execute", FAKE_MOUNT_FOR=fragment, FAKE_MOUNT_LINE=line)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertTrue(any(result_line.startswith(f"FAIL {name} (exit 0 on a mount unfit for {fault}); log: ") for result_line in self.results()), self.results())
                self.assert_closing_lines()

    def test_failed_setup_does_not_run_the_read_only_test(self):
        result = self.run_faults("--execute", FAKE_FAIL="erofs-readonly-journal-v1-setup", FAKE_FAIL_EXIT="6")
        self.assertEqual(result.returncode, 6, result.stderr)
        self.assertIn("FAIL erofs-readonly/journal/v1 (not run: setup did not pass)", self.results())
        self.assertFalse([call for call in self.docker_runs() if "--name kd-fs-fault-erofs-readonly-journal-v1-2" in call])
        self.assertEqual(self.pair_results()["erofs-readonly/journal/v2"], "PASS")
        self.assert_closing_lines()

    def test_skipped_setup_fails_the_run(self):
        result = self.run_faults("--execute", FAKE_SKIP="erofs-readonly-journal-v2-setup")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn(f"SKIP erofs-readonly/journal/v2 setup ({SKIP_REASON})", self.results())
        self.assertIn("FAIL erofs-readonly/journal/v2 (not run: setup did not pass)", self.results())
        self.assert_closing_lines()

    def test_build_failure_records_every_pair_as_not_run(self):
        result = self.run_faults("--execute", FAKE_GO_EXIT="4")
        self.assertEqual(result.returncode, 4, result.stderr)
        results = self.results()
        self.assertTrue(results[1].startswith("FAIL build journal (exit 4); logs: "))
        for pair in PAIRS:
            self.assertIn(f"FAIL {pair} (not run)", results)
        self.assertIn("fake go test output", result.stderr)
        self.assertEqual(self.docker_runs(), [])
        self.assert_closing_lines()

    def test_unavailable_docker_records_every_pair_as_not_run(self):
        result = self.run_faults("--execute", FAKE_INFO_EXIT="8")
        self.assertEqual(result.returncode, 8, result.stderr)
        results = self.results()
        self.assertTrue(results[0].startswith("FAIL preflight (exit 8); logs: "))
        for pair in PAIRS:
            self.assertIn(f"FAIL {pair} (not run)", results)
        self.assertFalse(self.go_log.exists())
        self.assert_closing_lines()

    def test_signal_during_a_test_records_each_pair_once(self):
        result = self.run_faults("--execute", FAKE_SIGNAL="enospc-tmpfs-keystore-v1")
        self.assertEqual(result.returncode, 143, result.stderr)
        results = self.results()
        self.assertIn("PASS enospc-tmpfs/journal/v1 (exit 0)", results)
        self.assertTrue(any(line.startswith("FAIL enospc-tmpfs/keystore/v1 (exit 143); logs: ") for line in results))
        self.assertFalse(any(line.startswith("FAIL enospc-tmpfs/journal/v1 ") for line in results))
        for pair in ("enospc-tmpfs/keystore/v2", "erofs-readonly/journal/v1", "erofs-readonly/keystore/v2"):
            self.assertIn(f"FAIL {pair} (not run)", results)
        self.assertEqual(len([line for line in self.docker_log.read_text().splitlines() if line.startswith("rm -f kd-fs-fault-enospc-tmpfs-keystore-v1-")]), 1)
        self.assert_closing_lines()

    def test_signal_during_setup_does_not_count_as_the_pair(self):
        for suite in SUITES:
            with self.subTest(suite=suite):
                self.reset()
                result = self.run_faults("--execute", FAKE_SIGNAL=f"erofs-readonly-{suite}-v1-setup")
                self.assertEqual(result.returncode, 143, result.stderr)
                results = self.results()
                self.assertTrue(any(line.startswith(f"FAIL erofs-readonly/{suite}/v1 setup (exit 143); logs: ") for line in results), results)
                self.assertIn(f"FAIL erofs-readonly/{suite}/v1 (not run)", results)
                self.assertEqual(self.pair_results()[f"erofs-readonly/{suite}/v1"], "FAIL")
                self.assertEqual(self.pair_results()["enospc-tmpfs/keystore/v2"], "PASS")
                self.assert_closing_lines()

    def test_signal_reaches_a_hung_test_and_removes_its_live_container(self):
        started = Path(f"{self.docker_log}.pid")
        removed = Path(f"{self.docker_log}.removed")
        # Releases the fake if the script never removes the container.
        self.addCleanup(removed.touch)
        process = subprocess.Popen(
            ["bash", str(SCRIPT), "--execute"],
            cwd=ROOT,
            env={**self.env, "FAKE_HANG": "enospc-tmpfs-journal-v2"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(process.kill)
        deadline = time.monotonic() + 60
        while not started.exists():
            self.assertLess(time.monotonic(), deadline, "the fake container did not start")
            time.sleep(0.05)
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 143, stderr)
        (live,) = Path(f"{self.docker_log}.live").read_text().splitlines()
        self.assertRegex(live, r"^kd-fs-fault-enospc-tmpfs-journal-v2-\S+$")
        results = self.results()
        self.assertTrue(any(line.startswith("FAIL enospc-tmpfs/journal/v2 (exit 143); logs: ") for line in results), results)
        self.assertIn("FAIL erofs-readonly/keystore/v2 (not run)", results)
        self.assert_closing_lines()

    def test_signal_during_create_removes_the_container_it_produces(self):
        result = self.run_faults("--execute", FAKE_SIGNAL_IN_CREATE="enospc-tmpfs-journal-v2")
        self.assertEqual(result.returncode, 143, result.stderr)
        (existed,) = Path(f"{self.docker_log}.existed").read_text().splitlines()
        self.assertRegex(existed, r"^kd-fs-fault-enospc-tmpfs-journal-v2-\S+$")
        self.assertFalse(any(line.startswith("FAIL cleanup") for line in self.results()), self.results())
        self.assertFalse([call for call in self.docker_starts() if "enospc-tmpfs-journal-v2" in call])
        self.assert_closing_lines()

    def test_failed_create_is_recorded_without_starting_the_container(self):
        result = self.run_faults("--execute", FAKE_CREATE_EXIT_FOR="enospc-tmpfs-journal-v1")
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertEqual(self.pair_results()["enospc-tmpfs/journal/v1"], "FAIL")
        self.assertEqual(self.pair_results()["enospc-tmpfs/journal/v2"], "PASS")
        self.assertIn("fake create failure", result.stderr)
        self.assertFalse([call for call in self.docker_starts() if "enospc-tmpfs-journal-v1" in call])
        self.assert_closing_lines()

    def test_container_left_by_this_run_fails_it(self):
        result = self.run_faults("--execute", FAKE_KEEP="enospc-tmpfs-journal-v2")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(set(self.pair_results().values()), {"PASS"})
        self.assertTrue(any(line.startswith("FAIL cleanup (containers left by this run: kd-fs-fault-enospc-tmpfs-journal-v2-") for line in self.results()), self.results())
        self.assertIn("Filesystem faults failed", result.stderr)

    def test_other_runs_containers_do_not_fail_it(self):
        result = self.run_faults("--execute")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(line.startswith("FAIL cleanup") for line in self.results()))
        self.assertIn("kd-* containers after run: kd-left-1 kd-fs-fault-enospc-tmpfs-journal-v1-20000101T000000Z-1", self.summary())

    def test_unlistable_containers_fail_the_run(self):
        result = self.run_faults("--execute", FAKE_PS_EXIT="4")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("FAIL cleanup (cannot list containers, docker exit 4)", self.results())
        self.assertIn("kd-* containers after run: unavailable (docker exit 4)", self.summary())

    def test_records_docker_mode_and_container_user(self):
        cases = [
            ({}, "docker mode: rootful", f"container user: {os.getuid()}:{os.getgid()}", f"uid={os.getuid()},gid={os.getgid()}"),
            ({"FAKE_SECURITY_OPTIONS": '["name=seccomp","name=rootless"]'}, "docker mode: rootless", "container user: 0:0", "uid=0,gid=0"),
            ({"FAKE_SECURITY_OPTIONS": '["name=rootless"]', "KNOWNDEVICE_LAB_USER": "1234:1235"}, "docker mode: rootless", "container user: 1234:1235", "uid=1234,gid=1235"),
        ]
        for env, mode, user, owner in cases:
            with self.subTest(env=env):
                self.reset()
                result = self.run_faults("--execute", **env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(mode, self.summary())
                self.assertIn(user, self.summary())
                self.assertIn(f"--user {user.split(': ')[1]} ", self.docker_runs()[0])
                self.assertIn(owner, self.run_named("enospc-tmpfs-journal-v1"))

    def test_usage_errors_write_nothing(self):
        for args in ([], ["--apply"], ["--execute", "extra"]):
            with self.subTest(args=args):
                result = self.run_faults(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Usage: bash scripts/fs_faults.sh --execute", result.stderr)
                self.assertIn("Profiles: enospc-tmpfs erofs-readonly; suites: journal keystore; families: v1 v2", result.stderr)
                self.assertFalse(self.out.exists())
                self.assertFalse(self.docker_log.exists())

    def test_existing_results_directory_is_refused(self):
        self.out.mkdir()
        (self.out / "summary.txt").write_text("earlier evidence\n")
        result = self.run_faults("--execute")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Results directory already exists", result.stderr)
        self.assertEqual((self.out / "summary.txt").read_text(), "earlier evidence\n")
        self.assertFalse(self.docker_log.exists())


if __name__ == "__main__":
    unittest.main()
