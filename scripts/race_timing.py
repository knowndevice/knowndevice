#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Measure per-test durations of race-enabled Go tests together with host load."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("./adapters/process", "./internal/controller", "./internal/profilelab", "./sdk/conformance")
# Tests with wall-clock bounds that have failed under host load; always listed.
WATCHED = (
    ("adapters/process", "TestBlockedServerOutputRespectsContext"),
    ("adapters/process", "TestRealSubprocessSignerLookupAndRedaction"),
    ("internal/controller", "TestFreshObservationIsDurableBeforePointerAndReplayFailsAfterReopen"),
    ("internal/profilelab", "TestDelayedAuthorityHandshakePastDeadlineSendsNoSign"),
    ("sdk/conformance", "TestBuiltinPublicSuite"),
)
OUTPUT_TAIL = 30
SLOWEST = 15


def short_package(name, module):
    return name[len(module) + 1:] if module and name.startswith(module + "/") else name


def parse_events(lines, module=""):
    """Fold `go test -json` events into per-package and per-test results."""
    packages, tests, failures, build_output, stray = {}, {}, [], {}, []
    running = {}
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            stray.append(raw)
            continue
        action = event.get("Action")
        if action in ("build-output", "build-fail"):
            path = short_package(event.get("ImportPath", ""), module)
            if event.get("Output"):
                build_output.setdefault(path, []).append(event["Output"].rstrip("\n"))
            continue
        package = short_package(event.get("Package", ""), module)
        test = event.get("Test")
        if not test:
            if action in ("pass", "fail", "skip"):
                packages[package] = {"result": action, "elapsed": event.get("Elapsed", 0.0)}
            continue
        key = (package, test)
        if action == "run":
            running[key] = []
        elif action == "output":
            running.setdefault(key, []).append(event.get("Output", "").rstrip("\n"))
        elif action in ("pass", "fail", "skip"):
            record = tests.setdefault(key, {"package": package, "test": test, "runs": []})
            elapsed = float(event.get("Elapsed", 0.0))
            record["runs"].append({"result": action, "elapsed": elapsed})
            if action == "fail":
                failures.append({"package": package, "test": test, "run": len(record["runs"]), "elapsed": elapsed, "output": running.get(key, [])[-OUTPUT_TAIL:]})
            running.pop(key, None)
    for record in tests.values():
        durations = [run["elapsed"] for run in record["runs"] if run["result"] != "skip"]
        record["passes"] = sum(run["result"] == "pass" for run in record["runs"])
        record["fails"] = sum(run["result"] == "fail" for run in record["runs"])
        record["skips"] = sum(run["result"] == "skip" for run in record["runs"])
        record["min"] = min(durations) if durations else None
        record["median"] = statistics.median(durations) if durations else None
        record["max"] = max(durations) if durations else None
    return {"packages": packages, "tests": sorted(tests.values(), key=lambda r: (r["package"], r["test"])), "failures": failures, "buildOutput": build_output, "nonJSONLines": len(stray)}


def seconds(value):
    return "-" if value is None else f"{value:.2f}"


def describe_tests(records):
    return [f"  {r['package']} {r['test']}: runs {len(r['runs'])}, fails {r['fails']}, skips {r['skips']}, min/median/max {seconds(r['min'])}/{seconds(r['median'])}/{seconds(r['max'])} s" for r in records]


def render(summary):
    lines = []
    env = summary.get("environment")
    if env:
        lines += [
            f"commit: {env['commit']}",
            f"go: {env['goVersion']} {env['goos']}/{env['goarch']}; CPUs {env['cpus']}; host {env['host']}",
            f"runner: {env['runner'] or 'none'}",
            f"command: {' '.join(env['command'])}",
            f"started: {env['started']}; finished: {env['finished']}; test wall time {env['wallSeconds']:.1f} s; prebuild {env['prebuildSeconds']:.1f} s",
            f"exit: {env['exitCode']}",
        ]
    load = summary.get("load")
    if load:
        lines.append(f"load (1-min): start {load['start'][0]:.2f}, end {load['end'][0]:.2f}, samples {load['samples']}, min {load['min']:.2f}, mean {load['mean']:.2f}, max {load['max']:.2f}")
    lines.append("packages:")
    for name, result in sorted(summary["packages"].items()):
        lines.append(f"  {result['result'].upper()} {name} {result['elapsed']:.2f} s")
    watched = [r for r in summary["tests"] if (r["package"], r["test"]) in WATCHED]
    missing = [f"{package} {test}" for package, test in WATCHED if not any(r["package"] == package and r["test"] == test for r in summary["tests"]) and any(package == p for p in summary["packages"])]
    lines.append("watched timing-bound tests:")
    lines += describe_tests(watched) + [f"  {name}: not run" for name in missing]
    slowest = sorted((r for r in summary["tests"] if r["max"] is not None), key=lambda r: r["max"], reverse=True)[:SLOWEST]
    lines.append(f"slowest {len(slowest)} tests by maximum:")
    lines += describe_tests(slowest)
    lines.append(f"failures: {len(summary['failures'])}")
    for failure in summary["failures"]:
        lines.append(f"  {failure['package']} {failure['test']} run {failure['run']} after {failure['elapsed']:.2f} s")
        lines += [f"    {line}" for line in failure["output"]]
    for path, output in sorted(summary["buildOutput"].items()):
        lines.append(f"build output for {path}:")
        lines += [f"    {line}" for line in output[-OUTPUT_TAIL:]]
    if summary["nonJSONLines"]:
        lines.append(f"non-JSON lines on stdout: {summary['nonJSONLines']}")
    return "\n".join(lines) + "\n"


class LoadSampler:
    def __init__(self, interval):
        self.interval, self.samples, self.stopped = interval, [], threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def loop(self):
        while True:
            self.samples.append((time.time(), *os.getloadavg()))
            if self.stopped.wait(self.interval):
                return

    def __enter__(self):
        self.start = os.getloadavg()
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stopped.set()
        self.thread.join()
        self.end = os.getloadavg()

    def summary(self):
        one = [sample[1] for sample in self.samples] or [self.start[0]]
        return {"start": list(self.start), "end": list(self.end), "samples": len(self.samples), "min": min(one), "mean": statistics.fmean(one), "max": max(one)}


def go_environment():
    env = dict(os.environ)
    env.setdefault("GOCACHE", str(ROOT / ".cache/go-build"))
    env.setdefault("GOMODCACHE", str(ROOT / ".cache/go-mod"))
    env.setdefault("GOTOOLCHAIN", "local")
    return env


def output(command, env):
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def runner_description():
    fields = [os.environ.get(name, "") for name in ("RUNNER_NAME", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion")]
    return " ".join(field for field in fields if field)


def measure(args):
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"--out {out} exists and is not empty")
    out.mkdir(parents=True, exist_ok=True)
    env = go_environment()
    packages = args.packages or list(PACKAGES)
    goversion, goos, goarch = (output(["go", "env", "GOVERSION", "GOOS", "GOARCH"], env).split() + ["unknown"] * 3)[:3]
    commit = output(["git", "rev-parse", "HEAD"], env)
    if output(["git", "status", "--porcelain", "--untracked-files=no"], env) not in ("", "unknown"):
        commit += "-dirty"
    module = output(["go", "list", "-m"], env)
    prebuild_started = time.monotonic()
    prebuild = subprocess.run(["go", "test", "-race", "-run", "^$", *packages], cwd=ROOT, env=env, capture_output=True, text=True)
    prebuild_seconds = time.monotonic() - prebuild_started
    (out / "prebuild.log").write_text(prebuild.stdout + prebuild.stderr)
    command = ["go", "test", "-race", "-json", f"-count={args.count}", f"-timeout={args.timeout}"]
    if args.run:
        command.append(f"-run={args.run}")
    command += packages
    started = datetime.now(timezone.utc)
    test_started = time.monotonic()
    with LoadSampler(args.sample_seconds) as sampler:
        with open(out / "events.jsonl", "w") as events, open(out / "stderr.txt", "w") as errors:
            exit_code = subprocess.run(command, cwd=ROOT, env=env, stdout=events, stderr=errors).returncode
    wall = time.monotonic() - test_started
    with open(out / "load.tsv", "w") as samples:
        samples.write("unix_time\tload1\tload5\tload15\n")
        samples.writelines("\t".join(f"{value:.2f}" for value in sample) + "\n" for sample in sampler.samples)
    with open(out / "events.jsonl") as events:
        summary = parse_events(events, module if module != "unknown" else "")
    summary["environment"] = {
        "commit": commit, "goVersion": goversion, "goos": goos, "goarch": goarch, "cpus": os.cpu_count(),
        "host": f"{platform.system()} {platform.release()} {platform.machine()}", "runner": runner_description(),
        "command": command, "started": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "finished": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "wallSeconds": wall, "prebuildSeconds": prebuild_seconds, "prebuildExit": prebuild.returncode, "exitCode": exit_code,
    }
    summary["load"] = sampler.summary()
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    text = render(summary)
    (out / "summary.txt").write_text(text)
    sys.stdout.write(text)
    if prebuild.returncode:
        print(f"prebuild exited {prebuild.returncode}; see {out / 'prebuild.log'}", file=sys.stderr)
        return prebuild.returncode
    return exit_code


def summarize(args):
    with open(args.events) as events:
        summary = parse_events(events, args.module)
    sys.stdout.write(json.dumps(summary, indent=1) + "\n" if args.json else render(summary))
    return 1 if summary["failures"] or any(r["result"] == "fail" for r in summary["packages"].values()) else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    run = sub.add_parser("run", help="run the race tests and write events, load samples and a summary to --out")
    run.add_argument("--out", required=True, help="new or empty output directory")
    run.add_argument("--count", type=int, default=3, help="go test -count value (default 3)")
    run.add_argument("--run", help="go test -run expression")
    run.add_argument("--timeout", default="60m", help="go test -timeout value; the 10m default cuts repeated runs on a loaded host (default 60m)")
    run.add_argument("--sample-seconds", type=float, default=5.0, help="load sampling interval (default 5)")
    run.add_argument("packages", nargs="*", help=f"packages (default {' '.join(PACKAGES)})")
    read = sub.add_parser("summarize", help="print the summary of an existing go test -json file; writes nothing")
    read.add_argument("events")
    read.add_argument("--module", default="github.com/knowndevice/knowndevice", help="module prefix to strip from package names")
    read.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = parser.parse_args(argv)
    if args.mode == "run" and args.count < 1:
        parser.error("--count must be at least 1")
    return measure(args) if args.mode == "run" else summarize(args)


if __name__ == "__main__":
    sys.exit(main())
