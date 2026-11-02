#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$root"

profiles="enospc-tmpfs erofs-readonly"
suites="journal keystore"
families="v1 v2"
# The tests stop writing their filler after 16 MiB and fail if ENOSPC has not
# appeared by then, so the limit must stay well below that.
tmpfs_size=8m
# The workflow's step limit must cover every run at this timeout plus the builds.
test_timeout=2m

usage() {
  echo "Usage: bash scripts/fs_faults.sh --execute" >&2
  echo "Profiles: $profiles; suites: $suites; families: $families" >&2
  echo "Exit: 0 all passed; 2 usage; 3 only skips; otherwise the first failure's exit code" >&2
  exit 2
}
[[ $# -eq 1 && "$1" == --execute ]] || usage

export GOCACHE="${GOCACHE:-$root/.cache/go-build}"
export GOMODCACHE="${GOMODCACHE:-$root/.cache/go-mod}"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"

load_average() {
  local value=""
  if [[ -r /proc/loadavg ]]; then
    value="$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)" || value=""
  elif command -v sysctl > /dev/null 2>&1; then
    value="$(LC_ALL=C sysctl -n vm.loadavg 2>/dev/null | tr -d '{}')" || value=""
  fi
  value="$(printf '%s\n' "$value" | awk '{$1 = $1; print}')"
  echo "${value:-unavailable}"
}

# A failing command under set -e exits through the trap, which records the
# current step's FAIL line.
step=""
step_log=""
begin() { step="$1"; step_log="${2:-}"; }
record() {
  echo "$1" | tee -a "$summary"
  step=""
  step_log=""
}
pass() { record "PASS $step (exit 0)"; }

# The summary is the only record of results, so a signal between writing a line
# and clearing the step cannot report one result twice.
has_result() { grep -Eq "^(PASS|FAIL|SKIP) $1 \(" "$summary" 2>/dev/null; }

container=""
job=""
failure=0
skips=0
failed() { [[ "$failure" -ne 0 ]] || failure="$1"; }

finish() {
  local status=$?
  set +e
  # A second signal must not cut cleanup short.
  trap '' HUP INT TERM
  if [[ "$status" -ne 0 && -n "$step" ]] && ! has_result "$step"; then
    echo "FAIL $step (exit $status); logs: $out/logs" | tee -a "$summary" >&2
    if [[ -n "$step_log" && -r "$step_log" ]]; then tail -n 40 "$step_log" >&2; fi
  fi
  if [[ -n "$container" ]]; then docker rm -f "$container" > /dev/null 2>&1; fi
  if [[ -n "$job" ]]; then kill "$job" 2>/dev/null; fi
  # Every profile, suite and family ends with a result line, however the run stopped.
  local profile suite family
  for profile in $profiles; do
    for suite in $suites; do
      for family in $families; do
        if ! has_result "$profile/$suite/$family"; then
          echo "FAIL $profile/$suite/$family (not run)" | tee -a "$summary" >&2
          if [[ "$status" -eq 0 ]]; then status=1; fi
        fi
      done
    done
  done
  # Only this run's containers can fail it; other runs' kd-* containers are listed and left alone.
  local names listing=0 others own
  names="$(docker ps -a --format '{{.Names}}' 2>/dev/null)" || listing=$?
  if [[ "$listing" -ne 0 ]]; then
    others="unavailable (docker exit $listing)"
    echo "FAIL cleanup (cannot list containers, docker exit $listing)" | tee -a "$summary" >&2
    if [[ "$status" -eq 0 ]]; then status=1; fi
  else
    others="$(printf '%s\n' "$names" | grep '^kd-' | tr '\n' ' ')"
    others="${others% }"
    others="${others:-none}"
    own="$(printf '%s\n' "$names" | grep -e "-$run_id\$" | tr '\n' ' ')"
    own="${own% }"
    if [[ -n "$own" ]]; then
      echo "FAIL cleanup (containers left by this run: $own)" | tee -a "$summary" >&2
      if [[ "$status" -eq 0 ]]; then status=1; fi
    fi
  fi
  {
    echo "load at end: $(load_average)"
    echo "kd-* containers after run: $others"
    echo "finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >> "$summary"
  if [[ "$status" -eq 0 ]]; then
    echo "Filesystem faults passed; data and logs: $out"
  else
    if [[ "$skips" -ne 0 ]]; then echo "A skipped test is not filesystem-fault evidence." >&2; fi
    echo "Filesystem faults failed; data and logs: $out" >&2
  fi
  exit "$status"
}

out="${KNOWNDEVICE_FS_FAULT_DIR:-$root/.work/fs-faults-$run_id}"
if [[ -e "$out" ]]; then echo "Results directory already exists: $out" >&2; exit 2; fi
mkdir -p "$out/artifacts" "$out/logs" "$out/mounts"
out="$(cd "$out" && pwd -P)"
summary="$out/summary.txt"
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

begin preflight
commit=unknown
# An exported copy inside another checkout must not report the outer repository's commit.
if [[ "$(git rev-parse --show-toplevel 2>/dev/null)" == "$root" ]]; then
  commit="$(git rev-parse --verify --quiet HEAD 2>/dev/null)" || commit=unknown
  if [[ "$commit" != unknown && -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
    commit="$commit-dirty"
  fi
fi
{
  echo "commit: $commit"
  echo "profiles: $profiles"
  echo "suites: $suites"
  echo "families: $families"
  echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "load at start: $(load_average)"
} > "$summary"

go_version="$(tr -d '[:space:]' < .go-version)"
if [[ ! "$go_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo ".go-version must hold one Go release such as 1.27.3" >&2; exit 2; fi
export GOTOOLCHAIN="go$go_version"

image="$(grep -Eo -m1 'eclipse-mosquitto:[^ @]+@sha256:[0-9a-f]{64}' lab/compose.yaml || true)"
if [[ -z "$image" ]]; then echo "lab/compose.yaml has no digest-pinned eclipse-mosquitto image" >&2; exit 2; fi

# Docker Engine on Linux keeps host file ownership, and the journal and key
# store refuse files owned by another user, so containers run as the invoking
# user. Rootless Docker already maps container root to that user.
security="$(docker info --format '{{json .SecurityOptions}}')"
if [[ "$security" == *name=rootless* ]]; then docker_mode=rootless; else docker_mode=rootful; fi
if [[ -z "${KNOWNDEVICE_LAB_USER:-}" ]]; then
  if [[ "$docker_mode" == rootless ]]; then
    KNOWNDEVICE_LAB_USER=0:0
  else
    KNOWNDEVICE_LAB_USER="$(id -u):$(id -g)"
  fi
fi
host_arch="$(docker info --format '{{.Architecture}}')"
case "$host_arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "Unsupported Docker host architecture: $host_arch" >&2; exit 2 ;;
esac
{
  echo "runtime: linux/$arch native architecture on $host_arch Docker host ($(docker info --format '{{.OperatingSystem}}'), kernel $(docker info --format '{{.KernelVersion}}'))"
  echo "docker mode: $docker_mode"
  echo "container user: $KNOWNDEVICE_LAB_USER"
  echo "image: $image"
  echo "tmpfs size: $tmpfs_size"
  echo "test timeout: $test_timeout"
} >> "$summary"
pass

for suite in $suites; do
  begin "build $suite" "$out/logs/build-$suite.log"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go test -c -trimpath -o "$out/artifacts/$suite.test" "./internal/$suite" > "$step_log" 2>&1
  pass
done

test_name() {
  case "$1" in
    v1) echo TestFilesystemFaultMount ;;
    v2) echo TestV2FilesystemFaultMount ;;
  esac
}

# Prints the fault mount before the test, so each log names the filesystem it
# exercised. A test binary has no default timeout outside the go command.
run_test() {
  local suite="$1" test="$2" fault="$3" name="$4" log="$5" status=0
  shift 5
  container="kd-fs-fault-$name-$run_id"
  # The daemon can finish a create request after its client is killed, so create
  # stays in the foreground: a signal waits for it and cleanup then finds the container.
  # shellcheck disable=SC2016  # Expanded by the container's shell.
  docker create --rm --name "$container" --platform "linux/$arch" --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges --user "$KNOWNDEVICE_LAB_USER" \
    --tmpfs /tmp:rw,size=8m \
    --mount "type=bind,source=$out/artifacts/$suite.test,target=/kd/suite.test,readonly" \
    "$@" \
    --env "KD_FS_FAULT=$fault" --env KD_FS_ROOT=/fault --workdir / --entrypoint /bin/sh "$image" \
    -c 'echo "mount: $(grep " /fault " /proc/mounts)"; exec "$@"' sh /kd/suite.test \
    -test.run "^$test\$" -test.v -test.count=1 "-test.timeout=$test_timeout" \
    > "$log" 2>&1 || status=$?
  if [[ "$status" -eq 0 ]]; then
    docker start --attach "$container" >> "$log" 2>&1 &
    job=$!
    # Unlike a foreground command, wait lets a trap run while the test hangs.
    wait "$job" || status=$?
    job=""
  fi
  container=""
  return "$status"
}

mount_matches() {
  local fault="$1" line="$2" target fstype options mode
  read -r _ _ target fstype options _ <<< "$line"
  mode="${options%%,*}"
  [[ "$target" == /fault ]] || return 1
  case "$fault" in
    enospc) [[ "$fstype" == tmpfs && "$mode" == rw ]] ;;
    erofs) [[ "$mode" == ro ]] ;;
    setup) [[ "$mode" == rw ]] ;;
    *) return 1 ;;
  esac
}

# Prints the first subtest, or "the run", that logged no observation of its own
# fault. exhaustFilesystem logs "observed" before the fault under test happens,
# so its line proves nothing.
missing_observation() {
  awk '
    function check() { if (subtest != "" && !seen && gap == "") gap = subtest }
    /^=== RUN +[^ ]+\// { check(); subtest = $3; seen = 0; next }
    /_test\.go:[0-9]+: observed / && !/observed Linux write errno ENOSPC on the bounded tmpfs/ { seen = 1; any = 1 }
    END { check(); if (gap == "" && !any) gap = "the run"; print gap }
  ' "$1"
}

reject() {
  local name="$1" log="$2" status="$3" detail="$4"
  record "FAIL $name ($detail); log: $log" >&2
  tail -n 40 "$log" >&2
  failed "$status"
  outcome=FAIL
}

# A zero exit alone is not evidence: a skip and a -test.run that matches
# nothing both exit 0.
report() {
  local name="$1" log="$2" status="$3" test="$4" fault="$5" mount gap
  mount="$(grep -m1 '^mount: ' "$log" || true)"
  if [[ -n "$mount" ]]; then echo "mount $name: ${mount#mount: }" >> "$summary"; fi
  if [[ "$status" -ne 0 ]]; then
    reject "$name" "$log" "$status" "exit $status"
    return 0
  fi
  if grep -q '^ *--- SKIP: ' "$log"; then
    local reason
    reason="$(awk '
      /^ *--- SKIP: /{print (last == "" ? "no reason logged" : last); exit}
      /_test\.go:[0-9]+: /{last = $0; sub(/^ *[^ ]*_test\.go:[0-9]+: /, "", last)}
    ' "$log")"
    outcome=SKIP
    skips=$((skips + 1))
    record "SKIP $name ($reason)" >&2
    return 0
  fi
  if ! grep -q "^--- PASS: $test " "$log"; then
    reject "$name" "$log" 1 "exit 0 without a passing $test"
    return 0
  fi
  if ! mount_matches "$fault" "$mount"; then
    reject "$name" "$log" 1 "exit 0 on a mount unfit for $fault"
    return 0
  fi
  if [[ "$fault" != setup ]]; then
    gap="$(missing_observation "$log")"
    if [[ -n "$gap" ]]; then
      reject "$name" "$log" 1 "exit 0 without an observed fault for $gap"
      return 0
    fi
  fi
  outcome=PASS
  record "PASS $name (exit 0)"
}

run_enospc() {
  local suite="$1" family="$2" test pair="enospc-tmpfs/$1/$2" name="enospc-tmpfs-$1-$2" status=0
  local log="$out/logs/$name.log"
  test="$(test_name "$family")"
  begin "$pair" "$log"
  run_test "$suite" "$test" enospc "$name" "$log" \
    --tmpfs "/fault:rw,size=$tmpfs_size,mode=0700,uid=${KNOWNDEVICE_LAB_USER%%:*},gid=${KNOWNDEVICE_LAB_USER##*:}" || status=$?
  report "$pair" "$log" "$status" "$test" enospc
}

run_erofs() {
  local suite="$1" family="$2" test pair="erofs-readonly/$1/$2" name="erofs-readonly-$1-$2" status=0
  local log="$out/logs/$name.log" setup_log="$out/logs/$name-setup.log" mount_dir="$out/mounts/$name"
  test="$(test_name "$family")"
  # The stores refuse a directory that is not private to the current user.
  mkdir -m 0700 "$mount_dir"
  begin "$pair setup" "$setup_log"
  run_test "$suite" "$test" setup "$name-setup" "$setup_log" \
    --mount "type=bind,source=$mount_dir,target=/fault" || status=$?
  report "$pair setup" "$setup_log" "$status" "$test" setup
  if [[ "$outcome" != PASS ]]; then
    record "FAIL $pair (not run: setup did not pass)" >&2
    return 0
  fi
  begin "$pair" "$log"
  status=0
  run_test "$suite" "$test" erofs "$name" "$log" \
    --mount "type=bind,source=$mount_dir,target=/fault,readonly" || status=$?
  report "$pair" "$log" "$status" "$test" erofs
}

# Each family gets a fresh mount: both use the same paths, and V1 refuses other schema versions.
for suite in $suites; do
  for family in $families; do run_enospc "$suite" "$family"; done
done
for suite in $suites; do
  for family in $families; do run_erofs "$suite" "$family"; done
done

if [[ "$failure" -ne 0 ]]; then exit "$failure"; fi
if [[ "$skips" -ne 0 ]]; then exit 3; fi
