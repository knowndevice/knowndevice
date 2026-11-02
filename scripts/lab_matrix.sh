#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$root"

profile_cells="reference-generation-cn-builtin stable-device-cn-builtin reference-generation-cn-generated-process stable-device-cn-generated-process"
all_cells="legacy-reference-builtin $profile_cells"
usage() {
  echo "Usage: bash scripts/lab_matrix.sh [--cell NAME] amd64|arm64" >&2
  echo "Cells: $all_cells" >&2
  exit 2
}

arch=""
only=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cell) [[ $# -ge 2 && -n "$2" ]] || usage; only="$2"; shift 2 ;;
    --cell=*) only="${1#--cell=}"; [[ -n "$only" ]] || usage; shift ;;
    amd64|arm64) [[ -z "$arch" ]] || usage; arch="$1"; shift ;;
    *) usage ;;
  esac
done
[[ -n "$arch" ]] || usage
if [[ -n "$only" ]]; then
  known=no
  for name in $all_cells; do [[ "$name" != "$only" ]] || known=yes; done
  if [[ "$known" == no ]]; then echo "Unknown cell: $only" >&2; usage; fi
fi

selected() { [[ -z "$only" || "$only" == "$1" ]]; }
needs_generated=no
for name in $all_cells; do
  if [[ "$name" == *-generated-process ]] && selected "$name"; then needs_generated=yes; fi
done

export GOCACHE="${GOCACHE:-$root/.cache/go-build}"
export GOMODCACHE="${GOMODCACHE:-$root/.cache/go-mod}"
export GOTOOLCHAIN=local
bin_dir="${KNOWNDEVICE_BIN_DIR:-bin}"
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

# Lists every kd-* resource on the Docker host, including other runs'; nothing is removed.
leftovers() {
  local kind="$1" names status=0
  if [[ "$kind" == containers ]]; then
    names="$(docker ps -a --format '{{.Names}}' 2>/dev/null)" || status=$?
  else
    names="$(docker network ls --format '{{.Name}}' 2>/dev/null)" || status=$?
  fi
  if [[ "$status" -ne 0 ]]; then
    echo "unavailable (docker exit $status)"
    return 0
  fi
  names="$(printf '%s\n' "$names" | grep '^kd-' | tr '\n' ' ' || true)"
  names="${names% }"
  echo "${names:-none}"
}

# A failing command under set -e exits through the trap, which records the
# current step's FAIL line, so every step ends with a PASS, SKIP or FAIL line.
step=""
step_log=""
begin() { step="$1"; step_log="${2:-}"; }
pass() {
  echo "PASS $step (${1:-exit 0})" | tee -a "$summary"
  step=""
  step_log=""
}
skip() { echo "SKIP $1 ($2)" | tee -a "$summary"; }

project=""
compose_file=""
stop_cell() {
  [[ -n "$project" ]] || return 0
  # Appends, so an exit-time retry keeps the first attempt's output.
  docker compose -p "$project" -f "$compose_file" logs --no-color >> "$out/logs/$project-services.log" 2>&1 || true
  local status=0
  docker compose -p "$project" -f "$compose_file" down >> "$out/logs/$project-down.log" 2>&1 || status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "Compose down failed for $project; see $out/logs/$project-down.log" >&2
    return "$status"
  fi
  project=""
}

finish() {
  local status=$?
  set +e
  # A second signal must not cut cleanup short; the cost is that a signal
  # cannot interrupt a hanging compose down or docker listing here.
  trap '' HUP INT TERM
  if [[ "$status" -ne 0 ]]; then
    local failed="${step:-unrecorded step}"
    echo "FAIL $failed (exit $status); logs: $out/logs" | tee -a "$summary" >&2
    if [[ -n "$step_log" && -r "$step_log" ]]; then tail -n 40 "$step_log" >&2; fi
  fi
  # A project whose down failed stays set, so this retries it.
  local down=0
  stop_cell || down=$?
  if [[ "$down" -ne 0 ]]; then
    echo "FAIL $project cleanup at exit (exit $down)" | tee -a "$summary" >&2
    if [[ "$status" -eq 0 ]]; then status="$down"; fi
  fi
  {
    echo "load at end: $(load_average)"
    echo "kd-* containers after run: $(leftovers containers)"
    echo "kd-* networks after run: $(leftovers networks)"
    echo "finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >> "$summary"
  if [[ "$status" -eq 0 ]]; then
    echo "Matrix passed; data and logs: $out"
  else
    echo "Matrix failed; data and logs: $out" >&2
  fi
  exit "$status"
}

out="${KNOWNDEVICE_MATRIX_DIR:-$root/.work/lab-matrix-$arch-$run_id}"
if [[ -e "$out" ]]; then echo "Matrix directory already exists: $out" >&2; exit 2; fi
mkdir -p "$out/artifacts" "$out/logs"
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
  echo "cells: ${only:-all}"
  echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "load at start: $(load_average)"
} > "$summary"

# Docker Engine on Linux keeps host file ownership, and the journal and key
# store refuse files owned by another user, so containers run as the seeding
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
export KNOWNDEVICE_LAB_USER
host_arch="$(docker info --format '{{.Architecture}}')"
case "$host_arch" in x86_64) host_arch=amd64 ;; aarch64) host_arch=arm64 ;; esac
if [[ "$host_arch" == "$arch" ]]; then mode=native; else mode=emulated; fi
runtime="linux/$arch $mode on $host_arch Docker host ($(docker info --format '{{.OperatingSystem}}'))"
{
  echo "runtime: $runtime"
  echo "docker mode: $docker_mode"
  echo "container user: $KNOWNDEVICE_LAB_USER"
} >> "$summary"
pass

begin artifacts
# Mounted executables are private copies so a rebuild cannot change a running cell.
for name in kd-reference kd-profilelab kd-adaptergen; do cp "$bin_dir/$name" "$out/artifacts/"; done
for name in knowndevice kd-reference kd-profilelab kd-adapter; do cp "$bin_dir/$name-linux-$arch" "$out/artifacts/"; done
chmod a-w "$out"/artifacts/*
pass

if [[ "$needs_generated" == yes ]]; then
  begin adaptergen "$out/logs/adaptergen.log"
  "$out/artifacts/kd-adaptergen" --root "$out" --dir generated --name matrix-adapter \
    --module example.invalid/matrix-adapter --sdk-replace "$root" > "$step_log" 2>&1
  pass
  begin generated-ci "$out/logs/generated-ci.log"
  (cd "$out/generated" && ./scripts/ci.sh) > "$step_log" 2>&1
  pass
  begin generated-build "$out/logs/generated-build.log"
  mkdir -p "$out/generated-build"
  (cd "$out/generated" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -o "$out/generated-build/kd-adapter-linux-$arch" ./cmd/adapter) > "$step_log" 2>&1
  pass
else
  for name in adaptergen generated-ci generated-build; do skip "$name" "no selected cell uses the generated adapter"; done
fi

run_cell() {
  local cell="$1"
  project="$(printf 'kd-%s-%s' "$cell" "$run_id" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-\n' '-')"
  begin "$cell" "$out/logs/$cell-up.log"
  local status=0
  docker compose -p "$project" -f "$compose_file" up -d > "$step_log" 2>&1 || status=$?
  if [[ "$status" -eq 0 ]]; then
    step_log="$out/logs/$cell-checks.log"
    docker compose -p "$project" -f "$compose_file" run --rm checks > "$step_log" 2>&1 || status=$?
  fi
  local down=0
  stop_cell || down=$?
  if [[ "$status" -ne 0 ]]; then exit "$status"; fi
  if [[ "$down" -ne 0 ]]; then
    begin "$cell cleanup" "$out/logs/$project-down.log"
    exit "$down"
  fi
  pass "exit 0, $(grep -c '^PASS' "$step_log") checks"
}

cell=legacy-reference-builtin
if selected "$cell"; then
  dir="$out/$cell-linux-$arch"
  begin "$cell-linux-$arch seed" "$out/logs/$cell-linux-$arch-seed.log"
  "$out/artifacts/kd-reference" seed --dir "$dir" > "$step_log" 2>&1
  pass
  export KNOWNDEVICE_LAB_DIR="$dir" KNOWNDEVICE_LAB_ARCH="$arch" KNOWNDEVICE_LAB_BIN_DIR="$out/artifacts"
  compose_file=lab/compose.yaml
  run_cell "$cell-linux-$arch"
fi

compose_file=lab/profiles/compose.yaml
export KNOWNDEVICE_PROFILE_ARCH="$arch" KNOWNDEVICE_PROFILE_RUNTIME="$runtime"
for adapter in builtin generated-process; do
  for profile in reference-generation-cn stable-device-cn; do
    selected "$profile-$adapter" || continue
    cell="$profile-$adapter-linux-$arch"
    dir="$out/$cell"
    args=(seed --dir "$dir" --profile "$profile"
      --service-artifact "$out/artifacts/kd-profilelab-linux-$arch"
      --controller-artifact "$out/artifacts/knowndevice-linux-$arch")
    if [[ "$adapter" == generated-process ]]; then
      args+=(--process-artifact "$out/generated-build/kd-adapter-linux-$arch")
    fi
    begin "$cell seed" "$out/logs/$cell-seed.log"
    "$out/artifacts/kd-profilelab" "${args[@]}" > "$step_log" 2>&1
    if [[ "$adapter" == builtin ]]; then cp "$out/artifacts/kd-adapter-linux-$arch" "$dir/artifacts/"; fi
    pass
    export KNOWNDEVICE_PROFILE_DIR="$dir" KNOWNDEVICE_PROFILE_BIN_DIR="$dir/artifacts"
    run_cell "$cell"
  done
done
