#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$root"
arch="${1:-}"
case "$arch" in amd64|arm64) ;; *) echo "Usage: bash scripts/lab_matrix.sh amd64|arm64" >&2; exit 2 ;; esac

export GOCACHE="${GOCACHE:-$root/.cache/go-build}"
export GOMODCACHE="${GOMODCACHE:-$root/.cache/go-mod}"
export GOTOOLCHAIN=local
bin_dir="${KNOWNDEVICE_BIN_DIR:-bin}"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
out="${KNOWNDEVICE_MATRIX_DIR:-$root/.work/lab-matrix-$arch-$run_id}"
if [[ -e "$out" ]]; then echo "Matrix directory already exists: $out" >&2; exit 2; fi
mkdir -p "$out/artifacts" "$out/logs"
out="$(cd "$out" && pwd -P)"

host_arch="$(docker info --format '{{.Architecture}}')"
case "$host_arch" in x86_64) host_arch=amd64 ;; aarch64) host_arch=arm64 ;; esac
if [[ "$host_arch" == "$arch" ]]; then mode=native; else mode=emulated; fi
runtime="linux/$arch $mode on $host_arch Docker host ($(docker info --format '{{.OperatingSystem}}'))"
commit=unknown
# An exported copy inside another checkout must not report the outer repository's commit.
if [[ "$(git rev-parse --show-toplevel 2>/dev/null)" == "$root" ]]; then
  commit="$(git rev-parse HEAD)"
  if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then commit="$commit-dirty"; fi
fi
{
  echo "commit: $commit"
  echo "runtime: $runtime"
  echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$out/summary.txt"

# Mounted executables are private copies so a rebuild cannot change a running cell.
for name in kd-reference kd-profilelab kd-adaptergen; do cp "$bin_dir/$name" "$out/artifacts/"; done
for name in knowndevice kd-reference kd-profilelab kd-adapter; do cp "$bin_dir/$name-linux-$arch" "$out/artifacts/"; done
chmod a-w "$out"/artifacts/*

"$out/artifacts/kd-adaptergen" --root "$out" --dir generated --name matrix-adapter \
  --module example.invalid/matrix-adapter --sdk-replace "$root"
(cd "$out/generated" && ./scripts/ci.sh) > "$out/logs/generated-ci.log" 2>&1
mkdir -p "$out/generated-build"
(cd "$out/generated" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
  go build -trimpath -o "$out/generated-build/kd-adapter-linux-$arch" ./cmd/adapter)
echo "PASS generated-ci" | tee -a "$out/summary.txt"

project=""
compose_file=""
stop_cell() {
  [[ -n "$project" ]] || return 0
  docker compose -p "$project" -f "$compose_file" logs --no-color > "$out/logs/$project-services.log" 2>&1 || true
  local status=0
  docker compose -p "$project" -f "$compose_file" down > "$out/logs/$project-down.log" 2>&1 || status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "Compose down failed for $project; see $out/logs/$project-down.log" >&2
    return "$status"
  fi
  project=""
}
# A project whose down failed stays set, so the exit trap retries it.
trap 'stop_cell || true' EXIT

run_cell() {
  local cell="$1"
  project="$(printf 'kd-%s-%s' "$cell" "$run_id" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-\n' '-')"
  local status=0
  docker compose -p "$project" -f "$compose_file" up -d > "$out/logs/$cell-up.log" 2>&1 \
    && docker compose -p "$project" -f "$compose_file" run --rm checks > "$out/logs/$cell-checks.log" 2>&1 \
    || status=$?
  local down=0
  stop_cell || down=$?
  if [[ "$status" -ne 0 ]]; then
    echo "FAIL $cell (exit $status); logs: $out/logs" | tee -a "$out/summary.txt" >&2
    tail -n 40 "$out/logs/$cell-checks.log" >&2 || true
    exit "$status"
  fi
  if [[ "$down" -ne 0 ]]; then
    echo "FAIL $cell cleanup (compose down exit $down); logs: $out/logs" | tee -a "$out/summary.txt" >&2
    exit "$down"
  fi
  echo "PASS $cell ($(grep -c '^PASS' "$out/logs/$cell-checks.log") checks)" | tee -a "$out/summary.txt"
}

cell="legacy-reference-builtin-linux-$arch"
"$out/artifacts/kd-reference" seed --dir "$out/$cell"
export KNOWNDEVICE_LAB_DIR="$out/$cell" KNOWNDEVICE_LAB_ARCH="$arch" KNOWNDEVICE_LAB_BIN_DIR="$out/artifacts"
compose_file=lab/compose.yaml
run_cell "$cell"

compose_file=lab/profiles/compose.yaml
export KNOWNDEVICE_PROFILE_ARCH="$arch" KNOWNDEVICE_PROFILE_RUNTIME="$runtime"
for adapter in builtin generated-process; do
  for profile in reference-generation-cn stable-device-cn; do
    cell="$profile-$adapter-linux-$arch"
    dir="$out/$cell"
    args=(seed --dir "$dir" --profile "$profile"
      --service-artifact "$out/artifacts/kd-profilelab-linux-$arch"
      --controller-artifact "$out/artifacts/knowndevice-linux-$arch")
    if [[ "$adapter" == generated-process ]]; then
      args+=(--process-artifact "$out/generated-build/kd-adapter-linux-$arch")
    fi
    "$out/artifacts/kd-profilelab" "${args[@]}"
    if [[ "$adapter" == builtin ]]; then cp "$out/artifacts/kd-adapter-linux-$arch" "$dir/artifacts/"; fi
    export KNOWNDEVICE_PROFILE_DIR="$dir" KNOWNDEVICE_PROFILE_BIN_DIR="$dir/artifacts"
    run_cell "$cell"
  done
done
echo "finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$out/summary.txt"
echo "Matrix passed; data and logs: $out"
