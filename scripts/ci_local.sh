#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
mode="${1:-all}"
case "$mode" in all|test|build|docs) ;; *) echo "Usage: bash scripts/ci_local.sh [all|test|build|docs]" >&2; exit 2 ;; esac

python="${KNOWNDEVICE_PYTHON:-}"
if [[ -z "$python" ]]; then
  for candidate in python3 python3.14 python3.13 python3.12 python3.11; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
      python="$candidate"
      break
    fi
  done
fi
if [[ -z "$python" ]]; then echo "Python 3.11+ is required; no tools were installed." >&2; exit 2; fi
"$python" -c 'import sys; sys.exit(sys.version_info < (3, 11))'
export PYTHONDONTWRITEBYTECODE=1
export GOCACHE="${GOCACHE:-$root/.cache/go-build}"
export GOMODCACHE="${GOMODCACHE:-$root/.cache/go-mod}"
export GOTOOLCHAIN=local
check_dir="${KNOWNDEVICE_CHECK_DIR:-.cache/checks}"
binary_dir="${KNOWNDEVICE_BIN_DIR:-bin}"
mkdir -p "$check_dir" "$binary_dir"

gate() {
  local name="$1"
  shift
  if "$@" >"$check_dir/$name.log" 2>&1; then
    echo "PASS $name"
  else
    local status=$?
    echo "FAIL $name (exit $status); log: $check_dir/$name.log" >&2
    tail -n 50 "$check_dir/$name.log" >&2
    exit "$status"
  fi
}

external_sdk() {
  (
    cd examples/sdk-consumer
    go test -race -count=1 ./...
    go run .
  )
}

if [[ "$mode" == all || "$mode" == docs ]]; then
  gate repository "$python" scripts/check_repository.py
fi
if [[ "$mode" == all || "$mode" == test ]]; then
  gate script-tests "$python" -m unittest discover -s tests/scripts -p 'test_*.py' -v
  gate go-format "$python" -c 'import pathlib, subprocess, sys; files = [str(p) for folder in ("cmd", "internal", "adapters", "api", "sdk", "examples") for p in pathlib.Path(folder).rglob("*.go")]; r = subprocess.run(["gofmt", "-l", *files], capture_output=True, text=True); print(r.stdout, end=""); print(r.stderr, end="", file=sys.stderr); sys.exit(r.returncode or bool(r.stdout))'
  gate go-vet go vet ./...
  gate go-race go test -race -count=1 ./...
  gate sdk-external external_sdk
fi
if [[ "$mode" == all || "$mode" == build ]]; then
  gate build-native go build -trimpath -o "$binary_dir/knowndevice" ./cmd/knowndevice
  gate build-linux-amd64 env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$binary_dir/knowndevice-linux-amd64" ./cmd/knowndevice
  gate build-linux-arm64 env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$binary_dir/knowndevice-linux-arm64" ./cmd/knowndevice
  gate reference-native go build -trimpath -o "$binary_dir/kd-reference" ./cmd/kd-reference
  gate reference-linux-amd64 env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$binary_dir/kd-reference-linux-amd64" ./cmd/kd-reference
  gate reference-linux-arm64 env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$binary_dir/kd-reference-linux-arm64" ./cmd/kd-reference
fi

if [[ "$mode" == all || "$mode" == build ]]; then
  gate profiles-native go build -trimpath -o "$binary_dir/kd-profilelab" ./cmd/kd-profilelab
  gate profiles-linux-amd64 env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$binary_dir/kd-profilelab-linux-amd64" ./cmd/kd-profilelab
  gate profiles-linux-arm64 env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$binary_dir/kd-profilelab-linux-arm64" ./cmd/kd-profilelab
  gate adapter-native go build -trimpath -o "$binary_dir/kd-adapter" ./cmd/kd-adapter
  gate adapter-linux-amd64 env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$binary_dir/kd-adapter-linux-amd64" ./cmd/kd-adapter
  gate adapter-linux-arm64 env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$binary_dir/kd-adapter-linux-arm64" ./cmd/kd-adapter
  gate generator-native go build -trimpath -o "$binary_dir/kd-adaptergen" ./cmd/kd-adaptergen
  gate generator-linux-amd64 env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$binary_dir/kd-adaptergen-linux-amd64" ./cmd/kd-adaptergen
  gate generator-linux-arm64 env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$binary_dir/kd-adaptergen-linux-arm64" ./cmd/kd-adaptergen
fi
