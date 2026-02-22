#!/bin/bash
#
# run-perf.sh - Build benchmarks and (optionally) run perf
#

set -euo pipefail

BUILD_DIR="${1:-build.perf}"
BENCH="${2:-bench_ed25519}"
shift 2 || true

JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=OFF \
  -DBUILD_BENCHMARKS=ON

cmake --build "$BUILD_DIR" -j "$JOBS"

BIN="$BUILD_DIR/bin/$BENCH"
if [[ ! -x "$BIN" ]]; then
  echo "benchmark not found: $BIN"
  exit 1
fi

if command -v perf >/dev/null 2>&1; then
  if perf stat true >/dev/null 2>&1; then
    exec perf stat "$BIN" "$@"
  fi
  echo "perf is installed but not permitted (check /proc/sys/kernel/perf_event_paranoid)."
  echo "Running benchmark without perf."
fi

exec "$BIN" "$@"

