#!/bin/bash
#
# run-fuzz-smoke.sh - Build fuzzers + run a short smoke pass
#

set -euo pipefail

BUILD_DIR="${1:-build.fuzz}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=clang \
  -DBUILD_TESTING=OFF \
  -DBUILD_BENCHMARKS=OFF \
  -DBUILD_FUZZERS=ON \
  -DENABLE_ASAN=ON \
  -DENABLE_UBSAN=ON

cmake --build "$BUILD_DIR" -j "$JOBS"

for fuzzer in "$BUILD_DIR"/bin/fuzz_*; do
  echo "[fuzz-smoke] $fuzzer"
  "$fuzzer" -runs=1000 >/dev/null
done

