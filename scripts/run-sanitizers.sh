#!/bin/bash
#
# run-sanitizers.sh - Build + run tests under sanitizers
#

set -euo pipefail

BUILD_DIR="${1:-build.sanitize}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DENABLE_ASAN=ON \
  -DENABLE_UBSAN=ON

cmake --build "$BUILD_DIR" -j "$JOBS"
ctest --test-dir "$BUILD_DIR" --output-on-failure

