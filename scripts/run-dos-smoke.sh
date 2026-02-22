#!/bin/bash
#
# run-dos-smoke.sh - Longer-running fuzz pass with larger inputs/timeouts
#

set -euo pipefail

BUILD_DIR="${1:-build.dos}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

RUNS="${RUNS:-20000}"
MAX_LEN="${MAX_LEN:-65536}"
TIMEOUT="${TIMEOUT:-2}"

cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=clang \
  -DBUILD_TESTING=OFF \
  -DBUILD_BENCHMARKS=OFF \
  -DBUILD_FUZZERS=ON \
  -DENABLE_ASAN=ON \
  -DENABLE_UBSAN=ON

cmake --build "$BUILD_DIR" -j "$JOBS"

FUZZ_ARGS=(
  "-runs=$RUNS"
  "-max_len=$MAX_LEN"
  "-timeout=$TIMEOUT"
)

FUZZERS=(
  fuzz_rpc_handle_request_json
  fuzz_json_parser
  fuzz_config_parse
  fuzz_entry_batch_parse
  fuzz_transaction_decode
  fuzz_compute_budget_parse
  fuzz_shred_parse
  fuzz_gossip_msg_decode
  fuzz_pubkey_base58
  fuzz_signature_base58
)

for f in "${FUZZERS[@]}"; do
  bin="$BUILD_DIR/bin/$f"
  if [[ ! -x "$bin" ]]; then
    echo "[dos-smoke] missing fuzzer: $bin"
    exit 1
  fi
  echo "[dos-smoke] $bin"
  "$bin" "${FUZZ_ARGS[@]}" >/dev/null
done

