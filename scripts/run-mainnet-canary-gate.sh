#!/usr/bin/env bash
#
# run-mainnet-canary-gate.sh - Combined gate for mainnet RPC+voting canary
#
# Runs:
#   1) health-check.sh all
#   2) rpc-smoke-jsonrpc.sh
#   3) run-sync-soak.sh
#
# Usage:
#   ./scripts/run-mainnet-canary-gate.sh [SOAK_DURATION_SEC]
#
# Optional env vars:
#   LOCAL_RPC=http://127.0.0.1:8899
#   REMOTE_RPC=https://api.mainnet-beta.solana.com
#   LOG_FILE=ledger.mainnet/validator.log
#   REQUIRE_VOTE_PROGRESS=1
#   MAX_SEVERE_MODE_EVENTS=6
#   MAX_SEVERE_MODE_RATIO=0.20
#

set -euo pipefail

SOAK_DURATION_SEC="${1:-1800}"
LOCAL_RPC="${LOCAL_RPC:-http://127.0.0.1:8899}"
REMOTE_RPC="${REMOTE_RPC:-https://api.mainnet-beta.solana.com}"
LOG_FILE="${LOG_FILE:-ledger.mainnet/validator.log}"
REQUIRE_VOTE_PROGRESS="${REQUIRE_VOTE_PROGRESS:-1}"
MAX_SEVERE_MODE_EVENTS="${MAX_SEVERE_MODE_EVENTS:-6}"
MAX_SEVERE_MODE_RATIO="${MAX_SEVERE_MODE_RATIO:-0.20}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -f "${LOG_FILE}" ]]; then
  echo "error: LOG_FILE does not exist: ${LOG_FILE}" >&2
  exit 2
fi

start_line="$(( $(wc -l < "${LOG_FILE}") + 1 ))"

echo "[canary-gate] local_rpc=${LOCAL_RPC} remote_rpc=${REMOTE_RPC} log=${LOG_FILE} soak=${SOAK_DURATION_SEC}s" >&2
echo "[canary-gate] log_window_start_line=${start_line}" >&2

echo "[canary-gate] health-check" >&2
RPC_URL="${LOCAL_RPC}" "${SCRIPT_DIR}/health-check.sh" all

echo "[canary-gate] rpc-smoke-jsonrpc" >&2
"${SCRIPT_DIR}/rpc-smoke-jsonrpc.sh" "${LOCAL_RPC}"

echo "[canary-gate] run-sync-soak" >&2
LOCAL_RPC="${LOCAL_RPC}" \
REMOTE_RPC="${REMOTE_RPC}" \
LOG_FILE="${LOG_FILE}" \
"${SCRIPT_DIR}/run-sync-soak.sh" "${SOAK_DURATION_SEC}"

echo "[canary-gate] analyze voting/backpressure window" >&2
python3 - "${LOG_FILE}" "${start_line}" "${REQUIRE_VOTE_PROGRESS}" "${MAX_SEVERE_MODE_EVENTS}" "${MAX_SEVERE_MODE_RATIO}" <<'PY'
import re
import sys
from pathlib import Path

log_path = Path(sys.argv[1])
start_line = int(sys.argv[2])
require_vote = int(sys.argv[3]) != 0
max_severe_events = int(sys.argv[4])
max_severe_ratio = float(sys.argv[5])

stats_votes_re = re.compile(r"Stats:.*\bvotes=([0-9]+)")
bp_mode_re = re.compile(r"RPC backpressure mode=([a-z]+)")

votes = []
mode_total = 0
mode_severe = 0

with log_path.open("r", encoding="utf-8", errors="replace") as f:
    for lineno, line in enumerate(f, start=1):
        if lineno < start_line:
            continue

        m = stats_votes_re.search(line)
        if m:
            votes.append(int(m.group(1)))

        m = bp_mode_re.search(line)
        if m:
            mode_total += 1
            if m.group(1) == "severe":
                mode_severe += 1

fail = []

if require_vote:
    if len(votes) < 2:
        fail.append(f"insufficient vote samples in log window ({len(votes)} < 2)")
    else:
        delta = votes[-1] - votes[0]
        print(f"vote_samples={len(votes)} votes_start={votes[0]} votes_end={votes[-1]} votes_delta={delta}")
        if delta <= 0:
            fail.append(f"vote counter did not increase (delta={delta})")
else:
    if len(votes) >= 2:
        delta = votes[-1] - votes[0]
        print(f"vote_samples={len(votes)} votes_start={votes[0]} votes_end={votes[-1]} votes_delta={delta}")
    else:
        print(f"vote_samples={len(votes)}")

if mode_total > 0:
    severe_ratio = mode_severe / mode_total
else:
    severe_ratio = 0.0
print(
    "backpressure_mode_events_total="
    f"{mode_total} severe_events={mode_severe} severe_ratio={severe_ratio:.3f}"
)

if mode_severe > max_severe_events:
    fail.append(
        f"severe backpressure events {mode_severe} exceed max {max_severe_events}"
    )
if mode_total > 0 and severe_ratio > max_severe_ratio:
    fail.append(
        f"severe backpressure ratio {severe_ratio:.3f} exceeds max {max_severe_ratio:.3f}"
    )

if fail:
    print("canary_window=FAIL")
    for item in fail:
        print(f"  - {item}")
    sys.exit(1)

print("canary_window=PASS")
PY

echo "[canary-gate] PASS" >&2
