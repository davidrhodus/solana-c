#!/usr/bin/env bash
#
# run-sync-soak.sh - Replay latency + sync-gap soak gate
#
# Usage:
#   ./scripts/run-sync-soak.sh [DURATION_SEC]
#
# Optional env vars:
#   LOCAL_RPC=http://127.0.0.1:8899
#   REMOTE_RPC=https://api.mainnet-beta.solana.com
#   LOG_FILE=ledger.mainnet/validator.log
#   INTERVAL_SEC=10
#   SLOT_COMMITMENT=processed
#   MAX_P95_MS=220
#   MAX_P99_MS=350
#

set -euo pipefail

DURATION_SEC="${1:-1800}"
LOCAL_RPC="${LOCAL_RPC:-http://127.0.0.1:8899}"
REMOTE_RPC="${REMOTE_RPC:-https://api.mainnet-beta.solana.com}"
LOG_FILE="${LOG_FILE:-ledger.mainnet/validator.log}"
INTERVAL_SEC="${INTERVAL_SEC:-10}"
SLOT_COMMITMENT="${SLOT_COMMITMENT:-processed}"
MAX_P95_MS="${MAX_P95_MS:-220}"
MAX_P99_MS="${MAX_P99_MS:-350}"

if ! [[ "${DURATION_SEC}" =~ ^[0-9]+$ ]] || (( DURATION_SEC < 60 )); then
  echo "error: DURATION_SEC must be >= 60" >&2
  exit 2
fi

if ! [[ "${INTERVAL_SEC}" =~ ^[0-9]+$ ]] || (( INTERVAL_SEC < 1 )); then
  echo "error: INTERVAL_SEC must be >= 1" >&2
  exit 2
fi

if [[ ! -f "${LOG_FILE}" ]]; then
  echo "error: log file not found: ${LOG_FILE}" >&2
  exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 2
fi

slot_query() {
  local url="$1"
  curl -s --max-time 4 \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSlot\",\"params\":[{\"commitment\":\"${SLOT_COMMITMENT}\"}]}" \
    "${url}" | sed -n 's/.*"result":\([0-9][0-9]*\).*/\1/p'
}

health_query() {
  local url="$1"
  curl -s --max-time 4 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' \
    "${url}" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p'
}

tmp_samples="$(mktemp)"
cleanup() {
  rm -f "${tmp_samples}"
}
trap cleanup EXIT

start_line="$(( $(wc -l < "${LOG_FILE}") + 1 ))"
start_ts="$(date +%s)"
end_ts="$((start_ts + DURATION_SEC))"

echo "sync_soak: duration=${DURATION_SEC}s interval=${INTERVAL_SEC}s commitment=${SLOT_COMMITMENT} local=${LOCAL_RPC} remote=${REMOTE_RPC}" >&2
echo "sync_soak: log=${LOG_FILE} start_line=${start_line}" >&2

while :; do
  now="$(date +%s)"
  if (( now >= end_ts )); then
    break
  fi

  local_slot="$(slot_query "${LOCAL_RPC}" || true)"
  remote_slot="$(slot_query "${REMOTE_RPC}" || true)"
  health="$(health_query "${LOCAL_RPC}" || true)"
  if [[ -z "${health}" ]]; then
    health="unknown"
  fi

  printf "%s %s %s %s\n" \
    "${now}" "${local_slot:-NA}" "${remote_slot:-NA}" "${health}" >> "${tmp_samples}"

  sleep "${INTERVAL_SEC}"
done

python3 - "${tmp_samples}" "${LOG_FILE}" "${start_line}" "${MAX_P95_MS}" "${MAX_P99_MS}" <<'PY'
import math
import re
import sys
from pathlib import Path

samples_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])
start_line = int(sys.argv[3])
max_p95 = float(sys.argv[4])
max_p99 = float(sys.argv[5])

rows = []
for raw in samples_path.read_text(encoding="utf-8", errors="replace").splitlines():
    parts = raw.strip().split()
    if len(parts) < 4:
        continue
    ts_s, l_s, r_s, health = parts[0], parts[1], parts[2], parts[3]
    try:
        ts = int(ts_s)
    except Exception:
        continue
    try:
        local = int(l_s)
        remote = int(r_s)
    except Exception:
        continue
    rows.append((ts, local, remote, health))

if len(rows) < 2:
    print("error: insufficient sync samples")
    sys.exit(2)

first = rows[0]
last = rows[-1]
dt = max(1, last[0] - first[0])

gap_start = first[2] - first[1]
gap_end = last[2] - last[1]
gap_delta = gap_end - gap_start
local_rate = (last[1] - first[1]) / dt
remote_rate = (last[2] - first[2]) / dt
health_last = last[3]

pat_replay_last = re.compile(r"Replay:\s+last_slot=\d+\s+slots=\d+\s+avg=[0-9.]+ms\s+last=([0-9]+(?:\.[0-9]+)?)ms")
pat_replay_total = re.compile(r"Replay timing:\s+slot=\d+\s+total=([0-9]+(?:\.[0-9]+)?)ms")
vals = []
if log_path.is_file():
    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, start=1):
            if lineno < start_line:
                continue
            m2 = pat_replay_total.search(line)
            if m2:
                vals.append(float(m2.group(1)))
                continue
            m1 = pat_replay_last.search(line)
            if m1:
                vals.append(float(m1.group(1)))

vals.sort()

def pct(v, p):
    if not v:
        return 0.0
    if len(v) == 1:
        return v[0]
    i = (p / 100.0) * (len(v) - 1)
    lo = int(math.floor(i))
    hi = int(math.ceil(i))
    if lo == hi:
        return v[lo]
    frac = i - lo
    return v[lo] + (v[hi] - v[lo]) * frac

replay_n = len(vals)
p50 = pct(vals, 50.0)
p90 = pct(vals, 90.0)
p95 = pct(vals, 95.0)
p99 = pct(vals, 99.0)
pmax = vals[-1] if vals else 0.0

print(f"sync_n={len(rows)} gap_start={gap_start} gap_end={gap_end} gap_delta={gap_delta}")
print(f"sync_rates local={local_rate:.3f} remote={remote_rate:.3f} health_last={health_last}")
print(f"replay_n={replay_n} p50={p50:.2f}ms p90={p90:.2f}ms p95={p95:.2f}ms p99={p99:.2f}ms max={pmax:.2f}ms")

fail = []
if gap_delta >= 0:
    fail.append(f"gap did not shrink (delta={gap_delta})")
if local_rate < remote_rate:
    fail.append(f"local replay rate below chain rate ({local_rate:.3f} < {remote_rate:.3f})")
if replay_n < 64:
    fail.append(f"insufficient replay samples ({replay_n} < 64)")
else:
    if p95 > max_p95:
        fail.append(f"p95 {p95:.2f}ms > {max_p95:.2f}ms")
    if p99 > max_p99:
        fail.append(f"p99 {p99:.2f}ms > {max_p99:.2f}ms")

if fail:
    print("sync_soak=FAIL")
    for item in fail:
        print(f"  - {item}")
    sys.exit(1)

print("sync_soak=PASS")
PY
