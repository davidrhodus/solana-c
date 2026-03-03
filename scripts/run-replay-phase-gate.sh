#!/usr/bin/env bash
#
# run-replay-phase-gate.sh - Multi-phase replay benchmark + latency gate
#
# Usage:
#   ./scripts/run-replay-phase-gate.sh [LEDGER_ROOT]
#
# Optional env vars:
#   BIN=./build.local/bin/solana-validator
#   MANIFEST_URL=https://data.pipedev.network/snapshot-manifest.json
#   SLOTS_PER_PHASE=512
#   START_SLOT=<manifest start slot override>
#   MIN_SAMPLES=128
#   MAX_P95_MS=200
#   MAX_P99_MS=350
#   MAX_MAX_MS=700
#   ALLOWED_REGRESSION_PCT=10
#

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LEDGER_ROOT="${1:-ledger.replay.phase}"
OUT_DIR="${OUT_DIR:-${LEDGER_ROOT}/results}"
BIN="${BIN:-${ROOT_DIR}/build.local/bin/solana-validator}"
MANIFEST_URL="${MANIFEST_URL:-https://data.pipedev.network/snapshot-manifest.json}"
SLOTS_PER_PHASE="${SLOTS_PER_PHASE:-512}"
MIN_SAMPLES="${MIN_SAMPLES:-128}"
MAX_P95_MS="${MAX_P95_MS:-200}"
MAX_P99_MS="${MAX_P99_MS:-350}"
MAX_MAX_MS="${MAX_MAX_MS:-700}"
ALLOWED_REGRESSION_PCT="${ALLOWED_REGRESSION_PCT:-10}"

ANALYZER="${ROOT_DIR}/scripts/replay-latency-percentiles.py"
RUNNER="${ROOT_DIR}/scripts/run-mainnet-smoke.sh"

if [[ ! -x "${BIN}" ]]; then
  BIN="${ROOT_DIR}/build/bin/solana-validator"
fi
if [[ ! -x "${BIN}" ]]; then
  echo "error: validator binary not found (set BIN=...)" >&2
  exit 1
fi
if [[ ! -x "${ANALYZER}" ]]; then
  echo "error: analyzer missing or not executable: ${ANALYZER}" >&2
  exit 1
fi
if [[ ! -x "${RUNNER}" ]]; then
  echo "error: smoke runner missing or not executable: ${RUNNER}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

start_slot_from_manifest() {
  python3 - <<'PY' "${MANIFEST_URL}"
import json
import sys
import urllib.request

url = sys.argv[1]
with urllib.request.urlopen(url, timeout=20) as r:
    data = json.loads(r.read().decode("utf-8"))
full = data.get("full_snapshot") or {}
full_slot = int(full.get("slot") or 0)
best_inc = 0
for inc in data.get("incremental_snapshots") or []:
    try:
        if int(inc.get("base_slot") or 0) != full_slot:
            continue
        s = int(inc.get("slot") or 0)
        if s > best_inc:
            best_inc = s
    except Exception:
        pass
start = best_inc or full_slot
print(start)
PY
}

metric_from_line() {
  local line="$1"
  local key="$2"
  python3 - <<'PY' "${line}" "${key}"
import re
import sys
line = sys.argv[1]
key = sys.argv[2]
m = re.search(rf"{re.escape(key)}=([0-9]+(?:\.[0-9]+)?)ms", line)
print(m.group(1) if m else "")
PY
}

run_phase() {
  local phase="$1"
  local halt_at="$2"
  local ledger="${LEDGER_ROOT}/${phase}"
  local log="${ledger}/validator.log"
  local metrics_file="${OUT_DIR}/${phase}.metrics"

  mkdir -p "${ledger}"
  rm -f "${log}"

  echo "[phase:${phase}] ledger=${ledger} halt_at=${halt_at}" >&2
  (
    export BIN
    export LOG_FILE="${log}"
    export HALT_AT="${halt_at}"
    export MANIFEST_URL
    export SOL_LOG_REPLAY_SLOTS=1

    # Baseline knobs (close to pre-tuning behaviour) before phase overrides.
    export SOL_AUTO_ROOT_PERIOD_MS=2000
    export SOL_AUTO_ROOT_ADAPTIVE=0
    export SOL_TX_PER_WORKER=1
    export SOL_TX_DAG_SCHED=0
    export SOL_TX_WAVE_SCHED=1

    case "${phase}" in
      baseline)
        ;;
      auto_root)
        export SOL_AUTO_ROOT_PERIOD_MS=500
        export SOL_AUTO_ROOT_ADAPTIVE=1
        ;;
      tx_workers)
        export SOL_TX_PER_WORKER=4
        ;;
      root_plus_workers)
        export SOL_AUTO_ROOT_PERIOD_MS=500
        export SOL_AUTO_ROOT_ADAPTIVE=1
        export SOL_TX_PER_WORKER=4
        ;;
      dag)
        export SOL_AUTO_ROOT_PERIOD_MS=500
        export SOL_AUTO_ROOT_ADAPTIVE=1
        export SOL_TX_PER_WORKER=4
        export SOL_TX_DAG_SCHED=1
        ;;
      all)
        export SOL_AUTO_ROOT_PERIOD_MS=500
        export SOL_AUTO_ROOT_ADAPTIVE=1
        export SOL_TX_PER_WORKER=4
        export SOL_TX_DAG_SCHED=1
        export SOL_TX_DAG_POP_BATCH=16
        ;;
      *)
        echo "error: unknown phase ${phase}" >&2
        exit 1
        ;;
    esac

    exec "${RUNNER}" "${ledger}"
  )

  local analyzer_args=(
    "${ANALYZER}"
    "${log}"
    --min-samples "${MIN_SAMPLES}"
  )
  if [[ "${phase}" == "all" ]]; then
    analyzer_args+=(
      --max-p95 "${MAX_P95_MS}"
      --max-p99 "${MAX_P99_MS}"
      --max-max "${MAX_MAX_MS}"
    )
  fi

  local metrics
  metrics="$("${analyzer_args[@]}")"
  echo "${metrics}" | tee "${metrics_file}"
}

START_SLOT="${START_SLOT:-}"
if [[ -z "${START_SLOT}" ]]; then
  START_SLOT="$(start_slot_from_manifest)"
fi
if ! [[ "${START_SLOT}" =~ ^[0-9]+$ ]] || (( START_SLOT == 0 )); then
  echo "error: invalid START_SLOT=${START_SLOT}" >&2
  exit 1
fi
if ! [[ "${SLOTS_PER_PHASE}" =~ ^[0-9]+$ ]] || (( SLOTS_PER_PHASE < 32 )); then
  echo "error: SLOTS_PER_PHASE must be >= 32 (got ${SLOTS_PER_PHASE})" >&2
  exit 1
fi

phases=(baseline auto_root tx_workers root_plus_workers dag all)
prev_p95=""
for phase in "${phases[@]}"; do
  halt_at=$((START_SLOT + SLOTS_PER_PHASE))
  run_phase "${phase}" "${halt_at}"
  line="$(cat "${OUT_DIR}/${phase}.metrics")"
  p95="$(metric_from_line "${line}" "p95")"
  if [[ -n "${prev_p95}" && -n "${p95}" ]]; then
    regress_ok="$(python3 - <<'PY' "${prev_p95}" "${p95}" "${ALLOWED_REGRESSION_PCT}"
import sys
prev = float(sys.argv[1])
cur = float(sys.argv[2])
allowed_pct = float(sys.argv[3])
limit = prev * (1.0 + allowed_pct / 100.0)
print("1" if cur <= limit else "0")
PY
)"
    if [[ "${regress_ok}" != "1" ]]; then
      echo "error: phase ${phase} regressed too far: prev_p95=${prev_p95}ms cur_p95=${p95}ms allowed=${ALLOWED_REGRESSION_PCT}%" >&2
      exit 1
    fi
  fi
  prev_p95="${p95}"
done

echo "replay_phase_gate=PASS"
