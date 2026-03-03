#!/usr/bin/env bash
#
# run-mainnet-smoke.sh - End-to-end mainnet bootstrap smoke run
#
# - Stops the legacy pipe-solana-validator systemd unit if present
# - Boots from snapshot (auto-downloads if missing)
# - Optionally halts shortly after snapshot slot is replayed (dev)
#
# Usage:
#   ./scripts/run-mainnet-smoke.sh [LEDGER_DIR]
#
# Optional env vars:
#   BIN=./build.local/bin/solana-validator
#   LOG_FILE=ledger.mainnet/validator.log
#   HALT_AT=123   # set empty to run continuously
#   MANIFEST_URL=https://data.pipedev.network/snapshot-manifest.json
#   ENABLE_VOTING=1   # default: 0 (smoke/non-voting mode)
#   IDENTITY_PATH=/path/to/identity.json   # required when ENABLE_VOTING=1
#   VOTE_ACCOUNT=/path/to/vote-account.json|<base58-pubkey>   # required when ENABLE_VOTING=1
#

set -euo pipefail

LEDGER_DIR="${1:-ledger.mainnet}"
BIN="${BIN:-./build.local/bin/solana-validator}"
LOG_FILE="${LOG_FILE:-${LEDGER_DIR}/validator.log}"
HALT_AT_PROVIDED=0
if [[ "${HALT_AT+x}" == "x" ]]; then
  HALT_AT_PROVIDED=1
fi
HALT_AT="${HALT_AT:-}"
MANIFEST_URL="${MANIFEST_URL:-${SOL_MAINNET_SNAPSHOT_MANIFEST_URL:-https://data.pipedev.network/snapshot-manifest.json}}"
ROCKSDB_PATH="${ROCKSDB_PATH:-${LEDGER_DIR}/rocksdb}"
GOSSIP_PORT="${GOSSIP_PORT:-8027}"
TPU_PORT="${TPU_PORT:-8026}"
TVU_PORT="${TVU_PORT:-8028}"
RPC_PORT="${RPC_PORT:-8899}"
RPC_BIND="${RPC_BIND:-127.0.0.1}"
ENABLE_VOTING="${ENABLE_VOTING:-0}"
IDENTITY_PATH="${IDENTITY_PATH:-${IDENTITY:-}}"
VOTE_ACCOUNT="${VOTE_ACCOUNT:-}"

case "${ENABLE_VOTING}" in
  1|true|TRUE|yes|YES|on|ON)
    ENABLE_VOTING=1
    ;;
  0|false|FALSE|no|NO|off|OFF|"")
    ENABLE_VOTING=0
    ;;
  *)
    echo "error: invalid ENABLE_VOTING=${ENABLE_VOTING} (expected 0/1)" >&2
    exit 1
    ;;
esac

if [[ ! -x "${BIN}" ]]; then
  BIN="./build/bin/solana-validator"
fi
if [[ ! -x "${BIN}" ]]; then
  echo "solana-validator binary not found (set BIN=...)" >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files --type=service 2>/dev/null | grep -q '^pipe-solana-validator\\.service'; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
      echo "Stopping pipe-solana-validator.service (best-effort)..." >&2
      sudo systemctl stop pipe-solana-validator.service >/dev/null 2>&1 || true
      sudo systemctl disable pipe-solana-validator.service >/dev/null 2>&1 || true
      # Prevent restarts during the smoke run without permanently mutating the host.
      sudo systemctl mask --runtime --now pipe-solana-validator.service >/dev/null 2>&1 || true
    else
      echo "warn: pipe-solana-validator.service present but sudo isn't non-interactive; stop it manually if you hit port conflicts." >&2
    fi
  fi
fi

mkdir -p "${LEDGER_DIR}"
mkdir -p "${LEDGER_DIR}/snapshot-archives"
mkdir -p "${ROCKSDB_PATH}"

# Best-effort: raise fd limit for gossip + RocksDB.
ulimit -n 1000000 >/dev/null 2>&1 || true

# Best-effort: keep CPUs at max frequency during bootstrap/replay.
# On some hosts the default governor ("schedutil") can leave cores stuck at low
# clocks, making snapshot load and replay look artificially slow.
if [[ -d /sys/devices/system/cpu/cpu0/cpufreq ]]; then
  if [[ -w /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
    echo "Setting CPU governor to performance (best-effort)..." >&2
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
      [[ -w "${gov}" ]] || continue
      echo performance > "${gov}" 2>/dev/null || true
    done
  elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    echo "Setting CPU governor to performance via sudo (best-effort)..." >&2
    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null 2>&1 || true
  fi
fi

if [[ -z "${HALT_AT}" && "${HALT_AT_PROVIDED}" -eq 0 ]]; then
  # Prefer the snapshot service manifest so the halt slot stays consistent even
  # when the validator refreshes stale local archives during bootstrap.
  halt_from_manifest=""
  if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    halt_from_manifest="$(
      curl -fsSL --connect-timeout 5 --max-time 20 "${MANIFEST_URL}" 2>/dev/null | \
        python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
full = data.get("full_snapshot") or {}
full_slot = int(full.get("slot") or 0)
best_inc = 0
for inc in (data.get("incremental_snapshots") or []):
    try:
        if int(inc.get("base_slot") or 0) != full_slot:
            continue
        s = int(inc.get("slot") or 0)
        if s > best_inc:
            best_inc = s
    except Exception:
        pass
start = best_inc or full_slot
if start > 0:
    print(start + 2)
' 2>/dev/null || true
    )"
  fi

  halt_from_local=""
  latest_snapshot="$(ls -1 "${LEDGER_DIR}"/snapshot-archives/snapshot-*-*.tar.* 2>/dev/null | tail -n 1 || true)"
  if [[ -n "${latest_snapshot}" ]]; then
    slot="$(basename "${latest_snapshot}" | sed -E 's/^snapshot-([0-9]+)-.*/\1/')"
    if [[ "${slot}" =~ ^[0-9]+$ ]]; then
      best_inc=0
      for inc in "${LEDGER_DIR}"/snapshot-archives/incremental-snapshot-"${slot}"-*.tar.*; do
        [[ -f "${inc}" ]] || continue
        inc_slot="$(basename "${inc}" | sed -E 's/^incremental-snapshot-[0-9]+-([0-9]+)-.*/\1/')"
        if [[ "${inc_slot}" =~ ^[0-9]+$ ]] && (( inc_slot > best_inc )); then
          best_inc="${inc_slot}"
        fi
      done
      if (( best_inc > 0 )); then
        halt_from_local="$((best_inc + 2))"
      else
        halt_from_local="$((slot + 2))"
      fi
    fi
  fi

  if [[ "${halt_from_manifest}" =~ ^[0-9]+$ && "${halt_from_local}" =~ ^[0-9]+$ ]]; then
    # Prefer the newer effective start slot. Some snapshot services publish only
    # full snapshots while RPC sources provide a fresher incremental.
    if (( halt_from_local > halt_from_manifest )); then
      HALT_AT="${halt_from_local}"
    else
      HALT_AT="${halt_from_manifest}"
    fi
  elif [[ "${halt_from_local}" =~ ^[0-9]+$ ]]; then
    HALT_AT="${halt_from_local}"
  elif [[ "${halt_from_manifest}" =~ ^[0-9]+$ ]]; then
    HALT_AT="${halt_from_manifest}"
  fi
fi

args=(
  --ledger "${LEDGER_DIR}"
  --rocksdb-path "${ROCKSDB_PATH}"
  --rpc-bind "${RPC_BIND}"
  --rpc-port "${RPC_PORT}"
  --log-level info
  --log-file "${LOG_FILE}"
  --entrypoint entrypoint.mainnet-beta.solana.com:8001
  --gossip-port "${GOSSIP_PORT}"
  --tpu-port "${TPU_PORT}"
  --tvu-port "${TVU_PORT}"
)

if [[ "${ENABLE_VOTING}" == "1" ]]; then
  if [[ -z "${IDENTITY_PATH}" ]]; then
    echo "error: ENABLE_VOTING=1 requires IDENTITY_PATH (or IDENTITY)" >&2
    exit 1
  fi
  if [[ ! -r "${IDENTITY_PATH}" ]]; then
    echo "error: identity keypair not readable: ${IDENTITY_PATH}" >&2
    exit 1
  fi
  if [[ -z "${VOTE_ACCOUNT}" ]]; then
    echo "error: ENABLE_VOTING=1 requires VOTE_ACCOUNT" >&2
    exit 1
  fi
  echo "Voting enabled: identity=${IDENTITY_PATH} vote_account=${VOTE_ACCOUNT}" >&2
  args+=(--identity "${IDENTITY_PATH}" --vote-account "${VOTE_ACCOUNT}")
else
  args+=(--no-voting)
fi

if [[ -n "${HALT_AT}" ]]; then
  echo "Dev smoke: halting once slot ${HALT_AT} is replayed." >&2
  args+=(--dev-halt-at-slot "${HALT_AT}")
fi

exec "${BIN}" "${args[@]}"
