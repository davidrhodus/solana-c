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
#

set -euo pipefail

SOAK_DURATION_SEC="${1:-1800}"
LOCAL_RPC="${LOCAL_RPC:-http://127.0.0.1:8899}"
REMOTE_RPC="${REMOTE_RPC:-https://api.mainnet-beta.solana.com}"
LOG_FILE="${LOG_FILE:-ledger.mainnet/validator.log}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -f "${LOG_FILE}" ]]; then
  echo "error: LOG_FILE does not exist: ${LOG_FILE}" >&2
  exit 2
fi

echo "[canary-gate] local_rpc=${LOCAL_RPC} remote_rpc=${REMOTE_RPC} log=${LOG_FILE} soak=${SOAK_DURATION_SEC}s" >&2

echo "[canary-gate] health-check" >&2
RPC_URL="${LOCAL_RPC}" "${SCRIPT_DIR}/health-check.sh" all

echo "[canary-gate] rpc-smoke-jsonrpc" >&2
"${SCRIPT_DIR}/rpc-smoke-jsonrpc.sh" "${LOCAL_RPC}"

echo "[canary-gate] run-sync-soak" >&2
LOCAL_RPC="${LOCAL_RPC}" \
REMOTE_RPC="${REMOTE_RPC}" \
LOG_FILE="${LOG_FILE}" \
"${SCRIPT_DIR}/run-sync-soak.sh" "${SOAK_DURATION_SEC}"

echo "[canary-gate] PASS" >&2
