#!/usr/bin/env bash
#
# run-mainnet.sh - End-to-end mainnet bootstrap (continuous)
#
# This is a thin wrapper around run-mainnet-smoke.sh that runs continuously by
# default (i.e. it does not auto-halt after a couple of slots).
#
# Usage:
#   ./scripts/run-mainnet.sh [LEDGER_DIR]
#
# Optional env vars:
#   BIN=./build.local/bin/solana-validator
#   LOG_FILE=ledger.mainnet/validator.log
#   HALT_AT=123   # set to halt once slot is replayed (dev)
#   ENABLE_VOTING=1
#   IDENTITY_PATH=/path/to/identity.json
#   VOTE_ACCOUNT=/path/to/vote-account.json|<base58-pubkey>
#

set -euo pipefail

LEDGER_DIR="${1:-ledger.mainnet}"

# Ensure HALT_AT is considered "provided" by the child script even when empty.
: "${HALT_AT:=}"
export HALT_AT

exec "$(dirname "$0")/run-mainnet-smoke.sh" "${LEDGER_DIR}"
