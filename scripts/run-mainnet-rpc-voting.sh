#!/usr/bin/env bash
#
# run-mainnet-rpc-voting.sh - Mainnet combined RPC+voting canary profile
#
# Usage:
#   IDENTITY_PATH=/path/to/identity.json \
#   VOTE_ACCOUNT=/path/to/vote-account.json \
#   ./scripts/run-mainnet-rpc-voting.sh [LEDGER_DIR]
#
# Notes:
# - Wraps run-mainnet-smoke.sh with ENABLE_VOTING=1.
# - Applies replay-protective RPC/backpressure defaults for a single-node
#   combined RPC+voting canary. Override any env as needed.
#

set -euo pipefail

LEDGER_DIR="${1:-ledger.mainnet}"

: "${IDENTITY_PATH:?set IDENTITY_PATH=/path/to/identity.json}"
: "${VOTE_ACCOUNT:?set VOTE_ACCOUNT=/path/to/vote-account.json or base58 vote pubkey}"

export ENABLE_VOTING=1
export IDENTITY_PATH
export VOTE_ACCOUNT

# Continuous mode by default (no auto-halt).
: "${HALT_AT:=}"
export HALT_AT

# Conservative networking defaults for a dedicated validator host.
: "${GOSSIP_PORT:=8001}"
: "${TPU_PORT:=8003}"
: "${TVU_PORT:=8004}"
: "${RPC_PORT:=8899}"
: "${RPC_BIND:=127.0.0.1}"
export GOSSIP_PORT TPU_PORT TVU_PORT RPC_PORT RPC_BIND

# Path defaults.
: "${ROCKSDB_PATH:=${LEDGER_DIR}/rocksdb}"
: "${LOG_FILE:=${LEDGER_DIR}/validator.log}"
export ROCKSDB_PATH LOG_FILE

# Replay-protective RPC behavior (override by exporting different values).
: "${SOL_SKIP_TX_INDEX:=1}"
: "${SOL_RPC_BACKPRESSURE:=1}"
: "${SOL_RPC_BACKPRESSURE_ADAPTIVE_GROWTH:=1}"
: "${SOL_RPC_BACKPRESSURE_HIGH_SLOTS:=192}"
: "${SOL_RPC_BACKPRESSURE_SEVERE_SLOTS:=768}"
: "${SOL_RPC_BACKPRESSURE_CLEAR_SLOTS:=96}"
: "${SOL_RPC_BACKPRESSURE_HIGH_GROWTH_SLOTS:=24}"
: "${SOL_RPC_BACKPRESSURE_SEVERE_GROWTH_SLOTS:=72}"
: "${SOL_RPC_BACKPRESSURE_HIGH_RPS:=350}"
: "${SOL_RPC_BACKPRESSURE_SEVERE_RPS:=120}"
: "${SOL_RPC_BACKPRESSURE_HIGH_MAX_CONN:=96}"
: "${SOL_RPC_BACKPRESSURE_SEVERE_MAX_CONN:=48}"
: "${SOL_RPC_BACKPRESSURE_REJECT_MODE:=2}"

# Replay scheduler probe budget under backlog.
: "${SOL_TVU_REPLAY_PARENT_PROBE_LIMIT:=48}"
: "${SOL_TVU_REPLAY_PARENT_PROBE_HIGH_LAG:=192}"
: "${SOL_TVU_REPLAY_PARENT_PROBE_SEVERE_LAG:=768}"

export SOL_SKIP_TX_INDEX
export SOL_RPC_BACKPRESSURE SOL_RPC_BACKPRESSURE_ADAPTIVE_GROWTH
export SOL_RPC_BACKPRESSURE_HIGH_SLOTS SOL_RPC_BACKPRESSURE_SEVERE_SLOTS SOL_RPC_BACKPRESSURE_CLEAR_SLOTS
export SOL_RPC_BACKPRESSURE_HIGH_GROWTH_SLOTS SOL_RPC_BACKPRESSURE_SEVERE_GROWTH_SLOTS
export SOL_RPC_BACKPRESSURE_HIGH_RPS SOL_RPC_BACKPRESSURE_SEVERE_RPS
export SOL_RPC_BACKPRESSURE_HIGH_MAX_CONN SOL_RPC_BACKPRESSURE_SEVERE_MAX_CONN
export SOL_RPC_BACKPRESSURE_REJECT_MODE
export SOL_TVU_REPLAY_PARENT_PROBE_LIMIT SOL_TVU_REPLAY_PARENT_PROBE_HIGH_LAG SOL_TVU_REPLAY_PARENT_PROBE_SEVERE_LAG

exec "$(dirname "$0")/run-mainnet-smoke.sh" "${LEDGER_DIR}"
