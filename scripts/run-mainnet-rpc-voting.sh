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
: "${ENTRYPOINTS:=entrypoint.mainnet-beta.solana.com:8001,entrypoint2.mainnet-beta.solana.com:8001,entrypoint3.mainnet-beta.solana.com:8001,entrypoint4.mainnet-beta.solana.com:8001,entrypoint5.mainnet-beta.solana.com:8001}"
export GOSSIP_PORT TPU_PORT TVU_PORT RPC_PORT RPC_BIND ENTRYPOINTS

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
# Keep TVU intake and replay selection tighter under backlog so replay threads
# stay focused on near-frontier slots on combined RPC+voting nodes.
: "${SOL_TVU_MAX_SHRED_AHEAD_SLOTS:=3072}"
: "${SOL_TVU_MAX_SHRED_AHEAD_HIGH_LAG:=1024}"
: "${SOL_TVU_MAX_SHRED_AHEAD_HIGH_SLOTS:=768}"
: "${SOL_TVU_MAX_SHRED_AHEAD_SEVERE_LAG:=4096}"
: "${SOL_TVU_MAX_SHRED_AHEAD_SEVERE_SLOTS:=384}"
: "${SOL_TVU_MAX_REPLAY_AHEAD_SLOTS:=768}"
: "${SOL_TVU_MAX_REPLAY_AHEAD_HIGH_LAG:=384}"
: "${SOL_TVU_MAX_REPLAY_AHEAD_HIGH_SLOTS:=48}"
: "${SOL_TVU_MAX_REPLAY_AHEAD_SEVERE_LAG:=896}"
: "${SOL_TVU_MAX_REPLAY_AHEAD_SEVERE_SLOTS:=16}"
: "${SOL_TVU_PRIMARY_DEAD_REPLAY_AHEAD_SLOTS:=4}"
: "${SOL_TVU_PRIMARY_INCOMPLETE_RETRY_MS:=750}"
# If primary replay keeps returning INCOMPLETE with the same complete variant,
# back off retries to avoid pinning replay on a stale duplicate variant.
: "${SOL_TVU_PRIMARY_INCOMPLETE_SAME_VARIANT_BACKOFF_MS:=5000}"
# Reduce duplicate-repair amplification while retaining dead-primary recovery.
: "${SOL_TVU_DEAD_PRIMARY_DUPLICATE_FANOUT:=32}"
: "${SOL_TVU_DEAD_PRIMARY_HIGHEST_FANOUT:=24}"
: "${SOL_TVU_DEAD_PRIMARY_ORPHAN_FANOUT:=4}"
: "${SOL_TVU_DEAD_PRIMARY_ANCESTOR_FANOUT:=4}"
# Repair pacing tuned for WAN entrypoints: reduce timeout/retry churn.
: "${SOL_REPAIR_REQUEST_TIMEOUT_MS:=120}"
: "${SOL_REPAIR_MAX_PENDING:=16384}"
: "${SOL_REPAIR_MAX_RETRIES:=6}"
# Keep replay-thread fanout conservative on combined RPC+voting nodes to avoid
# cross-slot replay convoy stalls under backlog.
: "${SOL_TVU_REPLAY_THREADS:=4}"
# Prefer async replay verify with bounded wait. This reduces sync verify
# outliers while preserving deterministic fallback via wait budget.
: "${SOL_REPLAY_VERIFY_ASYNC:=1}"
# Keep replay verify workers below CPU-count scaling on combined RPC+voting
# nodes to leave headroom for replay + networking threads.
: "${SOL_REPLAY_VERIFY_WORKERS:=24}"
# Bound async-verify wait before local fallback. Tune lower (or 0) when
# prioritizing strict latency over duplicate verify work.
: "${SOL_REPLAY_VERIFY_WAIT_BUDGET_MS:=192}"
# Keep replay queue waits bounded to avoid multi-second convoy stalls. The
# runtime defaults are core-count aware; we pin the canary profile to low-tail
# values for large-core RPC+voting nodes.
: "${SOL_TX_POOL_REPLAY_QUEUE_WAIT_LONG_BUDGET_MS:=160}"
# Let smaller replay batches fail over earlier instead of inheriting the long
# wait budget, which otherwise amplifies shard hot-spot tails.
: "${SOL_TX_POOL_REPLAY_NO_SEQ_FALLBACK_BATCH:=384}"
# Forced extra waits are opt-in; enabling them on busy shards can recreate
# multi-second replay outliers under contention.
: "${SOL_TX_POOL_REPLAY_FORCE_WAIT_ON_BUSY:=0}"
# Replay/tx scheduler tuning for large-core combined nodes: avoid oversubscription
# starvation while keeping enough execution throughput.
: "${SOL_TX_WORKERS:=96}"
: "${SOL_TX_PER_WORKER:=8}"
# Keep enough tx-pool shards for concurrent replay threads; too few shards can
# create multi-second queue convoys on busy mainnet slots.
: "${SOL_TX_POOL_SHARDS:=8}"
# Cap replay no-conflict batch size so one oversized dispatch doesn't monopolize
# a shard and create long-tail replay stragglers.
: "${SOL_TX_POOL_REPLAY_MAX_BATCH_TXS:=384}"
# Keep replay mostly sequential for stability, but allow very large replay
# batches to use tx-pool parallel mode.
: "${SOL_TX_REPLAY_SEQ_MAX_TXS:=1024}"
# Keep DAG ready-queue pop batches small to reduce worker work-hoarding and
# replay straggler tails on large-core hosts.
: "${SOL_TX_DAG_POP_BATCH:=1}"
# With tx indexing disabled on canary nodes, skip replay batch tx-status cache
# writes to avoid mutex-heavy tail spikes in process_tx.
: "${SOL_TX_STATUS_BATCH_RECORD:=0}"
# BPF ELF cache sizing for large-memory validator hosts. Small caches can thrash
# on mainnet's long-tail program set and trigger load/parse stalls on replay.
: "${SOL_BPF_PROG_CACHE_MB:=8192}"
: "${SOL_BPF_PROG_CACHE_ENTRIES:=131072}"
# Replay prewarm: parse/cache a bounded number of instruction program ELFs
# ahead of execute to reduce cold-load replay tail spikes.
: "${SOL_REPLAY_PREWARM_BPF_PROGRAMS:=1}"
# On large-memory combined RPC+voting hosts, a higher replay prewarm program
# budget materially reduces BPF cold-load replay outliers during catchup.
: "${SOL_REPLAY_PREWARM_MAX_PROGRAMS:=16384}"
# Prewarm more program variants up-front to reduce first-hit variant stalls.
: "${SOL_REPLAY_PREWARM_MAX_VARIANTS:=64}"
# Also prewarm readonly account views to reduce deep-CPI cold-load stalls.
: "${SOL_REPLAY_PREWARM_INCLUDE_READONLY:=1}"
# Bound in-flight BPF load wait before local fallback. A tighter budget avoids
# rare multi-second replay execute stalls on cold-loader contention.
: "${SOL_BPF_LOAD_WAIT_BUDGET_MS:=128}"

# Keep restart/catchup deterministic by default: reuse local snapshot archives
# and avoid long auto-refresh/download churn. Set
# SOL_AUTO_SNAPSHOT_ALLOW_NETWORK_DOWNLOAD=1 when bootstrapping a fresh ledger.
: "${SOL_AUTO_SNAPSHOT_MAX_LAG_SLOTS:=0}"
: "${SOL_AUTO_SNAPSHOT_FORCE_REFRESH_LAG_SLOTS:=0}"
: "${SOL_AUTO_SNAPSHOT_ALLOW_NETWORK_DOWNLOAD:=0}"

export SOL_SKIP_TX_INDEX
export SOL_RPC_BACKPRESSURE SOL_RPC_BACKPRESSURE_ADAPTIVE_GROWTH
export SOL_RPC_BACKPRESSURE_HIGH_SLOTS SOL_RPC_BACKPRESSURE_SEVERE_SLOTS SOL_RPC_BACKPRESSURE_CLEAR_SLOTS
export SOL_RPC_BACKPRESSURE_HIGH_GROWTH_SLOTS SOL_RPC_BACKPRESSURE_SEVERE_GROWTH_SLOTS
export SOL_RPC_BACKPRESSURE_HIGH_RPS SOL_RPC_BACKPRESSURE_SEVERE_RPS
export SOL_RPC_BACKPRESSURE_HIGH_MAX_CONN SOL_RPC_BACKPRESSURE_SEVERE_MAX_CONN
export SOL_RPC_BACKPRESSURE_REJECT_MODE
export SOL_TVU_REPLAY_PARENT_PROBE_LIMIT SOL_TVU_REPLAY_PARENT_PROBE_HIGH_LAG SOL_TVU_REPLAY_PARENT_PROBE_SEVERE_LAG
export SOL_TVU_MAX_SHRED_AHEAD_SLOTS SOL_TVU_MAX_SHRED_AHEAD_HIGH_LAG SOL_TVU_MAX_SHRED_AHEAD_HIGH_SLOTS
export SOL_TVU_MAX_SHRED_AHEAD_SEVERE_LAG SOL_TVU_MAX_SHRED_AHEAD_SEVERE_SLOTS
export SOL_TVU_MAX_REPLAY_AHEAD_SLOTS SOL_TVU_MAX_REPLAY_AHEAD_HIGH_LAG SOL_TVU_MAX_REPLAY_AHEAD_HIGH_SLOTS
export SOL_TVU_MAX_REPLAY_AHEAD_SEVERE_LAG SOL_TVU_MAX_REPLAY_AHEAD_SEVERE_SLOTS
export SOL_TVU_PRIMARY_DEAD_REPLAY_AHEAD_SLOTS SOL_TVU_PRIMARY_INCOMPLETE_RETRY_MS
export SOL_TVU_PRIMARY_INCOMPLETE_SAME_VARIANT_BACKOFF_MS
export SOL_TVU_DEAD_PRIMARY_DUPLICATE_FANOUT SOL_TVU_DEAD_PRIMARY_HIGHEST_FANOUT
export SOL_TVU_DEAD_PRIMARY_ORPHAN_FANOUT SOL_TVU_DEAD_PRIMARY_ANCESTOR_FANOUT
export SOL_REPAIR_REQUEST_TIMEOUT_MS SOL_REPAIR_MAX_PENDING SOL_REPAIR_MAX_RETRIES
export SOL_TVU_REPLAY_THREADS
export SOL_REPLAY_VERIFY_ASYNC SOL_REPLAY_VERIFY_WORKERS SOL_REPLAY_VERIFY_WAIT_BUDGET_MS
export SOL_TX_POOL_REPLAY_QUEUE_WAIT_LONG_BUDGET_MS SOL_TX_POOL_REPLAY_NO_SEQ_FALLBACK_BATCH SOL_TX_POOL_REPLAY_FORCE_WAIT_ON_BUSY
export SOL_TX_WORKERS SOL_TX_PER_WORKER SOL_TX_POOL_SHARDS SOL_TX_POOL_REPLAY_MAX_BATCH_TXS SOL_TX_REPLAY_SEQ_MAX_TXS
export SOL_TX_DAG_POP_BATCH SOL_TX_STATUS_BATCH_RECORD
export SOL_BPF_PROG_CACHE_MB SOL_BPF_PROG_CACHE_ENTRIES
export SOL_REPLAY_PREWARM_BPF_PROGRAMS SOL_REPLAY_PREWARM_MAX_PROGRAMS SOL_REPLAY_PREWARM_MAX_VARIANTS SOL_REPLAY_PREWARM_INCLUDE_READONLY
export SOL_BPF_LOAD_WAIT_BUDGET_MS
export SOL_AUTO_SNAPSHOT_MAX_LAG_SLOTS SOL_AUTO_SNAPSHOT_FORCE_REFRESH_LAG_SLOTS
export SOL_AUTO_SNAPSHOT_ALLOW_NETWORK_DOWNLOAD

exec "$(dirname "$0")/run-mainnet-smoke.sh" "${LEDGER_DIR}"
