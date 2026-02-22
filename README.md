# solana-c

Solana validator written in pure C (Linux x86_64).

## Build

```bash
# Optional: install dependencies (RocksDB, quiche, etc.)
./scripts/install-deps.sh

cmake -S . -B build.local
cmake --build build.local -j 8
```

## Tests

```bash
ctest --test-dir build.local --output-on-failure
```

## Run (dev)

```bash
./build.local/bin/solana-validator --help

# Example (see config/*.toml)
./build.local/bin/solana-validator --config config/testnet.toml
```

## Run (mainnet quickstart)

```bash
mkdir -p ledger.mainnet
# solana-validator will try to raise RLIMIT_NOFILE to 1,000,000 at startup.
# If that fails (common on constrained systems), set it manually:
# ulimit -n 1000000
./build.local/bin/solana-validator --ledger ledger.mainnet --rocksdb-path ledger.mainnet/rocksdb --no-voting --rpc-bind 0.0.0.0 --log-file ledger.mainnet/validator.log

# Optional: scripted end-to-end smoke bootstrap (best-effort stops a conflicting
# pipe-solana-validator systemd unit, and halts shortly after the snapshot slot)
bash ./scripts/run-mainnet-smoke.sh ledger.mainnet
```

## Snapshots (bootstrap)

- If no `--snapshot` is provided, `solana-validator` will try to auto-download a full snapshot archive (and the matching incremental, if available) into `<ledger>/snapshot-archives/` using `SOL_MAINNET_SNAPSHOT_MANIFEST_URL` (see `src/snapshot/sol_snapshot_download.h`).
- Large snapshots are downloaded using parallel HTTP range requests by default (64 connections; auto-scales up to 128 for very large archives) when the server supports it. Override via env: `SOL_SNAPSHOT_DOWNLOAD_CONNECTIONS` (max 128).
- On restarts, the validator prefers a persisted AccountsDB bootstrap state (skips snapshot ingest). If it lags the best available snapshot by >50k slots, it first attempts a fast refresh by applying a matching incremental snapshot to the existing AccountsDB; if unavailable, it falls back to a fresh snapshot load. Tune via CLI `--auto-snapshot-max-lag-slots`, config `snapshots.max_bootstrap_lag_slots`, or env `SOL_AUTO_SNAPSHOT_MAX_LAG_SLOTS` (0 disables refresh).
- After the first successful bootstrap, the validator persists additional cluster constants (genesis hash + shred version) into the AccountsDB bootstrap state so subsequent restarts don’t require RPC autodiscovery.
- Snapshot extraction prefers `pzstd` for large `.tar.zst` archives when available (faster than single-threaded decode). Tune via env: `SOL_SNAPSHOT_ARCHIVE_PZSTD_PROCESSES` and `SOL_SNAPSHOT_ARCHIVE_PZSTD=0/1`.
- Snapshot ingest uses a multi-threaded bulk writer (`SOL_SNAPSHOT_LOAD_THREADS`, auto-scales up to 96 threads by default) with a per-thread memory cap that auto-scales based on RAM (clamped to 32MB–1024MB per thread). Override via env: `SOL_SNAPSHOT_LOAD_MAX_BYTES_PER_THREAD_MB`.
- On large-memory hosts (>=128 GiB), AppendVec snapshot ingest defaults to deferring the accounts index build in RAM (fewer RocksDB writes, faster bootstrap). Disable via `SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX=0`. Tune via `SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX_SHARDS`, `SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX_CAPACITY_PER_SHARD`, and `SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX_FLUSH_THREADS` (defaults to up to 32).
- Streaming ingest (for `.tar.zst` archives) uses bounded queues; tune via env: `SOL_SNAPSHOT_STREAM_QUEUE_MAX`, `SOL_SNAPSHOT_STREAM_QUEUE_MAX_MB`, `SOL_SNAPSHOT_STREAM_CHUNK_QUEUE_MAX`, and `SOL_SNAPSHOT_STREAM_CHUNK_MAX_MB`.
- During snapshot ingest, RocksDB enters a bulk-load mode (WAL disabled, compactions disabled, larger write buffers). By default compression is disabled for speed; keep compression via env: `SOL_ROCKSDB_BULK_KEEP_COMPRESSION=1`.
- Downloads are written to `<archive>.partial` and atomically renamed on success; `.partial` files are resumed automatically.
- By default, snapshot accounts-hash verification is disabled to keep bootstrap time reasonable. Enable via CLI: `--verify-snapshot-accounts-hash` or config: `snapshots.verify_accounts_hash = true`.
- When enabled, the `snapshot-<slot>-<hash>` filename hash is verified against the computed accounts hash (and epoch accounts hash when available); mismatches fail bootstrap.
- Override via config: `snapshots.manifest_url = "..."` (see `config/validator.toml.example`).
- Optional fallback via config: `snapshots.rpc_urls = ["http://validator-rpc:8899", ...]`.
- Supported snapshot archive compressions: `.tar.zst`, `.tar.bz2`, `.tar.gz`, `.tar.lz4`, and plain `.tar` (auto-detected).

## Gossip (mainnet/testnet/devnet)

- `solana-validator` must advertise a correct `shred_version` and reachable TPU/TVU/repair/RPC sockets to participate in cluster gossip/turbine.
- To help validate bank-hash parity against mainnet vote traffic, set `SOL_LOG_BANK_FROZEN_VOTE_PARITY=1` to emit `bank frozen votes: ...` lines (best voted hash/weight vs local hash) after each frozen bank.
- Repair uses Agave-style ping/pong gating (server may ping first); the validator responds with a pong and resends one pending request after warming a peer.
- If a default port is already in use, startup will fail with `Address already in use`. Stop the conflicting process/service (e.g. `systemctl stop pipe-solana-validator`) or explicitly configure ports via CLI flags like `--gossip-port`, `--tpu-port`, `--tvu-port`, `--rpc-port`, and `--metrics-port`.
- If no entrypoint is configured, the validator defaults to the cluster entrypoint inferred from `snapshots.manifest_url` (`mainnet-beta` by default).
- If `network.shred_version = 0` (default), the validator auto-discovers the current shred version via `getClusterNodes` on an RPC URL:
  - `network.shred_version_rpc_url` (if set), otherwise
  - `snapshots.rpc_urls[0]` (if set), otherwise
  - an official endpoint inferred from `network.entrypoints[0]` (mainnet/testnet/devnet).
- If `network.advertise_ip` is not set, the validator tries to infer an outbound IP from the first entrypoint route; override if you’re behind NAT or on multi-homed hosts.

## QUIC (TPU)

- QUIC is enabled when quiche is installed and detected by CMake.
- Disable via config: `network.enable_quic = false` or CLI: `--no-quic`.

## Storage (RocksDB)

- AccountsDB and Blockstore can use RocksDB when built with RocksDB support.
- Enable via config: `ledger.rocksdb_path = "/path/to/rocksdb"` or CLI: `--rocksdb-path /path/to/rocksdb` (uses `accounts/` and `blockstore/` subdirs).
- If built with RocksDB and `--rocksdb-path` is not set, defaults to `<ledger>/rocksdb`.
- AccountsDB defaults to an AppendVec-on-disk layout in `<ledger>/accounts/` with a small RocksDB `accounts_index` CF (faster snapshot ingest than storing full account blobs in RocksDB).

## Benchmarks

```bash
cmake -S . -B build.bench -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCHMARKS=ON
cmake --build build.bench -j 8

./build.bench/bin/bench_ed25519 --iters 1000000
./build.bench/bin/bench_shred --iters 1000000 --verify 1
./build.bench/bin/bench_accounts --iters 500000

# Optional: run under perf (if permitted by kernel settings)
./scripts/run-perf.sh build.perf bench_ed25519 --iters 1000000
```

## Security (dev)

```bash
./scripts/run-sanitizers.sh
./scripts/run-fuzz-smoke.sh
./scripts/run-dos-smoke.sh
./scripts/run-static-analysis.sh
./scripts/run-static-analysis.sh build.local --all --jobs 8
```

## Deployment

See `docs/deployment.md`.
