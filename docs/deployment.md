# Solana C Validator Deployment Guide

This guide covers deploying the Solana C validator for testnet and mainnet.

## Prerequisites

### Hardware Requirements

| Component | Testnet | Mainnet |
|-----------|---------|---------|
| CPU | 8+ cores | 16+ cores (32+ recommended) |
| RAM | 32 GB | 128 GB+ |
| Storage | 500 GB SSD | 2 TB NVMe SSD |
| Network | 100 Mbps | 1 Gbps+ |

### Software Requirements

- Ubuntu 22.04 LTS (recommended)
- CMake 3.16+
- GCC 11+ or Clang 14+
- Rust 1.70+ (for quiche)

## Installation

### Option 1: Build from Source

```bash
# Install dependencies
./scripts/install-deps.sh

# Build validator
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Verify installation
./bin/solana-validator --version
```

### Option 2: Docker

```bash
# Build image
docker build -t solana-c-validator .

# Run container
docker run -d --name validator \
  -v ./ledger:/ledger \
  -v ./config:/config \
  -p 8899:8899 -p 8001:8001 \
  solana-c-validator
```

## Configuration

### Generate Keypairs

```bash
# Generate identity keypair
./bin/sol-keygen new -o identity.json

# Generate vote account keypair
./bin/sol-vote create-keypair -o vote.json

# Show public keys
./bin/sol-keygen pubkey identity.json
./bin/sol-vote pubkey vote.json
```

### Create Vote Account

Before starting the validator, create a vote account on-chain:

```bash
# Using Solana CLI (requires SOL for account creation)
solana create-vote-account \
  vote.json \
  $(./bin/sol-keygen pubkey identity.json) \
  $(./bin/sol-keygen pubkey identity.json) \
  --commission 10
```

### Configuration File

Create a configuration file based on `config/testnet.toml`:

```toml
[validator]
identity_keypair = "./identity.json"
vote_account = "./vote.json"
ledger_path = "./ledger"

[network]
entrypoints = ["entrypoint.testnet.solana.com:8001"]

[logging]
level = "info"
format = "text"

[metrics]
enable = true
port = 9090
```

## Running the Validator

### Direct Execution

```bash
./bin/solana-validator \
  --config config/testnet.toml \
  --identity identity.json \
  --vote-account vote.json \
  --ledger ./ledger
```

### Systemd Service

```bash
# Copy service file
sudo cp scripts/solana-validator.service /etc/systemd/system/

# Edit configuration
sudo nano /etc/systemd/system/solana-validator.service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable solana-validator
sudo systemctl start solana-validator

# Check status
sudo systemctl status solana-validator
journalctl -u solana-validator -f
```

### Docker Compose

```bash
# Start validator
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Monitoring

### Health Endpoint

```bash
# Check health
curl http://localhost:8899/health

# Response: {"status":"ok"} or {"status":"unhealthy","reason":"..."}
```

### Prometheus Metrics

Metrics are available at `http://localhost:9090/metrics`:

```
# Key metrics
solana_slot_height              Current slot
solana_votes_submitted          Total votes submitted
solana_tpu_packets_received     TPU packets received
solana_tvu_shreds_received      TVU shreds received
solana_peers_connected          Connected gossip peers
```

### Grafana Dashboard

Start monitoring stack with docker-compose:

```bash
docker-compose --profile monitoring up -d

# Access Grafana at http://localhost:3000
# Default credentials: admin/admin
```

## Operations

### Check Sync Status

```bash
# Via RPC
curl -X POST http://localhost:8899 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getSlot"}'

# Via health endpoint
curl http://localhost:8899/health
```

### View Logs

```bash
# Systemd
journalctl -u solana-validator -f

# Docker
docker-compose logs -f validator

# Log file (if configured)
tail -f validator.log
```

### Restart Validator

```bash
# Systemd
sudo systemctl restart solana-validator

# Docker
docker-compose restart validator
```

## Parity Verification (Agave)

Before enabling voting on mainnet, you should prove that replayed slots produce
Solana-accurate bank hashes (and related inputs like signature count and last
blockhash). This repo includes a best-effort harness to compare solana-c vs an
Agave validator over a small replay window.

### Prerequisites

- Validator-grade storage with **large free space** (mainnet snapshot state is
  large; plan for **multiple TB** to run Agave + solana-c side-by-side).
- An Agave validator binary for the target mainnet release (as of Feb 2026:
  Agave `v3.1.8`). Point the harness at it via `AGAVE_VALIDATOR=...`. The
  harness warns when `AGAVE_EXPECT_VERSION` (default: `3.1.8`) doesn’t match
  `AGAVE_VALIDATOR --version` (set `AGAVE_EXPECT_VERSION=` to disable).
- Snapshot archives already present on disk (full + optional incremental).
- Open UDP ports for gossip/repair, and no conflicting validator processes.

### Run

```bash
# Optional (offline): sanity-check that vote accounts roundtrip exactly from a
# snapshot ledger (helps catch VoteState encoding regressions early).
./bin/sol-verify-vote-state --ledger ledger.mainnet --limit 5000

# Compare bank-hash parity across a short replay window (default 64 slots)
AGAVE_VALIDATOR=/path/to/agave-validator ./scripts/verify-agave-parity.sh --source-archives ledger.mainnet/snapshot-archives --cleanup
```

Useful knobs:

- `--workdir <DIR>`: Put the parity workdir on your large NVMe mount.
- `--timeout <SECONDS>` / `TIMEOUT_SECS=...`: Avoid hanging indefinitely if shreds can’t be repaired.
- `AGAVE_EXPECT_VERSION=3.1.8`: Warn on Agave version mismatches (set empty to disable).
- `AGAVE_USE_SNAPSHOT_ARCHIVES_AT_STARTUP=never`: Reuse Agave’s already-unpacked on-disk snapshot state.
- `SOL_ROCKSDB_BULK_NO_COMPRESSION=1`: Faster snapshot ingest, **much higher disk usage** (off by default).

Outputs (under the workdir):

- `agave.validator.log`, `solanac.validator.log`
- `agave.bank_frozen.tsv`, `solanac.bank_frozen.tsv`
- `mismatches.txt` (when mismatches are detected)

## Troubleshooting

### Common Issues

**Validator not syncing:**
- Check network connectivity to entrypoints
- Verify firewall allows ports 8001, 8003, 8004
- Check disk space and IOPS

**Snapshot bootstrap is slow:**
- Tune snapshot download parallelism: `SOL_SNAPSHOT_DOWNLOAD_CONNECTIONS=128` (defaults auto-scale up to 128 for very large archives)
- Tune snapshot ingest parallelism: `SOL_SNAPSHOT_LOAD_THREADS=64` (default caps at 96 to avoid RocksDB contention)
- Tune snapshot ingest batching (memory per thread): `SOL_SNAPSHOT_LOAD_MAX_BYTES_PER_THREAD_MB=512` (auto-scales based on RAM by default)
- Tune streaming ingest queues (for `.tar.zst`): `SOL_SNAPSHOT_STREAM_QUEUE_MAX`, `SOL_SNAPSHOT_STREAM_QUEUE_MAX_MB`, `SOL_SNAPSHOT_STREAM_CHUNK_QUEUE_MAX`, `SOL_SNAPSHOT_STREAM_CHUNK_MAX_MB`

**Validator restarts re-download/re-load snapshots:**
- Restarts prefer existing snapshot archives in `ledger/snapshot-archives/`
- If the AccountsDB has a persisted bootstrap state, restarts skip snapshot load entirely and start from the on-disk AccountsDB
- To force a full re-bootstrap, delete the AccountsDB RocksDB directory (e.g. `ledger/rocksdb/accounts`) and restart

**Vote transactions failing:**
- Verify vote account exists on-chain
- Check vote account has enough SOL for fees
- Verify identity keypair matches vote account authority

**High memory usage:**
- Consider enabling swap
- Reduce sigverify/banking threads
- Check for memory leaks in logs

### Debug Commands

```bash
# Check gossip peers
curl -X POST http://localhost:8899 \
  -d '{"jsonrpc":"2.0","id":1,"method":"getClusterNodes"}'

# Get vote accounts
curl -X POST http://localhost:8899 \
  -d '{"jsonrpc":"2.0","id":1,"method":"getVoteAccounts"}'

# Get validator info
curl -X POST http://localhost:8899 \
  -d '{"jsonrpc":"2.0","id":1,"method":"getIdentity"}'
```

## Security Recommendations

1. **Key Management**
   - Store keypairs securely (encrypted disk, HSM for mainnet)
   - Never expose identity keypair
   - Use separate keys for identity and vote authority

2. **Network**
   - Use firewall to restrict RPC access
   - Consider running RPC behind reverse proxy
   - Enable TLS for public endpoints

3. **Updates**
   - Subscribe to Solana security announcements
   - Test updates on testnet before mainnet
   - Have rollback plan ready

## Support

- GitHub Issues: https://github.com/solana-labs/solana-c/issues
- Solana Discord: https://discord.gg/solana
- Documentation: https://docs.solana.com
