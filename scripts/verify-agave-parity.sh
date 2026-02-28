#!/usr/bin/env bash
#
# verify-agave-parity.sh
#
# Best-effort replay/bank-hash parity check between solana-c and an Agave validator.
# This is an integration harness intended for dev/testing, not CI.
#
# Requires:
# - solana-c validator built (default: ./build.local/bin/solana-validator)
# - Agave validator binary (default: /home/ubuntu/solanacdn-bin/pipe-solana-validator)
# - Pre-downloaded snapshot archives (full + optional incremental)
#
# Example:
#   ./scripts/verify-agave-parity.sh \
#     --source-archives ledger.mainnet/snapshot-archives \
#     --slots 64
#

set -euo pipefail

SOLANAC_BIN="${SOLANAC_VALIDATOR:-./build.local/bin/solana-validator}"
AGAVE_BIN="${AGAVE_VALIDATOR:-}"
if [[ -z "${AGAVE_BIN}" ]]; then
  if command -v agave-validator >/dev/null 2>&1; then
    AGAVE_BIN="$(command -v agave-validator)"
  else
    AGAVE_BIN="/home/ubuntu/solanacdn-bin/pipe-solana-validator"
  fi
fi
AGAVE_EXPECT_VERSION="${AGAVE_EXPECT_VERSION:-3.1.8}"
SNAPSHOT_FETCH_BIN="${SNAPSHOT_FETCH_BIN:-./build.local/bin/sol-snapshot-fetch}"
REFRESH_SNAPSHOTS="${REFRESH_SNAPSHOTS:-1}"
AGAVE_EXTRA_ARGS="${AGAVE_EXTRA_ARGS:-}"
SNAPSHOT_FETCH_RPC_URL="${SNAPSHOT_FETCH_RPC_URL:-}"
SOLANAC_LOG_LEVEL="${SOLANAC_LOG_LEVEL:-info}"
AGAVE_RESTRICTED_REPAIR_ONLY_MODE="${AGAVE_RESTRICTED_REPAIR_ONLY_MODE:-0}"
# Keep QUIC enabled by default for parity runs (matches mainnet behavior).
AGAVE_TPU_DISABLE_QUIC="${AGAVE_TPU_DISABLE_QUIC:-0}"
AGAVE_USE_DEV_HALT_AT_SLOT="${AGAVE_USE_DEV_HALT_AT_SLOT:-1}"
# If 1, pass --full-rpc-api to Agave (some versions crash with QUIC errors).
AGAVE_FULL_RPC_API="${AGAVE_FULL_RPC_API:-1}"

# Comma/space-separated list of entrypoints. Passed as repeatable --entrypoint
# args to both validators.
ENTRYPOINT="${ENTRYPOINT:-entrypoint.mainnet-beta.solana.com:8001,entrypoint2.mainnet-beta.solana.com:8001,entrypoint3.mainnet-beta.solana.com:8001}"
SLOTS="${SLOTS:-64}"
AGAVE_RUST_LOG="${AGAVE_RUST_LOG:-solana_runtime::bank=info}"
AGAVE_USE_SNAPSHOT_ARCHIVES_AT_STARTUP="${AGAVE_USE_SNAPSHOT_ARCHIVES_AT_STARTUP:-when-newest}"
GENESIS_RPC_URL="${GENESIS_RPC_URL:-https://api.mainnet-beta.solana.com}"
AGAVE_DISABLE_SOLANACDN_BUILDER="${AGAVE_DISABLE_SOLANACDN_BUILDER:-}"
if [[ -z "${AGAVE_DISABLE_SOLANACDN_BUILDER}" ]]; then
  if [[ "$(basename "$AGAVE_BIN")" == pipe-solana-validator* ]]; then
    AGAVE_DISABLE_SOLANACDN_BUILDER=1
  else
    AGAVE_DISABLE_SOLANACDN_BUILDER=0
  fi
fi
# Avoid colliding with any locally running validators (e.g. systemd units).
AGAVE_GOSSIP_PORT="${AGAVE_GOSSIP_PORT:-8031}"
# Agave needs a reasonably large dynamic port range for TPU/TVU/repair (+QUIC).
# Keep this non-overlapping with the default solana-c ports used below.
AGAVE_DYNAMIC_PORT_RANGE="${AGAVE_DYNAMIC_PORT_RANGE:-8100-8200}"
# Max wall time for each validator run (0 disables). Used to avoid harness hangs
# when shreds can't be repaired.
TIMEOUT_SECS="${TIMEOUT_SECS:-3600}"
# For parity runs, keep all required UDP ports within common validator firewall ranges.
# Also disable QUIC by default so we don't need to expose TPU+6.
SOLANAC_GOSSIP_PORT="${SOLANAC_GOSSIP_PORT:-8027}"
SOLANAC_TPU_PORT="${SOLANAC_TPU_PORT:-8026}"
SOLANAC_TVU_PORT="${SOLANAC_TVU_PORT:-8028}"

SOURCE_ARCHIVES=""
WORKDIR=""
PARALLEL=0
CLEANUP=0

OWN_SOLANAC_LEDGER=1
OWN_AGAVE_LEDGER=1
OWN_AGAVE_SNAPSHOTS=1

usage() {
  cat <<'EOF'
Usage: scripts/verify-agave-parity.sh [--source-archives DIR] [--workdir DIR] [--slots N] [--entrypoint HOST:PORT[,HOST:PORT...]] [--parallel] [--cleanup]

Options:
  --source-archives DIR   Directory containing snapshot archives (default: ./ledger.<network>/snapshot-archives)
  --workdir DIR           Working directory to create ledgers/logs (default: ./ledger.parity.<epoch>)
  --slots N               Number of slots to replay after snapshot start (default: 64)
  --entrypoint HOST:PORT  Gossip entrypoint (repeatable via comma-separated list) (default: entrypoint.mainnet-beta.solana.com:8001,entrypoint2...,entrypoint3...)
  --timeout SECONDS       Per-validator wall timeout (default: 3600, 0 disables)
  --parallel              Run Agave + solana-c simultaneously (faster, more load)
  --cleanup               Delete heavy ledgers after runs (keeps logs)

Environment:
  SOLANAC_VALIDATOR       Path to solana-c validator binary (default: ./build.local/bin/solana-validator)
  SOLANAC_LOG_LEVEL       solana-c log level (trace/debug/info/warn/error) (default: info)
  AGAVE_VALIDATOR         Path to Agave validator binary (default: /home/ubuntu/solanacdn-bin/pipe-solana-validator)
  AGAVE_EXPECT_VERSION    If set (default: 3.1.8), warn when Agave --version doesn't contain this string. Set empty to disable.
  SNAPSHOT_FETCH_BIN      Path to sol-snapshot-fetch helper (default: ./build.local/bin/sol-snapshot-fetch)
  REFRESH_SNAPSHOTS       If 1, refresh snapshot archives via sol-snapshot-fetch (default: 1)
  SNAPSHOT_FETCH_RPC_URL  (ignored) RPC URL for snapshot-fetch (manifest-only)
  SOLANAC_LEDGER_DIR      Reuse an existing solana-c ledger dir (default: <workdir>/solanac.ledger)
  AGAVE_LEDGER_DIR        Reuse an existing Agave ledger dir (default: <workdir>/agave.ledger)
  AGAVE_SNAPSHOTS_DIR     Reuse an existing Agave snapshots dir (default: <workdir>/agave.snapshots)
  AGAVE_IDENTITY_FILE     Reuse an existing Agave identity keypair json (default: <workdir>/agave.identity.json)
  AGAVE_RUST_LOG          RUST_LOG filter for Agave (default: solana_runtime::bank=info)
  AGAVE_DISABLE_SOLANACDN_BUILDER If 1 and supported, pass --no-solanacdn-builder (default: 0)
  AGAVE_USE_SNAPSHOT_ARCHIVES_AT_STARTUP Agave snapshot startup policy (default: when-newest)
  AGAVE_TPU_DISABLE_QUIC  If 1 and supported, pass --tpu-disable-quic (default: 1)
  AGAVE_USE_DEV_HALT_AT_SLOT If 1, pass --dev-halt-at-slot to Agave (default: 0)
  GENESIS_RPC_URL         HTTP(S) RPC base URL used to fetch genesis.tar.bz2 when missing (default: https://api.mainnet-beta.solana.com)
  AGAVE_GOSSIP_PORT       Agave gossip port (default: 8031)
  AGAVE_DYNAMIC_PORT_RANGE Agave dynamic port range (default: 8030-8055)
  TIMEOUT_SECS            Per-validator wall timeout (default: 3600, 0 disables)
  SOLANAC_GOSSIP_PORT     solana-c gossip port (default: 8027)
  SOLANAC_TPU_PORT        solana-c TPU port (default: 8026)
  SOLANAC_TVU_PORT        solana-c TVU port (default: 8028)
  ENTRYPOINT              Comma/space-separated entrypoint list override
  SLOTS                   Default slots override
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

die() {
  echo "error: $*" >&2
  exit 1
}

cleanup_children() {
  set +e
  if [[ -n "${SOLANAC_PID:-}" ]]; then
    kill "${SOLANAC_PID}" 2>/dev/null || true
    wait "${SOLANAC_PID}" 2>/dev/null || true
  fi
  if [[ -n "${AGAVE_PID:-}" ]]; then
    kill "${AGAVE_PID}" 2>/dev/null || true
    wait "${AGAVE_PID}" 2>/dev/null || true
  fi
  if (( CLEANUP )); then
    if (( OWN_SOLANAC_LEDGER )) && [[ -n "${SOLANAC_LEDGER:-}" ]]; then
      rm -rf "$SOLANAC_LEDGER" 2>/dev/null || true
    fi
    if (( OWN_AGAVE_LEDGER )) && [[ -n "${AGAVE_LEDGER:-}" ]]; then
      rm -rf "$AGAVE_LEDGER" 2>/dev/null || true
    fi
    if (( OWN_AGAVE_SNAPSHOTS )) && [[ -n "${AGAVE_SNAPSHOTS:-}" ]]; then
      rm -rf "$AGAVE_SNAPSHOTS" 2>/dev/null || true
    fi
  fi
  set -e
}

ensure_genesis_bin() {
  local ledger_dir="$1"
  local rpc_url="$2"

  [[ -n "$ledger_dir" ]] || return 1
  [[ -d "$ledger_dir" ]] || die "Agave ledger dir missing: $ledger_dir"

  local genesis_path="$ledger_dir/genesis.bin"
  if [[ -s "$genesis_path" ]]; then
    return 0
  fi

  local base="${rpc_url%/}"
  [[ -n "$base" ]] || die "GENESIS_RPC_URL is empty"

  echo "Downloading genesis.bin from ${base}/genesis.tar.bz2 ..."
  local tmp
  tmp="$(mktemp "$ledger_dir/genesis.tar.bz2.XXXXXX")"
  if ! curl -fsSL --connect-timeout 10 --max-time 120 "${base}/genesis.tar.bz2" -o "$tmp"; then
    rm -f "$tmp"
    die "failed to download genesis.tar.bz2 from ${base}"
  fi

  if ! tar -xjf "$tmp" -C "$ledger_dir"; then
    rm -f "$tmp"
    die "failed to extract genesis.tar.bz2 into $ledger_dir"
  fi

  rm -f "$tmp"

  if [[ ! -s "$genesis_path" ]]; then
    die "genesis.bin missing after extraction: $genesis_path"
  fi
}

link_or_copy() {
  # Try to hardlink huge archives to avoid long copies. Fall back to cp when
  # hardlinking isn't possible (e.g. different filesystem). Prefer symlinks
  # over copies to avoid duplicating 100GB+ archives.
  local src="$1"
  local dst="$2"

  # No-op when reusing an existing snapshots directory as the source.
  if [[ "$src" == "$dst" ]]; then
    return 0
  fi
  # If the destination already refers to the same inode (hardlink/symlink),
  # avoid clobbering it (cp will error with "are the same file").
  if [[ -e "$dst" && "$src" -ef "$dst" ]]; then
    return 0
  fi

  if ln -f "$src" "$dst" 2>/dev/null; then
    return 0
  fi
  # Use an absolute symlink target so the link remains valid even when the
  # destination is on a different filesystem (/tmp, /var, ...).
  local link_src="$src"
  if [[ "$src" != /* ]]; then
    local src_dir src_base abs_dir
    src_dir="$(dirname "$src")"
    src_base="$(basename "$src")"
    abs_dir="$(cd "$src_dir" 2>/dev/null && pwd -P || true)"
    if [[ -n "$abs_dir" ]]; then
      link_src="${abs_dir}/${src_base}"
    fi
  fi
  if ln -sf "$link_src" "$dst" 2>/dev/null; then
    return 0
  fi
  cp -f "$src" "$dst"
}

wait_for_log_slot_frozen() {
  local log_path="$1"
  local slot="$2"
  local timeout_secs="$3"
  local pid="$4"

  local start_ts
  start_ts="$(date +%s)"

  while true; do
    if [[ -s "$log_path" ]]; then
      if grep -q "bank frozen: ${slot} " "$log_path"; then
        return 0
      fi
    fi

    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi

    if (( timeout_secs > 0 )); then
      local now_ts
      now_ts="$(date +%s)"
      if (( now_ts - start_ts >= timeout_secs )); then
        return 2
      fi
    fi

    sleep 2
  done
}

log_has_frozen_slot() {
  local log_path="$1"
  local slot="$2"

  [[ -s "$log_path" ]] || return 1
  grep -q "bank frozen: ${slot} " "$log_path"
}

wait_for_pid_exit() {
  local pid="$1"
  local timeout_secs="$2"

  local start_ts
  start_ts="$(date +%s)"

  while kill -0 "$pid" 2>/dev/null; do
    if (( timeout_secs > 0 )); then
      local now_ts
      now_ts="$(date +%s)"
      if (( now_ts - start_ts >= timeout_secs )); then
        return 1
      fi
    fi
    sleep 1
  done

  return 0
}

extract_full_slot() {
  local name
  name="$(basename "$1")"
  echo "$name" | sed -n 's/^snapshot-\([0-9][0-9]*\)-.*/\1/p'
}

extract_incr_slots() {
  local name
  name="$(basename "$1")"
  # incremental-snapshot-<base>-<slot>-<hash>.tar...
  echo "$name" | sed -n 's/^incremental-snapshot-\([0-9][0-9]*\)-\([0-9][0-9]*\)-.*/\1 \2/p'
}

find_latest_full_snapshot() {
  local dir="$1"
  local best=""
  local best_slot=0

  shopt -s nullglob
  for f in "$dir"/snapshot-*.tar.*; do
    case "$f" in
      *.partial*|*.tmp) continue ;;
    esac
    local slot
    slot="$(extract_full_slot "$f")"
    [[ -n "$slot" ]] || continue
    if (( slot > best_slot )); then
      best_slot="$slot"
      best="$f"
    fi
  done
  shopt -u nullglob

  [[ -n "$best" ]] || return 1
  echo "$best"
}

find_best_incremental_snapshot() {
  local dir="$1"
  local base_slot="$2"
  local best=""
  local best_slot=0

  shopt -s nullglob
  for f in "$dir"/incremental-snapshot-"$base_slot"-*.tar.*; do
    case "$f" in
      *.partial*|*.tmp) continue ;;
    esac
    local base slot
    read -r base slot < <(extract_incr_slots "$f" || true)
    [[ -n "$base" && -n "$slot" ]] || continue
    [[ "$base" == "$base_slot" ]] || continue
    if (( slot > best_slot )); then
      best_slot="$slot"
      best="$f"
    fi
  done
  shopt -u nullglob

  [[ -n "$best" ]] || return 1
  echo "$best"
}

infer_network() {
  # Best-effort inference based on the RPC URL/entrypoint strings.
  local hint="${GENESIS_RPC_URL} ${ENTRYPOINT}"
  if [[ "$hint" == *"devnet"* ]]; then
    echo "devnet"
  elif [[ "$hint" == *"testnet"* ]]; then
    echo "testnet"
  else
    echo "mainnet-beta"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-archives)
      SOURCE_ARCHIVES="${2:-}"; shift 2 ;;
    --workdir)
      WORKDIR="${2:-}"; shift 2 ;;
    --slots)
      SLOTS="${2:-}"; shift 2 ;;
    --entrypoint)
      ENTRYPOINT="${2:-}"; shift 2 ;;
    --timeout)
      TIMEOUT_SECS="${2:-}"; shift 2 ;;
    --parallel)
      PARALLEL=1; shift 1 ;;
    --cleanup)
      CLEANUP=1; shift 1 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "unknown argument: $1" ;;
  esac
done

if [[ -z "$SOURCE_ARCHIVES" ]]; then
  case "$(infer_network)" in
    devnet) SOURCE_ARCHIVES="ledger.devnet/snapshot-archives" ;;
    testnet) SOURCE_ARCHIVES="ledger.testnet/snapshot-archives" ;;
    *) SOURCE_ARCHIVES="ledger.mainnet/snapshot-archives" ;;
  esac
fi
mkdir -p "$SOURCE_ARCHIVES"
[[ -d "$SOURCE_ARCHIVES" ]] || die "not a directory: $SOURCE_ARCHIVES"
[[ -x "$SOLANAC_BIN" ]] || die "solana-c validator not executable: $SOLANAC_BIN"
[[ -x "$AGAVE_BIN" ]] || die "Agave validator not executable: $AGAVE_BIN"

AGAVE_VERSION_STR="$("$AGAVE_BIN" --version 2>/dev/null | head -n 1 || true)"
if [[ -n "$AGAVE_VERSION_STR" ]]; then
  echo "Agave version: $AGAVE_VERSION_STR" >&2
else
  echo "warn: failed to query Agave version via '$AGAVE_BIN --version'" >&2
fi
if [[ -n "${AGAVE_EXPECT_VERSION}" && -n "${AGAVE_VERSION_STR}" ]]; then
  if [[ "$AGAVE_VERSION_STR" != *"$AGAVE_EXPECT_VERSION"* ]]; then
    echo "warn: Agave version mismatch: expected '$AGAVE_EXPECT_VERSION' but got: $AGAVE_VERSION_STR" >&2
    echo "warn: set AGAVE_VALIDATOR to the desired binary, or set AGAVE_EXPECT_VERSION= to disable the check." >&2
  fi
fi

AGAVE_HELP="$("$AGAVE_BIN" --help 2>/dev/null || true)"

AGAVE_RUN_SUBCMD=()
if echo "$AGAVE_HELP" | grep -qE '^[[:space:]]+run[[:space:]]'; then
  AGAVE_RUN_SUBCMD=(run)
fi

AGAVE_HAS_EXIT=0
if echo "$AGAVE_HELP" | grep -qE '^[[:space:]]+exit[[:space:]]'; then
  AGAVE_HAS_EXIT=1
fi

AGAVE_DEFAULT_ARGS=()
if [[ "$AGAVE_DISABLE_SOLANACDN_BUILDER" == "1" ]] && echo "$AGAVE_HELP" | grep -q -- "--no-solanacdn-builder"; then
  # Some Agave builds (e.g. pipe-solana-validator) enable a SolanaCDN builder
  # side-channel by default. Disable it in parity runs to avoid getting stuck
  # if the control plane isn't reachable.
  AGAVE_DEFAULT_ARGS+=(--no-solanacdn-builder)
fi

# Many dev hosts cannot meet mainnet PoH hash-rate requirements. For a replay
# parity harness we don't need to produce blocks, so disable the PoH speed test
# to avoid aborting early.
#
# Note: Some builds hide this flag from --help output. It's still supported by
# common Agave/Solana validator binaries (including pipe-solana-validator).
AGAVE_DEFAULT_ARGS+=(--no-poh-speed-test)

# Parity runs are often executed in CI/dev environments that are not publicly
# reachable on UDP ports. Agave's default port reachability checks can stall
# gossip/replay in these setups, so disable them. (This flag may be hidden from
# --help output but is supported by common Agave validator binaries.)
AGAVE_DEFAULT_ARGS+=(--no-port-check)

# Disable TPU QUIC to avoid binding/advertising extra ports. This flag is often
# hidden from --help but supported by common Agave validator binaries.
if [[ "$AGAVE_TPU_DISABLE_QUIC" == "1" ]]; then
  if "$AGAVE_BIN" --tpu-disable-quic --version >/dev/null 2>&1; then
    AGAVE_DEFAULT_ARGS+=(--tpu-disable-quic)
  else
    echo "warn: AGAVE_TPU_DISABLE_QUIC=1 but '$AGAVE_BIN' does not accept --tpu-disable-quic" >&2
  fi
fi

# Reduce inbound shred flood during catchup by not advertising the validator's
# TPU/TVU/repair ports. This improves the odds of successfully repairing and
# replaying a small window of slots for parity runs, even on machines that
# cannot keep up with tip-of-chain turbine traffic.
if [[ "$AGAVE_RESTRICTED_REPAIR_ONLY_MODE" == "1" ]]; then
  # This flag may be hidden from --help output; probe support directly.
  if "$AGAVE_BIN" --restricted-repair-only-mode --version >/dev/null 2>&1; then
    AGAVE_DEFAULT_ARGS+=(--restricted-repair-only-mode)
  else
    echo "warn: AGAVE_RESTRICTED_REPAIR_ONLY_MODE=1 but '$AGAVE_BIN' does not accept --restricted-repair-only-mode" >&2
  fi
fi

AGAVE_FULL_RPC_ARGS=()
if [[ "$AGAVE_FULL_RPC_API" == "1" ]]; then
  AGAVE_FULL_RPC_ARGS=(--full-rpc-api)
fi

# shellcheck disable=SC2206
AGAVE_EXTRA_ARGS_ARR=(${AGAVE_EXTRA_ARGS})

if ! [[ "$SLOTS" =~ ^[0-9]+$ ]]; then
  die "--slots must be a non-negative integer"
fi
if ! [[ "$TIMEOUT_SECS" =~ ^[0-9]+$ ]]; then
  die "--timeout must be a non-negative integer (seconds)"
fi
if ! [[ "$REFRESH_SNAPSHOTS" =~ ^[0-9]+$ ]]; then
  die "REFRESH_SNAPSHOTS must be a non-negative integer (0 or 1 recommended)"
fi

TIMEOUT_ARGS=()
if (( TIMEOUT_SECS > 0 )); then
  if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_ARGS=(timeout --preserve-status --signal TERM --kill-after 30s "${TIMEOUT_SECS}s")
  else
    echo "warn: 'timeout' not found; --timeout ignored" >&2
  fi
fi

if [[ -n "$SNAPSHOT_FETCH_RPC_URL" ]]; then
  echo "warn: SNAPSHOT_FETCH_RPC_URL is ignored; snapshot fetch uses manifest only" >&2
fi

if (( REFRESH_SNAPSHOTS )); then
  if [[ -x "$SNAPSHOT_FETCH_BIN" ]]; then
    net="$(infer_network)"
    echo "Refreshing snapshot archives in $SOURCE_ARCHIVES (network=${net})..." >&2
    fetch_args=(--output-dir "$SOURCE_ARCHIVES" --network "$net")
    if ! "$SNAPSHOT_FETCH_BIN" "${fetch_args[@]}"; then
      die "failed to refresh snapshot archives (set REFRESH_SNAPSHOTS=0 to skip)"
    fi
  else
    echo "warn: REFRESH_SNAPSHOTS=1 but SNAPSHOT_FETCH_BIN not executable: $SNAPSHOT_FETCH_BIN" >&2
  fi
fi

# Avoid port conflicts with any host-provisioned validator services.
if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files --type=service 2>/dev/null | grep -q '^pipe-solana-validator\\.service'; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
      echo "Stopping pipe-solana-validator.service (best-effort)..." >&2
      sudo systemctl stop pipe-solana-validator.service >/dev/null 2>&1 || true
      sudo systemctl disable pipe-solana-validator.service >/dev/null 2>&1 || true
      sudo systemctl mask --runtime --now pipe-solana-validator.service >/dev/null 2>&1 || true
    else
      echo "warn: pipe-solana-validator.service present but sudo isn't non-interactive; stop it manually if you hit port conflicts." >&2
    fi
  fi
fi

if [[ -z "$WORKDIR" ]]; then
  # Pick a workspace with the most free disk. Parity runs can need 100s of GB
  # for RocksDB, so /tmp (often on a different volume) is a safer default on
  # dev hosts where $PWD may live on a nearly-full filesystem.
  base_dir="."
  if command -v df >/dev/null 2>&1; then
    avail_here="$(df -Pk . 2>/dev/null | awk 'NR==2 {print $4}' || true)"
    avail_tmp="$(df -Pk /tmp 2>/dev/null | awk 'NR==2 {print $4}' || true)"
    if [[ "$avail_here" =~ ^[0-9]+$ && "$avail_tmp" =~ ^[0-9]+$ ]]; then
      if (( avail_tmp > avail_here )); then
        base_dir="/tmp"
      fi
    fi
  fi
  WORKDIR="${base_dir}/ledger.parity.$(date +%s)"
fi

if ! FULL_SNAPSHOT="$(find_latest_full_snapshot "$SOURCE_ARCHIVES")"; then
  if [[ -x "$SNAPSHOT_FETCH_BIN" ]]; then
    net="$(infer_network)"
    echo "No full snapshot found under $SOURCE_ARCHIVES; downloading latest snapshots (network=${net})..." >&2
    fetch_args=(--output-dir "$SOURCE_ARCHIVES" --network "$net")
    "$SNAPSHOT_FETCH_BIN" "${fetch_args[@]}" || true
  else
    die "no full snapshot found under $SOURCE_ARCHIVES (and SNAPSHOT_FETCH_BIN not executable: $SNAPSHOT_FETCH_BIN)"
  fi
fi

FULL_SNAPSHOT="$(find_latest_full_snapshot "$SOURCE_ARCHIVES")" || die "no full snapshot found under $SOURCE_ARCHIVES"
BASE_SLOT="$(extract_full_slot "$FULL_SNAPSHOT")"
[[ -n "$BASE_SLOT" ]] || die "failed to parse full snapshot slot: $FULL_SNAPSHOT"

INCR_SNAPSHOT=""
INCR_SLOT=""
if INCR_SNAPSHOT="$(find_best_incremental_snapshot "$SOURCE_ARCHIVES" "$BASE_SLOT" 2>/dev/null)"; then
  read -r _ INCR_SLOT < <(extract_incr_slots "$INCR_SNAPSHOT")
fi

START_SLOT="$BASE_SLOT"
if [[ -n "$INCR_SLOT" ]]; then
  START_SLOT="$INCR_SLOT"
fi

HALT_SLOT=$(( START_SLOT + SLOTS ))
AGAVE_DEV_HALT_SLOT="${AGAVE_DEV_HALT_SLOT:-$HALT_SLOT}"

ENTRYPOINT_ARGS=()
if [[ -n "${ENTRYPOINT}" ]]; then
  IFS=$', \t\n' read -r -a _eps <<<"${ENTRYPOINT}"
  for _ep in "${_eps[@]}"; do
    [[ -n "${_ep}" ]] || continue
    ENTRYPOINT_ARGS+=(--entrypoint "${_ep}")
  done
fi
if [[ "${#ENTRYPOINT_ARGS[@]}" -eq 0 ]]; then
  die "no entrypoints configured (set ENTRYPOINT=host:port[,host:port...])"
fi

AGAVE_HALT_ARGS=()
if [[ "${AGAVE_USE_DEV_HALT_AT_SLOT}" == "1" ]]; then
  # Note: Some builds hide this flag from --help output. It's still supported by
  # common Agave/Solana validator binaries, but it's deprecated and its semantics
  # have changed over time. The harness already stops Agave once it observes the
  # target frozen slot, so this is optional.
  AGAVE_HALT_ARGS=(--dev-halt-at-slot "$AGAVE_DEV_HALT_SLOT")
fi

mkdir -p "$WORKDIR"

HARNESS_LOG="$WORKDIR/harness.log"
: >"$HARNESS_LOG"
exec > >(tee -a "$HARNESS_LOG") 2>&1
echo "Harness log: $HARNESS_LOG"

echo ""
echo "Using snapshot:"
echo "  full: $FULL_SNAPSHOT"
if [[ -n "$INCR_SNAPSHOT" ]]; then
  echo "  incr: $INCR_SNAPSHOT"
fi
echo "Start slot: $START_SLOT"
echo "Halt slot:  $HALT_SLOT"
if [[ "${AGAVE_USE_DEV_HALT_AT_SLOT}" == "1" ]]; then
  echo "Agave dev-halt-at-slot: $AGAVE_DEV_HALT_SLOT"
else
  echo "Agave dev-halt-at-slot: disabled (target would be $AGAVE_DEV_HALT_SLOT)"
fi
echo "Entrypoints:"
for ((i=0; i<${#ENTRYPOINT_ARGS[@]}; i+=2)); do
  echo "  ${ENTRYPOINT_ARGS[i+1]}"
done
echo "Workdir:    $WORKDIR"
echo "Timeout:    ${TIMEOUT_SECS}s"
echo "Ports:"
echo "  Agave gossip:    $AGAVE_GOSSIP_PORT (dyn: $AGAVE_DYNAMIC_PORT_RANGE, rpc: 18999)"
echo "  solana-c gossip: $SOLANAC_GOSSIP_PORT (tpu: $SOLANAC_TPU_PORT, tvu: $SOLANAC_TVU_PORT, rpc: 18899)"

trap cleanup_children EXIT INT TERM

SOLANAC_LEDGER="$WORKDIR/solanac.ledger"
AGAVE_LEDGER="$WORKDIR/agave.ledger"
AGAVE_SNAPSHOTS="$WORKDIR/agave.snapshots"
AGAVE_IDENTITY="$WORKDIR/agave.identity.json"

if [[ -n "${SOLANAC_LEDGER_DIR:-}" ]]; then
  SOLANAC_LEDGER="${SOLANAC_LEDGER_DIR}"
  OWN_SOLANAC_LEDGER=0
fi
if [[ -n "${AGAVE_LEDGER_DIR:-}" ]]; then
  AGAVE_LEDGER="${AGAVE_LEDGER_DIR}"
  OWN_AGAVE_LEDGER=0
fi
if [[ -n "${AGAVE_SNAPSHOTS_DIR:-}" ]]; then
  AGAVE_SNAPSHOTS="${AGAVE_SNAPSHOTS_DIR}"
  OWN_AGAVE_SNAPSHOTS=0
fi
if [[ -n "${AGAVE_IDENTITY_FILE:-}" ]]; then
  AGAVE_IDENTITY="${AGAVE_IDENTITY_FILE}"
fi

mkdir -p "$SOLANAC_LEDGER/snapshot-archives" "$SOLANAC_LEDGER/rocksdb"
mkdir -p "$AGAVE_LEDGER" "$AGAVE_SNAPSHOTS"

link_or_copy "$FULL_SNAPSHOT" "$SOLANAC_LEDGER/snapshot-archives/$(basename "$FULL_SNAPSHOT")"
link_or_copy "$FULL_SNAPSHOT" "$AGAVE_SNAPSHOTS/$(basename "$FULL_SNAPSHOT")"
if [[ -n "$INCR_SNAPSHOT" ]]; then
  link_or_copy "$INCR_SNAPSHOT" "$SOLANAC_LEDGER/snapshot-archives/$(basename "$INCR_SNAPSHOT")"
  link_or_copy "$INCR_SNAPSHOT" "$AGAVE_SNAPSHOTS/$(basename "$INCR_SNAPSHOT")"
fi

# Agave requires --identity; generate an ephemeral keypair for the harness
# unless a reusable one was provided.
if [[ ! -s "${AGAVE_IDENTITY}" ]]; then
  python3 - <<PY
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import json

key = ed25519.Ed25519PrivateKey.generate()
priv = key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
pub = key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
with open("${AGAVE_IDENTITY}", "w", encoding="utf-8") as f:
    json.dump(list(priv + pub), f)
PY
fi

ensure_genesis_bin "$AGAVE_LEDGER" "$GENESIS_RPC_URL"

SOLANAC_LOG="$WORKDIR/solanac.validator.log"
AGAVE_LOG="$WORKDIR/agave.validator.log"
AGAVE_STDOUT="$WORKDIR/agave.stdout.log"
SOLANAC_STDOUT="$WORKDIR/solanac.stdout.log"

echo ""
echo "Running Agave (reference)..."
ulimit -n 1000000 || true

set +e
AGAVE_PID=""
SOLANAC_PID=""
AGAVE_STATUS=0
SOLANAC_STATUS=0

  if (( PARALLEL )); then
    echo "Mode: parallel (this will use significant CPU/disk)"

  env RUST_LOG="$AGAVE_RUST_LOG" "$AGAVE_BIN" \
      --ledger "$AGAVE_LEDGER" \
    --snapshots "$AGAVE_SNAPSHOTS" \
    --no-snapshot-fetch \
    --no-genesis-fetch \
    --use-snapshot-archives-at-startup "$AGAVE_USE_SNAPSHOT_ARCHIVES_AT_STARTUP" \
    --log "$AGAVE_LOG" \
      "${AGAVE_DEFAULT_ARGS[@]}" \
      "${AGAVE_EXTRA_ARGS_ARR[@]}" \
      --identity "$AGAVE_IDENTITY" \
      "${ENTRYPOINT_ARGS[@]}" \
      --gossip-port "$AGAVE_GOSSIP_PORT" \
      "${AGAVE_FULL_RPC_ARGS[@]}" \
      --rpc-bind-address 127.0.0.1 \
      --rpc-port 18999 \
      --dynamic-port-range "$AGAVE_DYNAMIC_PORT_RANGE" \
      --no-voting \
      "${AGAVE_HALT_ARGS[@]}" "${AGAVE_RUN_SUBCMD[@]}" >"$AGAVE_STDOUT" 2>&1 &
  AGAVE_PID=$!

  echo ""
  echo "Running solana-c..."
  ulimit -n 1000000 || true

  env SOL_LOG_BANK_FROZEN_LT_HASH=1 \
    "${TIMEOUT_ARGS[@]}" "$SOLANAC_BIN" \
      --ledger "$SOLANAC_LEDGER" \
      --rocksdb-path "$SOLANAC_LEDGER/rocksdb" \
      --auto-snapshot-max-lag-slots 0 \
      "${ENTRYPOINT_ARGS[@]}" \
      --no-voting \
      --no-rpc \
      --no-quic \
      --rpc-bind 127.0.0.1 \
      --rpc-port 18899 \
      --gossip-port "$SOLANAC_GOSSIP_PORT" \
      --tpu-port "$SOLANAC_TPU_PORT" \
      --tvu-port "$SOLANAC_TVU_PORT" \
      --no-metrics \
      --dev-halt-at-slot "$HALT_SLOT" \
      --log-level "$SOLANAC_LOG_LEVEL" \
      --log-file "$SOLANAC_LOG" \
      >"$SOLANAC_STDOUT" 2>&1 &
  SOLANAC_PID=$!

  START_TS="$(date +%s)"
  AGAVE_REACHED=0
  AGAVE_DONE=0
  SOLANAC_DONE=0

  while (( !AGAVE_DONE || !SOLANAC_DONE )); do
    if (( TIMEOUT_SECS > 0 )); then
      NOW_TS="$(date +%s)"
      if (( NOW_TS - START_TS >= TIMEOUT_SECS )); then
        echo "error: timeout waiting for parity run to reach slot $HALT_SLOT" >&2
        kill "$SOLANAC_PID" 2>/dev/null || true
        kill "$AGAVE_PID" 2>/dev/null || true
        wait "$SOLANAC_PID" 2>/dev/null || true
        wait "$AGAVE_PID" 2>/dev/null || true
        exit 143
      fi
    fi

    if (( !SOLANAC_DONE )); then
      if ! kill -0 "$SOLANAC_PID" 2>/dev/null; then
        wait "$SOLANAC_PID" || SOLANAC_STATUS=$?
        SOLANAC_STATUS=${SOLANAC_STATUS:-0}
        SOLANAC_DONE=1
        if (( SOLANAC_STATUS != 0 )); then
          echo "solana-c exited non-zero ($SOLANAC_STATUS); killing Agave ($AGAVE_PID)" >&2
          kill "$AGAVE_PID" 2>/dev/null || true
          wait "$AGAVE_PID" 2>/dev/null || true
          exit "$SOLANAC_STATUS"
        fi
      fi
    fi

    if (( !AGAVE_REACHED )); then
      if log_has_frozen_slot "$AGAVE_LOG" "$HALT_SLOT"; then
        AGAVE_REACHED=1
        if (( AGAVE_HAS_EXIT )); then
          "$AGAVE_BIN" --ledger "$AGAVE_LEDGER" exit --force --no-wait-for-exit >/dev/null 2>&1 || true
        else
          kill "$AGAVE_PID" 2>/dev/null || true
        fi
      elif ! kill -0 "$AGAVE_PID" 2>/dev/null; then
        wait "$AGAVE_PID" || AGAVE_STATUS=$?
        AGAVE_STATUS=${AGAVE_STATUS:-0}
        echo "error: Agave exited before reaching slot $HALT_SLOT (status=$AGAVE_STATUS)" >&2
        kill "$SOLANAC_PID" 2>/dev/null || true
        wait "$SOLANAC_PID" 2>/dev/null || true
        exit 1
      fi
    fi

    if (( AGAVE_REACHED && !AGAVE_DONE )); then
      if ! kill -0 "$AGAVE_PID" 2>/dev/null; then
        wait "$AGAVE_PID" || AGAVE_STATUS=$?
        AGAVE_STATUS=${AGAVE_STATUS:-0}
        AGAVE_DONE=1
      fi
    fi

    sleep 2
  done
  else
    echo "Mode: sequential"
    ulimit -n 1000000 || true
    env RUST_LOG="$AGAVE_RUST_LOG" AGAVE_DUMP_DELTA_ACCOUNTS="${AGAVE_DUMP_DELTA_ACCOUNTS:-}" SOL_DUMP_DELTA_ACCOUNTS="$WORKDIR" "$AGAVE_BIN" \
      --ledger "$AGAVE_LEDGER" \
    --snapshots "$AGAVE_SNAPSHOTS" \
    --no-snapshot-fetch \
    --no-genesis-fetch \
    --use-snapshot-archives-at-startup "$AGAVE_USE_SNAPSHOT_ARCHIVES_AT_STARTUP" \
    --log "$AGAVE_LOG" \
      "${AGAVE_DEFAULT_ARGS[@]}" \
      "${AGAVE_EXTRA_ARGS_ARR[@]}" \
      --identity "$AGAVE_IDENTITY" \
      "${ENTRYPOINT_ARGS[@]}" \
      --gossip-port "$AGAVE_GOSSIP_PORT" \
      "${AGAVE_FULL_RPC_ARGS[@]}" \
      --rpc-bind-address 127.0.0.1 \
      --rpc-port 18999 \
      --dynamic-port-range "$AGAVE_DYNAMIC_PORT_RANGE" \
      --no-voting \
      "${AGAVE_HALT_ARGS[@]}" "${AGAVE_RUN_SUBCMD[@]}" >"$AGAVE_STDOUT" 2>&1 &
  AGAVE_PID=$!

  wait_for_log_slot_frozen "$AGAVE_LOG" "$HALT_SLOT" "$TIMEOUT_SECS" "$AGAVE_PID"
  rc=$?
  if (( rc != 0 )); then
    if (( rc == 2 )); then
      echo "error: Agave did not reach slot $HALT_SLOT within ${TIMEOUT_SECS}s" >&2
    else
      wait "$AGAVE_PID" || AGAVE_STATUS=$?
      AGAVE_STATUS=${AGAVE_STATUS:-0}
      echo "error: Agave exited before reaching slot $HALT_SLOT (status=$AGAVE_STATUS)" >&2
    fi
    echo "Agave log tail ($AGAVE_LOG):" >&2
    tail -n 50 "$AGAVE_LOG" >&2 || true
    kill "$AGAVE_PID" 2>/dev/null || true
    wait "$AGAVE_PID" 2>/dev/null || true
    exit 1
  fi

  # --- Query Agave RPC IMMEDIATELY (before it processes more slots) ---
  AGAVE_DUMP_DIR="$WORKDIR"
  if kill -0 "$AGAVE_PID" 2>/dev/null; then
    echo "Querying Agave RPC for sysvar accounts..."
    for sysvar_name in Clock SlotHashes SlotHistory RecentBlockhashes Fees; do
      case "$sysvar_name" in
        Clock)              pk="SysvarC1ock11111111111111111111111111111111" ;;
        SlotHashes)         pk="SysvarS1otHashes111111111111111111111111111" ;;
        SlotHistory)        pk="SysvarS1otHistory11111111111111111111111111" ;;
        RecentBlockhashes)  pk="SysvarRecentB1ockHashes11111111111111111111" ;;
        Fees)               pk="SysvarFees111111111111111111111111111111111" ;;
      esac
      python3 -c "
import json, subprocess, sys, base64, hashlib
r = subprocess.run(['curl', '-s', '--max-time', '5', '-X', 'POST', 'http://127.0.0.1:18999',
    '-H', 'Content-Type: application/json',
    '-d', json.dumps({'jsonrpc':'2.0','id':1,'method':'getAccountInfo',
        'params':['$pk',{'encoding':'base64','commitment':'processed'}]})],
    capture_output=True, text=True)
try:
    d = json.loads(r.stdout)
    v = d['result']['value']
    if v is None:
        print(f'  $sysvar_name: NOT FOUND')
    else:
        data = base64.b64decode(v['data'][0])
        h = hashlib.sha256(data).hexdigest()[:16]
        lam = v['lamports']
        exe = v['executable']
        owner = v['owner']
        print(f'  $sysvar_name: lamports={lam} data_len={len(data)} data_sha256={h} executable={exe} owner={owner}')
        with open('$AGAVE_DUMP_DIR/agave_sysvar_${sysvar_name}.bin', 'wb') as f:
            f.write(data)
except Exception as e:
    print(f'  $sysvar_name: error: {e}')
" 2>/dev/null || true
    done

    # Auto-extract pubkeys from solana-c's delta TSV or a pre-existing pubkeys file
    DELTA_PUBKEYS_FILE=""
    DELTA_TSV=$(ls "$WORKDIR"/delta_accounts.*.tsv 2>/dev/null | head -1)
    if [[ -n "$DELTA_TSV" ]]; then
      tail -n +2 "$DELTA_TSV" | cut -f1 > "$WORKDIR/delta_pubkeys.txt"
      DELTA_PUBKEYS_FILE="$WORKDIR/delta_pubkeys.txt"
    elif [[ -n "${DELTA_PUBKEYS_FILE_PREV:-}" && -s "${DELTA_PUBKEYS_FILE_PREV}" ]]; then
      DELTA_PUBKEYS_FILE="${DELTA_PUBKEYS_FILE_PREV}"
      echo "  Using pre-existing delta pubkeys: $DELTA_PUBKEYS_FILE"
    fi
    if [[ -n "$DELTA_PUBKEYS_FILE" ]]; then
      echo "Querying Agave RPC for $(wc -l < "$DELTA_PUBKEYS_FILE") delta accounts (batch mode)..."
      python3 -c "
import json, subprocess, sys, base64, hashlib, os

rpc_url = 'http://127.0.0.1:18999'
dump_dir = '$AGAVE_DUMP_DIR'
pubkeys_file = '$DELTA_PUBKEYS_FILE'
BATCH_SIZE = 100

with open(pubkeys_file) as f:
    pubkeys = [line.strip() for line in f if line.strip()]

out_path = dump_dir + '/agave_accounts.tsv'
queried = 0
errors = 0
context_slot = None

with open(out_path, 'w') as out:
    out.write('pubkey\tlamports\tdata_len\tdata_hash\texecutable\towner\trent_epoch\n')
    for batch_start in range(0, len(pubkeys), BATCH_SIZE):
        batch = pubkeys[batch_start:batch_start + BATCH_SIZE]
        try:
            payload = json.dumps({'jsonrpc':'2.0','id':1,'method':'getMultipleAccounts',
                'params':[batch,{'encoding':'base64','commitment':'processed'}]})
            r = subprocess.run(['curl', '-s', '--max-time', '10', '-X', 'POST', rpc_url,
                '-H', 'Content-Type: application/json', '-d', payload],
                capture_output=True, text=True, timeout=15)
            d = json.loads(r.stdout)
            if context_slot is None:
                context_slot = d.get('result', {}).get('context', {}).get('slot')
                print(f'  RPC context slot: {context_slot}', flush=True)
            values = d['result']['value']
            for pk, v in zip(batch, values):
                if v is None:
                    out.write(f'{pk}\t0\t0\t0000000000000000\t0\t11111111111111111111111111111111\t0\n')
                else:
                    data = base64.b64decode(v['data'][0])
                    h = hashlib.sha256(data).hexdigest()[:16]
                    out.write(f'{pk}\t{v[\"lamports\"]}\t{len(data)}\t{h}\t{1 if v[\"executable\"] else 0}\t{v[\"owner\"]}\t{v.get(\"rentEpoch\",0)}\n')
                    bin_path = os.path.join(dump_dir, f'agave_acct_{pk}.bin')
                    with open(bin_path, 'wb') as bf:
                        bf.write(data)
                queried += 1
        except Exception as e:
            errors += 1
            print(f'  Batch error at {batch_start}: {e}', flush=True)
            if errors > 10:
                print(f'  Too many batch errors ({errors}), stopping.', flush=True)
                break
        if (batch_start + BATCH_SIZE) % 500 < BATCH_SIZE:
            print(f'  Progress: {min(batch_start + BATCH_SIZE, len(pubkeys))}/{len(pubkeys)} ({errors} errors)', flush=True)
    print(f'  Done: {queried} queried, {errors} errors, context_slot={context_slot} -> {out_path}', flush=True)
" 2>&1 || true
    else
      echo "  No delta TSV found in $WORKDIR, skipping delta account comparison."
    fi
  else
    echo "Warning: Agave PID $AGAVE_PID no longer alive, cannot query RPC."
  fi

  # Kill Agave now that we're done querying
  if (( AGAVE_HAS_EXIT )); then
    "$AGAVE_BIN" --ledger "$AGAVE_LEDGER" exit --force --no-wait-for-exit >/dev/null 2>&1 || true
  else
    kill "$AGAVE_PID" 2>/dev/null || true
  fi
  if ! wait_for_pid_exit "$AGAVE_PID" 60; then
    kill "$AGAVE_PID" 2>/dev/null || true
  fi
  wait "$AGAVE_PID" || AGAVE_STATUS=$?
  AGAVE_STATUS=${AGAVE_STATUS:-0}

  echo "Agave exit: $AGAVE_STATUS (log: $AGAVE_LOG, stdout: $AGAVE_STDOUT)"

  if (( CLEANUP )); then
    if (( OWN_AGAVE_LEDGER && OWN_AGAVE_SNAPSHOTS )); then
      echo "Cleaning up Agave ledger dirs to save disk..." >&2
      rm -rf "$AGAVE_LEDGER" "$AGAVE_SNAPSHOTS" || true
    else
      echo "Note: skipping Agave cleanup; using user-provided ledger/snapshots dirs." >&2
    fi
  fi

  # --- Now run solana-c (Agave is already stopped) ---
  echo ""
  echo "Running solana-c..."
  ulimit -n 1000000 || true

  env SOL_LOG_BANK_FROZEN_LT_HASH=1 SOL_LOG_TX_RESULTS=1 SOL_DUMP_DELTA_ACCOUNTS="$WORKDIR" \
  "${TIMEOUT_ARGS[@]}" "$SOLANAC_BIN" \
    --ledger "$SOLANAC_LEDGER" \
    --rocksdb-path "$SOLANAC_LEDGER/rocksdb" \
    --auto-snapshot-max-lag-slots 0 \
    "${ENTRYPOINT_ARGS[@]}" \
    --no-voting \
    --no-rpc \
    --no-quic \
    --rpc-bind 127.0.0.1 \
    --rpc-port 18899 \
    --gossip-port "$SOLANAC_GOSSIP_PORT" \
    --tpu-port "$SOLANAC_TPU_PORT" \
    --tvu-port "$SOLANAC_TVU_PORT" \
    --no-metrics \
    --dev-halt-at-slot "$HALT_SLOT" \
    --log-level "$SOLANAC_LOG_LEVEL" \
      --log-file "$SOLANAC_LOG" \
    >"$SOLANAC_STDOUT" 2>&1
  SOLANAC_STATUS=$?
  if (( SOLANAC_STATUS != 0 )); then
    echo "solana-c exit: $SOLANAC_STATUS (log: $SOLANAC_LOG, stdout: $SOLANAC_STDOUT)" >&2
    echo "warning: solana-c exited non-zero ($SOLANAC_STATUS); continuing with parity check anyway" >&2
  fi
fi
set -e

echo "Agave exit: $AGAVE_STATUS (log: $AGAVE_LOG, stdout: $AGAVE_STDOUT)"
echo "solana-c exit: $SOLANAC_STATUS (log: $SOLANAC_LOG, stdout: $SOLANAC_STDOUT)"

if (( CLEANUP )); then
  if (( OWN_SOLANAC_LEDGER )); then
    echo "Cleaning up solana-c ledger dirs to save disk..." >&2
    rm -rf "$SOLANAC_LEDGER" || true
  else
    echo "Note: skipping solana-c cleanup; using user-provided ledger dir." >&2
  fi
fi

AGAVE_FROZEN="$WORKDIR/agave.bank_frozen.tsv"
SOLANAC_FROZEN="$WORKDIR/solanac.bank_frozen.tsv"

extract_bank_frozen() {
  # Emits: "<slot> <hash> <signature_count> <last_blockhash> <accounts_lt_hash_checksum>"
  awk '
    /bank frozen:/ {
      slot = "";
      hash = "";
      sig = "";
      last = "";
      lt = "";
      for (i = 1; i <= NF; i++) {
        if ($i == "frozen:" && (i+1) <= NF) { slot = $(i+1); }
        if ($i == "hash:" && (i+1) <= NF) { hash = $(i+1); }
        if ($i == "signature_count:" && (i+1) <= NF) { sig = $(i+1); }
        if ($i == "last_blockhash:" && (i+1) <= NF) { last = $(i+1); }
        if ($i == "checksum:" && (i+1) <= NF) { lt = $(i+1); }
      }

      gsub(/[^0-9]/, "", slot);
      gsub(/[^0-9]/, "", sig);
      gsub(/[^1-9A-HJ-NP-Za-km-z]/, "", hash);
      gsub(/[^1-9A-HJ-NP-Za-km-z]/, "", last);
      gsub(/[^1-9A-HJ-NP-Za-km-z]/, "", lt);

      if (slot != "" && hash != "") {
        if (sig == "") sig = "-";
        if (last == "") last = "-";
        if (lt == "") lt = "-";
        print slot, hash, sig, last, lt;
      }
    }
  ' "$1" | sort -n -k1,1 -k2,2 | uniq
}

extract_bank_frozen "$AGAVE_LOG" >"$AGAVE_FROZEN" || true
extract_bank_frozen "$SOLANAC_LOG" >"$SOLANAC_FROZEN" || true

echo ""
echo "Comparing bank hashes..."
echo "  Agave:    $(wc -l <"$AGAVE_FROZEN" | tr -d ' ') entries ($AGAVE_FROZEN)"
echo "  solana-c: $(wc -l <"$SOLANAC_FROZEN" | tr -d ' ') entries ($SOLANAC_FROZEN)"

if [[ ! -s "$AGAVE_FROZEN" ]]; then
  echo "error: no bank frozen hashes found in Agave log." >&2
  echo "Try increasing Agave logging, e.g.:" >&2
  echo "  AGAVE_RUST_LOG=info scripts/verify-agave-parity.sh ..." >&2
  exit 1
fi
if [[ ! -s "$SOLANAC_FROZEN" ]]; then
  echo "error: no bank frozen hashes found in solana-c log." >&2
  echo "Check $SOLANAC_LOG for startup/replay errors." >&2
  exit 1
fi

MISMATCHES="$WORKDIR/mismatches.txt"

awk '
  FNR==NR {
    ag[$1, $2] = 1;
    ag_slot[$1] = 1;
    next
  }
  {
    sc[$1, $2] = 1;
    sc_slot[$1] = 1;
  }
  END {
    mism = 0;
    for (s in ag_slot) {
      if (!sc_slot[s]) continue;
      ok = 0;
      for (pair in ag) {
        split(pair, a, SUBSEP);
        if (a[1] != s) continue;
        if (sc[a[1], a[2]]) { ok = 1; break; }
      }
      if (!ok) {
        print s;
        mism++;
      }
    }
    exit(mism ? 1 : 0);
  }
' "$AGAVE_FROZEN" "$SOLANAC_FROZEN" >"$MISMATCHES" || true

if [[ -s "$MISMATCHES" ]]; then
  echo "Mismatch detected for slots (showing up to 20):"
  head -n 20 "$MISMATCHES"
  echo ""
  echo "Per-slot bank freeze details (Agave vs solana-c):"
  while read -r s; do
    [[ -n "$s" ]] || continue
    echo "slot $s"
    echo "  agave:"
    awk -v ss="$s" '$1==ss {printf "    hash=%s sig=%s last=%s lt=%s\n", $2, $3, $4, $5}' "$AGAVE_FROZEN" || true
    echo "  solana-c:"
    awk -v ss="$s" '$1==ss {printf "    hash=%s sig=%s last=%s lt=%s\n", $2, $3, $4, $5}' "$SOLANAC_FROZEN" || true
  done < <(head -n 20 "$MISMATCHES")
  echo ""

  # Post-execution account comparison (if Agave binary dumps exist)
  AGAVE_ACCT_BINS=$(ls "$WORKDIR"/agave_acct_*.bin 2>/dev/null | wc -l)
  if (( AGAVE_ACCT_BINS > 0 )); then
    echo "=== Post-execution account comparison ==="
    echo "Agave binary dumps: $AGAVE_ACCT_BINS"
    python3 -c "
import os, sys, hashlib, csv, struct

workdir = '$WORKDIR'

# Load solana-c delta TSV
delta_tsv = None
for f in sorted(os.listdir(workdir)):
    if f.startswith('delta_accounts.') and f.endswith('.tsv'):
        delta_tsv = os.path.join(workdir, f)
        break
if not delta_tsv:
    print('  No delta TSV found, skipping.')
    sys.exit(0)

sc_accounts = {}
with open(delta_tsv) as f:
    reader = csv.DictReader(f, delimiter='\t')
    for row in reader:
        sc_accounts[row['pubkey']] = row

# Compare each account
mismatches_lamports = []
mismatches_data = []
mismatches_owner = []
matches = 0
no_sc_bin = 0

for pk, sc in sc_accounts.items():
    agave_bin = os.path.join(workdir, f'agave_acct_{pk}.bin')
    if not os.path.exists(agave_bin):
        continue  # Agave returned null (account deleted or not found)

    sc_lamports = int(sc['curr_lamports'])
    sc_data_len = int(sc['curr_data_len'])
    sc_exec = int(sc['executable'])
    sc_owner = sc['owner']

    # Load Agave account data from TSV
    agave_tsv = os.path.join(workdir, 'agave_accounts.tsv')
    agave_info = None
    if os.path.exists(agave_tsv):
        with open(agave_tsv) as af:
            areader = csv.DictReader(af, delimiter='\t')
            for arow in areader:
                if arow['pubkey'] == pk:
                    agave_info = arow
                    break

    if agave_info is None:
        continue

    ag_lamports = int(agave_info['lamports'])
    ag_data_len = int(agave_info['data_len'])
    ag_exec = int(agave_info['executable'])
    ag_owner = agave_info['owner']

    if ag_lamports != sc_lamports:
        mismatches_lamports.append((pk, ag_lamports, sc_lamports, sc_owner))
        continue

    if ag_owner != sc_owner:
        mismatches_owner.append((pk, ag_owner, sc_owner))
        continue

    if ag_data_len != sc_data_len:
        mismatches_data.append((pk, 'data_len', ag_data_len, sc_data_len, sc_owner, -1))
        continue

    # Compare binary data byte-by-byte
    with open(agave_bin, 'rb') as bf:
        agave_data = bf.read()

    # Find solana-c binary dump
    sc_bin = None
    for prefix in ['solanac_sysvar', 'solanac_vote', 'solanac_acct']:
        # Find file matching the slot
        import glob
        candidates = glob.glob(os.path.join(workdir, f'{prefix}_*_{pk}.bin'))
        if candidates:
            sc_bin = candidates[0]
            break
    if sc_bin is None:
        no_sc_bin += 1
        continue

    with open(sc_bin, 'rb') as bf:
        sc_data = bf.read()

    if agave_data != sc_data:
        first_diff = -1
        for j in range(min(len(agave_data), len(sc_data))):
            if agave_data[j] != sc_data[j]:
                first_diff = j
                break
        if first_diff < 0 and len(agave_data) != len(sc_data):
            first_diff = min(len(agave_data), len(sc_data))
        mismatches_data.append((pk, 'content', len(agave_data), len(sc_data), sc_owner, first_diff))
    else:
        matches += 1

print(f'  Matches: {matches}')
print(f'  Lamport mismatches: {len(mismatches_lamports)}')
print(f'  Data mismatches: {len(mismatches_data)}')
print(f'  Owner mismatches: {len(mismatches_owner)}')
print(f'  No solana-c binary: {no_sc_bin}')

if mismatches_lamports:
    print(f'  --- Lamport mismatches (first 20) ---')
    for pk, ag, sc, owner in mismatches_lamports[:20]:
        print(f'    {pk[:24]}... agave={ag} solanac={sc} diff={ag-sc} owner={owner[:16]}...')

if mismatches_data:
    print(f'  --- Data mismatches (first 20) ---')
    from collections import Counter
    by_owner = Counter(m[4] for m in mismatches_data)
    print(f'    By owner: {dict(by_owner)}')
    for pk, field, ag_len, sc_len, owner, first_diff in mismatches_data[:20]:
        print(f'    {pk[:24]}... {field} agave_len={ag_len} sc_len={sc_len} first_diff@{first_diff} owner={owner[:16]}...')
" 2>&1 || true
  fi

  echo "See logs:"
  echo "  $AGAVE_LOG"
  echo "  $SOLANAC_LOG"
  exit 1
fi

echo "OK: solana-c bank hashes match Agave for all overlapping frozen slots."
