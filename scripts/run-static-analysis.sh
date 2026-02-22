#!/bin/bash
#
# run-static-analysis.sh - Optional static analysis helpers
#

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run-static-analysis.sh [build_dir] [--all] [--jobs N] [files...]

Options:
  --all       Run clang-tidy over all .c files in src/ and tests/unit/
  --jobs N    Parallelism for clang-tidy (default: 1 or $JOBS)
EOF
}

BUILD_DIR="build.local"
if [[ $# -gt 0 && "${1:-}" != --* ]]; then
  BUILD_DIR="$1"
  shift
fi

MODE="curated"
JOBS="${JOBS:-1}"
FILES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --all)
      MODE="all"
      shift
      ;;
    --jobs)
      JOBS="${2:-}"
      shift 2
      ;;
    *)
      FILES+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$JOBS" || ! "$JOBS" =~ ^[0-9]+$ ]]; then
  echo "Invalid --jobs value: '$JOBS'"
  exit 2
fi

if [[ ! -f "$BUILD_DIR/compile_commands.json" ]]; then
  echo "compile_commands.json not found in $BUILD_DIR"
  echo "Run: cmake -S . -B $BUILD_DIR"
  exit 1
fi

if command -v clang-tidy >/dev/null 2>&1; then
  if [[ "$MODE" == "all" ]]; then
    mapfile -t FILES < <(rg --files src tests/unit | rg "\\.c$")
  elif [[ ${#FILES[@]} -eq 0 ]]; then
    FILES=(
      src/validator/main.c
      src/net/sol_quic.c
      src/util/sol_config.c
      src/txn/sol_message.c
      src/shred/sol_shred.c
      src/blockstore/sol_blockstore.c
      src/entry/sol_entry.c
      src/gossip/sol_gossip_msg.c
      src/storage/sol_storage_backend.c
      src/storage/sol_rocksdb.c
      src/tpu/sol_tpu.c
      src/tvu/sol_tvu.c
      src/rpc/sol_rpc.c
      src/snapshot/sol_snapshot.c
      src/snapshot/sol_snapshot_archive.c
      src/snapshot/sol_snapshot_download.c
      tests/unit/test_snapshot.c
    )
  fi

  echo "[clang-tidy] ${#FILES[@]} file(s) (jobs: $JOBS)"
  if [[ "${JOBS}" -gt 1 ]]; then
    printf '%s\0' "${FILES[@]}" | xargs -0 -n 1 -P "$JOBS" clang-tidy -p "$BUILD_DIR"
  else
    for f in "${FILES[@]}"; do
      if [[ -f "$f" ]]; then
        clang-tidy -p "$BUILD_DIR" "$f"
      else
        echo "[clang-tidy] missing file: $f"
      fi
    done
  fi
else
  echo "[clang-tidy] not installed (skipping)"
fi

if command -v cppcheck >/dev/null 2>&1; then
  CPP_TARGETS=(src)
  if [[ "$MODE" == "all" ]]; then
    CPP_TARGETS+=(tests/unit)
    echo "[cppcheck] src/ tests/unit/"
  else
    echo "[cppcheck] src/"
  fi
  cppcheck \
    --enable=warning,style,performance,portability \
    --inconclusive \
    --inline-suppr \
    --std=c17 \
    -Isrc -Iinclude \
    -iexternal -ibuild -ibuild.local -ibuild.bench -ibuild.fuzz \
    "${CPP_TARGETS[@]}"
else
  echo "[cppcheck] not installed (skipping)"
fi
