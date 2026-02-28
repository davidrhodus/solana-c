#!/usr/bin/env bash
#
# rpc-smoke-jsonrpc.sh - Lightweight JSON-RPC smoke test for solana-c RPC server
#
# This checks that all JSON-RPC methods wired in `src/rpc/sol_rpc.c` are
# reachable (i.e. not "Method not found") and that a few core methods return a
# successful result with valid parameters.
#
# Usage:
#   ./scripts/rpc-smoke-jsonrpc.sh [RPC_URL]
#
# Env:
#   RPC_URL=http://127.0.0.1:8899
#

set -euo pipefail

RPC_URL="${1:-${RPC_URL:-http://127.0.0.1:8899}}"

fail() { echo "FAIL: $*" >&2; exit 1; }

if ! command -v curl >/dev/null 2>&1; then
  fail "curl not found"
fi
if ! command -v rg >/dev/null 2>&1; then
  fail "rg not found (ripgrep)"
fi

rpc_call() {
  local method="$1"
  local params_json="${2:-[]}"
  curl -sS --max-time 10 -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params_json}}" \
    "${RPC_URL}"
}

is_method_not_found() {
  rg -q "\"code\"\\s*:\\s*-32601|Method not found"
}

has_result() {
  rg -q "\"result\"\\s*:"
}

has_error() {
  rg -q "\"error\"\\s*:"
}

echo "RPC_URL=${RPC_URL}"

# Basic liveness
if ! curl -sS --max-time 5 "${RPC_URL}" >/dev/null 2>&1; then
  # Some servers don't serve anything at "/"; don't fail on this.
  :
fi

# Determine a slot we should have data for.
slot="$(rpc_call getSlot '[]' | sed -E 's/.*"result":([0-9]+).*/\1/')"
if [[ ! "${slot}" =~ ^[0-9]+$ ]]; then
  echo "getSlot response:"
  rpc_call getSlot '[]' | head -c 400 || true
  echo
  fail "unable to parse getSlot result from ${RPC_URL}"
fi
block_slot=$((slot > 0 ? slot - 1 : 0))

echo "local_slot=${slot} test_block_slot=${block_slot}"

# A few "should succeed" checks (valid params).
echo "[core] getVersion"
rpc_call getVersion '[]' | is_method_not_found && fail "getVersion: method not found"
rpc_call getVersion '[]' | has_result || fail "getVersion: missing result"

echo "[core] getHealth"
rpc_call getHealth '[]' | is_method_not_found && fail "getHealth: method not found"

echo "[core] getLatestBlockhash"
rpc_call getLatestBlockhash '[]' | is_method_not_found && fail "getLatestBlockhash: method not found"
rpc_call getLatestBlockhash '[]' | has_result || fail "getLatestBlockhash: missing result"

echo "[core] getBlock (${block_slot})"
resp="$(rpc_call getBlock "[${block_slot}]" || true)"
if [[ -z "${resp}" ]]; then
  fail "getBlock: empty response"
fi
printf "%s" "${resp}" | is_method_not_found && fail "getBlock: method not found"
# During bootstrap (slot=0 / snapshot download / no ledger history) getBlock may
# legitimately return an error like "Block not available for slot". Treat any
# non-32601 response as "method reachable".
if ! printf "%s" "${resp}" | has_result; then
  printf "%s" "${resp}" | has_error || fail "getBlock: missing result and error"
fi

echo "[core] getBlockTime (${block_slot})"
rpc_call getBlockTime "[${block_slot}]" | is_method_not_found && fail "getBlockTime: method not found"

echo "[core] getBlockHeight"
rpc_call getBlockHeight '[]' | is_method_not_found && fail "getBlockHeight: method not found"

echo "[core] getGenesisHash"
rpc_call getGenesisHash '[]' | is_method_not_found && fail "getGenesisHash: method not found"

echo "[core] getIdentity"
rpc_call getIdentity '[]' | is_method_not_found && fail "getIdentity: method not found"

echo "[core] getBalance (SystemProgram)"
rpc_call getBalance "[\"11111111111111111111111111111111\"]" | is_method_not_found && fail "getBalance: method not found"

echo "[core] getAccountInfo (SystemProgram)"
rpc_call getAccountInfo "[\"11111111111111111111111111111111\"]" | is_method_not_found && fail "getAccountInfo: method not found"

# Dispatch coverage: walk the method routing table and ensure nothing returns
# -32601 (method not found). Invalid params is acceptable here.
methods="$(
  # Extract method names from the dispatch chain in src/rpc/sol_rpc.c.
  # Keep this POSIX/simple: ripgrep uses Rust-regex syntax.
  # sol_rpc.c also has HTTP and WS code that uses a `method` variable (GET/POST,
  # ...Subscribe). Only scan the JSON-RPC dispatch block.
  sed -n '/Route to method handler/,/HTTP handling/p' src/rpc/sol_rpc.c | \
    rg -o 'strcmp\(method, \"[^\"]+\"' | \
    sed -E 's/.*\"([^\"]+)\".*/\1/' | sort -u
)"

bad=0
count=0
while IFS= read -r m; do
  [[ -n "${m}" ]] || continue
  count=$((count + 1))
  resp="$(rpc_call "${m}" '[]' || true)"
  if [[ -z "${resp}" ]]; then
    echo "[missing] ${m}: empty response"
    bad=$((bad + 1))
    continue
  fi
  if printf "%s" "${resp}" | is_method_not_found; then
    echo "[missing] ${m}: method not found"
    bad=$((bad + 1))
    continue
  fi
done <<< "${methods}"

echo "checked_methods=${count} missing_methods=${bad}"
if [[ "${bad}" -ne 0 ]]; then
  exit 1
fi

echo "OK"
