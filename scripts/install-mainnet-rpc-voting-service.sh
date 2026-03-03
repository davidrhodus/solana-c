#!/usr/bin/env bash
#
# install-mainnet-rpc-voting-service.sh
#
# Install the dedicated systemd service + env file for the combined
# RPC+voting mainnet canary profile.
#

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "error: run as root (or via sudo)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_DIR="/etc/solana-c"
ENV_PATH="${ENV_DIR}/mainnet-rpc-voting.env"
SERVICE_PATH="/etc/systemd/system/solana-validator-rpc-voting.service"

install -d -m 0755 "${ENV_DIR}"
install -m 0644 "${SCRIPT_DIR}/mainnet-rpc-voting.env.example" "${ENV_PATH}"
install -m 0644 "${SCRIPT_DIR}/solana-validator-rpc-voting.service" "${SERVICE_PATH}"

echo "Installed:"
echo "  ${ENV_PATH}"
echo "  ${SERVICE_PATH}"
echo
echo "Next:"
echo "  1) Edit ${ENV_PATH} (IDENTITY_PATH, VOTE_ACCOUNT, paths/ports)"
echo "  2) systemctl daemon-reload"
echo "  3) systemctl enable --now solana-validator-rpc-voting"
echo "  4) journalctl -u solana-validator-rpc-voting -f"
