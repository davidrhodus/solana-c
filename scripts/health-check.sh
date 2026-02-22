#!/bin/bash
#
# health-check.sh - Health check script for Solana C validator
#
# Returns exit code 0 if healthy, 1 if unhealthy
# Suitable for use with monitoring systems and load balancers
#

set -e

# Configuration
RPC_URL="${RPC_URL:-http://localhost:8899}"
TIMEOUT="${TIMEOUT:-5}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check health endpoint
check_health() {
    local response
    local status

    response=$(curl -s --max-time "$TIMEOUT" "${RPC_URL}/health" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "${RED}[FAIL]${NC} Cannot connect to ${RPC_URL}/health"
        return 1
    fi

    status=$(echo "$response" | grep -o '"status"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)

    case "$status" in
        ok)
            echo -e "${GREEN}[OK]${NC} Validator is healthy"
            return 0
            ;;
        degraded)
            echo -e "${YELLOW}[WARN]${NC} Validator is degraded"
            echo "$response" | grep -o '"message"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4
            return 0  # Degraded is still "alive"
            ;;
        unhealthy)
            echo -e "${RED}[FAIL]${NC} Validator is unhealthy"
            echo "$response" | grep -o '"message"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4
            return 1
            ;;
        *)
            echo -e "${RED}[FAIL]${NC} Unknown status: $status"
            return 1
            ;;
    esac
}

# Check liveness
check_live() {
    local response

    response=$(curl -s --max-time "$TIMEOUT" "${RPC_URL}/health/live" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "${RED}[FAIL]${NC} Liveness check failed"
        return 1
    fi

    if [ "$response" = "ok" ]; then
        echo -e "${GREEN}[OK]${NC} Validator is alive"
        return 0
    else
        echo -e "${RED}[FAIL]${NC} Validator not alive: $response"
        return 1
    fi
}

# Check readiness
check_ready() {
    local response

    response=$(curl -s --max-time "$TIMEOUT" "${RPC_URL}/health/ready" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "${RED}[FAIL]${NC} Readiness check failed"
        return 1
    fi

    if [ "$response" = "ready" ]; then
        echo -e "${GREEN}[OK]${NC} Validator is ready"
        return 0
    else
        echo -e "${YELLOW}[WARN]${NC} Validator not ready: $response"
        return 1
    fi
}

# Get detailed status
get_status() {
    local response

    response=$(curl -s --max-time "$TIMEOUT" "${RPC_URL}/health" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Cannot connect to validator"
        return 1
    fi

    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
}

# Check slot progress
check_slot() {
    local response
    local current
    local highest

    response=$(curl -s --max-time "$TIMEOUT" "${RPC_URL}/health" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "${RED}[FAIL]${NC} Cannot get slot info"
        return 1
    fi

    current=$(echo "$response" | grep -o '"current_slot"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*')
    highest=$(echo "$response" | grep -o '"highest_slot"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*')

    if [ -z "$current" ] || [ -z "$highest" ]; then
        echo -e "${RED}[FAIL]${NC} Cannot parse slot info"
        return 1
    fi

    local behind=$((highest - current))

    if [ $behind -gt 100 ]; then
        echo -e "${RED}[FAIL]${NC} Slot: $current (behind by $behind)"
        return 1
    elif [ $behind -gt 10 ]; then
        echo -e "${YELLOW}[WARN]${NC} Slot: $current (behind by $behind)"
        return 0
    else
        echo -e "${GREEN}[OK]${NC} Slot: $current (synced)"
        return 0
    fi
}

# Usage
usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  health    Full health check (default)"
    echo "  live      Liveness check only"
    echo "  ready     Readiness check only"
    echo "  status    Detailed status JSON"
    echo "  slot      Slot progress check"
    echo "  all       Run all checks"
    echo ""
    echo "Environment variables:"
    echo "  RPC_URL   RPC endpoint (default: http://localhost:8899)"
    echo "  TIMEOUT   Request timeout in seconds (default: 5)"
    echo ""
}

# Main
main() {
    case "${1:-health}" in
        health)
            check_health
            ;;
        live)
            check_live
            ;;
        ready)
            check_ready
            ;;
        status)
            get_status
            ;;
        slot)
            check_slot
            ;;
        all)
            echo "=== Health Check ==="
            check_health
            echo ""
            echo "=== Liveness Check ==="
            check_live
            echo ""
            echo "=== Readiness Check ==="
            check_ready
            echo ""
            echo "=== Slot Check ==="
            check_slot
            ;;
        -h|--help|help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

main "$@"
