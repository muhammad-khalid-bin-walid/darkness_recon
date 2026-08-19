#!/usr/bin/env bash
# tests/bats/setup.bash — Common test environment for bats tests

export OUTPUT_DIR="/tmp/dark_recon_test_output"
export CACHE_DIR="/tmp/dark_recon_test_cache"
export LOGS_DIR="/tmp/dark_recon_test_logs"
export THREADS=10
export TIMEOUT=30
export TIMESTAMP="20260101_000000"
export DOMAIN="test.example.com"
export GRACEFUL_DEGRADATION=true
export DEBUG_MODE=false

mkdir -p "$OUTPUT_DIR" \
         "$CACHE_DIR/state/${DOMAIN}" \
         "$CACHE_DIR/wordlists" \
         "$LOGS_DIR"

# Minimal log() stub so phases can call it without sourcing full core.sh
if ! declare -f log >/dev/null 2>&1; then
    log() {
        local level="$1"; shift
        echo "[${level}] $*" >&2
    }
    export -f log
fi

# Minimal tool_available() stub
if ! declare -f tool_available >/dev/null 2>&1; then
    tool_available() {
        command -v "$1" >/dev/null 2>&1
    }
    export -f tool_available
fi
