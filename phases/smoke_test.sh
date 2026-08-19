#!/usr/bin/env bash
# Dark Recon Framework - End-to-End Smoke Test
# Verifies all phases load and execute without errors
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRAMEWORK_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DOMAIN="${1:-example.com}"
PASS=0
FAIL=0
ERRORS=()

echo "============================================"
echo " Dark Recon Framework - End-to-End Smoke Test"
echo "============================================"
echo "Test domain: $TEST_DOMAIN"
echo ""

# Source core
echo "[1/4] Sourcing core/core.sh..."
source "$FRAMEWORK_DIR/core/core.sh"
echo "  OK - core.sh loaded"

# Source phase_manager
echo "[2/4] Sourcing phases/phase_manager.sh..."
source "$FRAMEWORK_DIR/phases/phase_manager.sh"
echo "  OK - phase_manager.sh loaded"

# Check bridge functions are available
echo "[3/4] Checking bridge functions..."
for func in py_validate py_log write_finding write_asset scope_guard phase_log; do
    if type "$func" &>/dev/null; then
        echo "  OK - $func available"
        ((PASS++))
    else
        echo "  FAIL - $func not found"
        ERRORS+=("$func not available")
        ((FAIL++))
    fi
done

# Count phases in PHASE_DEPS
echo "[4/4] Checking phase registry..."
phase_count=${#PHASE_DEPS[@]}
enabled_count=0
for phase in "${!PHASE_ENABLED[@]}"; do
    ((enabled_count++))
done

echo "  PHASE_DEPS entries: $phase_count"
echo "  PHASE_ENABLED entries: $enabled_count"

if [ "$phase_count" -ge 290 ]; then
    echo "  OK - Phase count looks correct"
    ((PASS++))
else
    echo "  WARN - Phase count lower than expected (need 290+)"
    ERRORS+=("Phase count $phase_count < 290")
    ((FAIL++))
fi

# Check that phase files exist for enabled phases
echo ""
echo "Checking phase files for enabled phases..."
missing=0
for phase in "${!PHASE_ENABLED[@]}"; do
    mapped_name="${phase_map_${phase}:-$phase}"
    phase_file="$FRAMEWORK_DIR/phases/${mapped_name}_phase.sh"
    if [ ! -f "$phase_file" ]; then
        echo "  MISSING: $phase -> $phase_file"
        ((missing++))
    fi
done

if [ "$missing" -eq 0 ]; then
    echo "  OK - All enabled phase files exist"
    ((PASS++))
else
    echo "  FAIL - $missing phase files missing"
    ERRORS+=("$missing phase files missing")
    ((FAIL++))
fi

# Summary
echo ""
echo "============================================"
echo " RESULTS: $PASS passed, $FAIL failed"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    echo "Errors:"
    for err in "${ERRORS[@]}"; do
        echo "  - $err"
    done
    exit 1
fi

echo "All smoke tests passed!"
exit 0
