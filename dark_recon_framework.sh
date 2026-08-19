#!/bin/bash
# Dark Recon Framework 1.0.1 - 41-Phase Zero False Positive Reconnaissance Framework
# Made by DarkLegende
# Wrapper for backward compatibility - calls the modular architecture

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if v4 modular structure exists
if [ -f "$SCRIPT_DIR/phases/phase_manager.sh" ]; then
    exec "$SCRIPT_DIR/phases/phase_manager.sh" "$@"
else
    echo "[ERROR] Modular v4 structure not found. Please ensure all files are present."
    exit 1
fi