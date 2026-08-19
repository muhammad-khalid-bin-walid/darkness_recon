#!/usr/bin/env bash
# lib/validate_output.sh — Thin bash wrapper around lib/validator.py
#
# Usage:
#   lib/validate_output.sh <model_type> <json_string> [output_file]
#
# model_type: asset | finding | endpoint | credential | scanrun
#
# Exit codes:
#   0  valid (and written to output_file if provided)
#   1  invalid — validation errors printed to stderr
#   2  bad usage (missing required arguments)
#
# Validation errors are written to stderr as JSON objects:
#   {"level": "ERROR", "error": "...", "data": ...}

set -euo pipefail

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

if [ "$#" -lt 2 ]; then
    echo '{"level":"ERROR","error":"Missing required arguments","data":null}' >&2
    echo "Usage: $0 <model_type> <json_string> [output_file]" >&2
    echo "  model_type: asset | finding | endpoint | credential | scanrun" >&2
    exit 2
fi

MODEL_TYPE="$1"
JSON_STRING="$2"
OUTPUT_FILE="${3:-}"

# ---------------------------------------------------------------------------
# Run Python validator
# ---------------------------------------------------------------------------

if [ -n "$OUTPUT_FILE" ]; then
    python3 -m lib.validator "$MODEL_TYPE" "$JSON_STRING" "$OUTPUT_FILE"
else
    python3 -m lib.validator "$MODEL_TYPE" "$JSON_STRING"
fi
