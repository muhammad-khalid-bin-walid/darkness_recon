#!/bin/bash
# lib/phase_bridge.sh — Shell bridge functions wrapping Python lib layer
# Source this from core.sh or individual phases

BRIDGE_PYTHON="${BRIDGE_PYTHON:-python3}"
BRIDGE_MODULE="lib.phase_bridge"
LIB_DIR="${LIB_DIR:-$(dirname "${BASH_SOURCE[0]}")}"

# Validate a JSON dict against a schema model and write to output path
# Usage: py_validate <model_type> <json_string> <output_path>
py_validate() {
    local model_type="$1"
    local json_string="$2"
    local output_path="$3"
    cd "$LIB_DIR/.." && "$BRIDGE_PYTHON" -m "$BRIDGE_MODULE" validate "$model_type" "$json_string" "$output_path" 2>/dev/null
    return $?
}

# Validate a JSON file against a schema model
# Usage: py_validate_file <model_type> <input_file> <output_path>
py_validate_file() {
    local model_type="$1"
    local input_file="$2"
    local output_path="$3"
    cd "$LIB_DIR/.." && "$BRIDGE_PYTHON" -m "$BRIDGE_MODULE" validate_file "$model_type" "$input_file" "$output_path" 2>/dev/null
    return $?
}

# Emit a structured JSON log record via Python logger
# Usage: py_log <level> <event> [--phase <phase>] [--target <target>] [--duration <ms>] [--extra <json>]
py_log() {
    cd "$LIB_DIR/.." && "$BRIDGE_PYTHON" -m "$BRIDGE_MODULE" log "$@" 2>/dev/null
    return $?
}

# Check if a target is in scope for a program
# Usage: py_scope_check <target> <program> [--config_dir <dir>]
# Returns 0 if in scope, 1 if out of scope
py_scope_check() {
    cd "$LIB_DIR/.." && "$BRIDGE_PYTHON" -m "$BRIDGE_MODULE" scope_check "$@"
    return $?
}

# Filter a file of targets into in-scope and out-of-scope lists
# Usage: py_filter_scope <targets_file> <program> [--config_dir <dir>]
py_filter_scope() {
    cd "$LIB_DIR/.." && "$BRIDGE_PYTHON" -m "$BRIDGE_MODULE" filter_scope "$@"
    return $?
}

# Calculate confidence score
# Usage: py_score <source_count> <evidence_quality> <cross_validated>
py_score() {
    cd "$LIB_DIR/.." && "$BRIDGE_PYTHON" -m "$BRIDGE_MODULE" score "$@"
    return $?
}

# Deduplicate findings
# Usage: py_dedup <input_file> <output_file> [--key <field>]
py_dedup() {
    cd "$LIB_DIR/.." && "$BRIDGE_PYTHON" -m "$BRIDGE_MODULE" dedup "$@"
    return $?
}

# Batch validate JSON files in a directory
# Usage: py_batch_validate <model_type> <input_dir> <output_dir>
py_batch_validate() {
    cd "$LIB_DIR/.." && "$BRIDGE_PYTHON" -m "$BRIDGE_MODULE" batch_validate "$@"
    return $?
}

# Write a finding using Python validation + JSON persistence
# Usage: write_finding <json_string> <output_path>
write_finding() {
    py_validate "finding" "$1" "$2"
    local rc=$?
    if [ $rc -eq 0 ]; then
        py_log "INFO" "Finding written" --extra "$1" 2>/dev/null || true
    else
        py_log "ERROR" "Finding validation failed" --extra "$1" 2>/dev/null || true
    fi
    return $rc
}

# Write an asset using Python validation + JSON persistence
# Usage: write_asset <json_string> <output_path>
write_asset() {
    py_validate "asset" "$1" "$2"
    local rc=$?
    if [ $rc -eq 0 ]; then
        py_log "INFO" "Asset written" --extra "$1" 2>/dev/null || true
    else
        py_log "ERROR" "Asset validation failed" --extra "$1" 2>/dev/null || true
    fi
    return $rc
}

# Write an endpoint using Python validation + JSON persistence
# Usage: write_endpoint <json_string> <output_path>
write_endpoint() {
    py_validate "endpoint" "$1" "$2"
    local rc=$?
    if [ $rc -eq 0 ]; then
        py_log "INFO" "Endpoint written" --extra "$1" 2>/dev/null || true
    else
        py_log "ERROR" "Endpoint validation failed" --extra "$1" 2>/dev/null || true
    fi
    return $rc
}

# Phase-scoped logging wrapper (combines shell log + Python structured log)
# Usage: phase_log <level> <message> <phase> <target>
phase_log() {
    local level="$1"
    local message="$2"
    local phase="${3:-}"
    local target="${4:-}"
    log "$level" "$message"
    if [ -n "$phase" ]; then
        py_log "$level" "$message" --phase "$phase" --target "$target" 2>/dev/null || true
    fi
}

# Scope-gated execution: run a command only if target is in scope
# Usage: scope_guard <target> <program> <command...>
scope_guard() {
    local target="$1"
    local program="$2"
    shift 2
    if py_scope_check "$target" "$program" >/dev/null 2>&1; then
        "$@"
        return $?
    else
        phase_log "WARN" "Target $target is out of scope for program $program" "scope_guard" "$target"
        return 1
    fi
}

export -f py_validate py_validate_file py_log py_scope_check py_filter_scope py_score py_dedup py_batch_validate write_finding write_asset write_endpoint phase_log scope_guard
