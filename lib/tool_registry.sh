#!/bin/bash
# lib/tool_registry.sh — Shell wrapper for tool auto-detection (plan Phase 6)
# Integrates with core.sh tool_available() and logs degradation events.

# Source this file to get enhanced tool checking with degradation logging.

# check_tool_with_fallback <tool_name>
# Returns the best available tool name (with fallback) or empty string if none.
check_tool_with_fallback() {
    local tool="$1"
    local fallback="${2:-}"

    if command -v "${tool}" >/dev/null 2>&1; then
        echo "${tool}"
        return 0
    fi

    if [ -n "${fallback}" ] && command -v "${fallback}" >/dev/null 2>&1; then
        log "WARN" "[tool_registry] ${tool} not found, using fallback: ${fallback}" 2>/dev/null \
            || echo "[!] ${tool} not found, using fallback: ${fallback}" >&2
        echo "${fallback}"
        return 0
    fi

    log "WARN" "[tool_registry] ${tool} not found (no fallback available)" 2>/dev/null \
        || echo "[!] ${tool} not found (no fallback available)" >&2
    echo ""
    return 1
}

# log_tool_degradation <tool_name> <fallback|""> <capabilities_affected>
log_tool_degradation() {
    local tool="$1"
    local fallback="${2:-none}"
    local capabilities="${3:-unknown}"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local record
    record="{\"timestamp\":\"${timestamp}\",\"level\":\"WARN\",\"event\":\"tool_degraded\",\"tool\":\"${tool}\",\"fallback\":\"${fallback}\",\"capabilities_affected\":\"${capabilities}\"}"

    if declare -f log >/dev/null 2>&1; then
        log "WARN" "[degraded] ${tool} unavailable — capabilities affected: ${capabilities}"
    fi
    echo "${record}" >> "${LOGS_DIR:-/tmp}/tool_degradation.jsonl" 2>/dev/null || true
}

# assert_essential_tool <tool_name>
# Exits 1 if the tool is not available.
assert_essential_tool() {
    local tool="$1"
    if ! command -v "${tool}" >/dev/null 2>&1; then
        if declare -f log >/dev/null 2>&1; then
            log "ERROR" "Essential tool '${tool}' not found. Install it and re-run."
        else
            echo "[ERROR] Essential tool '${tool}' not found. Install it and re-run." >&2
        fi
        return 1
    fi
    return 0
}

export -f check_tool_with_fallback log_tool_degradation assert_essential_tool
