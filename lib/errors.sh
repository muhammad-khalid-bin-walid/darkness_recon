#!/bin/bash
# lib/errors.sh — Shell error taxonomy (plan Phase 14)
# classify_error() maps exit codes / tool output to taxonomy codes.

# Error codes matching lib/errors.py ErrorCode enum
readonly ERR_NETWORK="network"
readonly ERR_AUTH="auth"
readonly ERR_RATE_LIMIT="rate_limit"
readonly ERR_PARSE="parse"
readonly ERR_TOOL_MISSING="tool_missing"
readonly ERR_DISK="disk"
readonly ERR_CONFIG="config"
readonly ERR_SCOPE="scope"
readonly ERR_UNKNOWN="unknown"

# classify_error <exit_code> [stderr_snippet]
# Echos an error code string from the taxonomy.
classify_error() {
    local exit_code="${1:-0}"
    local stderr_snippet="${2:-}"
    local lower_stderr
    lower_stderr=$(echo "${stderr_snippet}" | tr '[:upper:]' '[:lower:]')

    # Tool not found
    if [ "${exit_code}" -eq 127 ] || echo "${lower_stderr}" | grep -q "command not found\|not found\|no such file"; then
        echo "${ERR_TOOL_MISSING}"
        return
    fi

    # Network errors
    if echo "${lower_stderr}" | grep -qE "connection refused|timeout|network|dns|resolve|no route"; then
        echo "${ERR_NETWORK}"
        return
    fi

    # Auth errors
    if echo "${lower_stderr}" | grep -qE "unauthorized|forbidden|401|403|authentication"; then
        echo "${ERR_AUTH}"
        return
    fi

    # Rate limit
    if echo "${lower_stderr}" | grep -qE "rate.?limit|429|too many requests|throttl"; then
        echo "${ERR_RATE_LIMIT}"
        return
    fi

    # Parse errors
    if echo "${lower_stderr}" | grep -qE "parse error|invalid json|syntax error|unexpected token|decode"; then
        echo "${ERR_PARSE}"
        return
    fi

    # Disk errors
    if echo "${lower_stderr}" | grep -qE "no space left|disk full|enospc|write.*fail"; then
        echo "${ERR_DISK}"
        return
    fi

    echo "${ERR_UNKNOWN}"
}

# log_classified_error <phase> <tool> <exit_code> [stderr_snippet]
# Logs a structured error with taxonomy code to LOGS_DIR.
log_classified_error() {
    local phase="${1:-unknown}"
    local tool="${2:-unknown}"
    local exit_code="${3:-1}"
    local stderr_snippet="${4:-}"
    local error_code
    error_code=$(classify_error "${exit_code}" "${stderr_snippet}")
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local record
    record="{\"timestamp\":\"${timestamp}\",\"level\":\"ERROR\",\"phase\":\"${phase}\",\"tool\":\"${tool}\",\"error_code\":\"${error_code}\",\"exit_code\":${exit_code}}"

    # Write to structured error log
    local err_log="${LOGS_DIR:-/tmp}/errors.jsonl"
    echo "${record}" >> "${err_log}" 2>/dev/null || true

    # Also emit via log() if available
    if declare -f log >/dev/null 2>&1; then
        log "ERROR" "[${error_code}] Tool ${tool} in phase ${phase} failed (exit=${exit_code})"
    else
        echo "[ERROR] [${error_code}] Tool ${tool} in phase ${phase} failed (exit=${exit_code})" >&2
    fi
}

export -f classify_error log_classified_error
