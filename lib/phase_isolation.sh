#!/bin/bash
# lib/phase_isolation.sh — Crash isolation helpers (plan Phase 12)
# A single phase failure must never kill the whole run.

# run_isolated <phase_name> <function_name> [args...]
# Runs a phase function in an isolated subshell. Captures exit code and logs.
# Returns 0 even on phase failure (graceful degradation).
run_isolated() {
    local phase_name="$1"
    shift
    local func_name="$1"
    shift
    local args=("$@")

    local start_ts
    start_ts=$(date +%s%3N 2>/dev/null || date +%s)
    local phase_log="${LOGS_DIR:-/tmp}/phase_${phase_name}.log"

    log "INFO" "[isolation] Starting phase: ${phase_name}" 2>/dev/null || echo "[*] Starting phase: ${phase_name}"

    # Run in subshell — failures are contained
    (
        set +e
        "${func_name}" "${args[@]}" 2>&1
    ) > "${phase_log}" 2>&1
    local exit_code=$?

    local end_ts
    end_ts=$(date +%s%3N 2>/dev/null || date +%s)
    local duration_ms=$(( end_ts - start_ts ))

    if [ "${exit_code}" -ne 0 ]; then
        log "WARN" "[isolation] Phase ${phase_name} failed (exit=${exit_code}, duration=${duration_ms}ms) — continuing" \
            2>/dev/null || echo "[!] Phase ${phase_name} failed (exit=${exit_code}) — continuing"

        # Record failure in state
        local state_dir="${CACHE_DIR:-/tmp/cache}/state/${DOMAIN:-unknown}"
        mkdir -p "${state_dir}"
        echo "{\"phase\":\"${phase_name}\",\"status\":\"failed\",\"exit_code\":${exit_code},\"duration_ms\":${duration_ms}}" \
            > "${state_dir}/${phase_name}.failed"
    else
        log "INFO" "[isolation] Phase ${phase_name} completed (duration=${duration_ms}ms)" \
            2>/dev/null || echo "[*] Phase ${phase_name} completed"
    fi

    # Always return 0 — isolation means the run continues
    return 0
}

# is_phase_failed <phase_name> — returns 0 if phase failed in a prior run
is_phase_failed() {
    local phase_name="$1"
    local state_dir="${CACHE_DIR:-/tmp/cache}/state/${DOMAIN:-unknown}"
    [ -f "${state_dir}/${phase_name}.failed" ]
}

# clear_phase_failure <phase_name> — remove failure marker (allow retry)
clear_phase_failure() {
    local phase_name="$1"
    local state_dir="${CACHE_DIR:-/tmp/cache}/state/${DOMAIN:-unknown}"
    rm -f "${state_dir}/${phase_name}.failed" 2>/dev/null || true
}

export -f run_isolated is_phase_failed clear_phase_failure
