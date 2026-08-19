#!/bin/bash
# lib/idempotency.sh — Idempotent phase design helpers (plan Phase 13)
# Re-running a phase never duplicates or corrupts prior output.

# is_phase_output_valid <output_file> [min_bytes]
# Returns 0 if the file exists, is non-empty, and passes basic JSON validation.
is_phase_output_valid() {
    local output_file="$1"
    local min_bytes="${2:-1}"

    # File must exist and be readable
    [ -f "${output_file}" ] || return 1

    # File must be larger than min_bytes
    local size
    size=$(wc -c < "${output_file}" 2>/dev/null || echo 0)
    [ "${size}" -ge "${min_bytes}" ] || return 1

    # If it ends in .json, do a basic JSON validity check
    case "${output_file}" in
        *.json)
            if command -v jq >/dev/null 2>&1; then
                jq empty "${output_file}" 2>/dev/null || return 1
            elif command -v python3 >/dev/null 2>&1; then
                python3 -c "import json,sys; json.load(open(sys.argv[1]))" "${output_file}" 2>/dev/null || return 1
            fi
            ;;
    esac

    return 0
}

# is_phase_done <domain> <phase_name>
# Returns 0 if the checkpoint file exists for this domain+phase.
is_phase_done() {
    local domain="$1"
    local phase_name="$2"
    local state_file="${CACHE_DIR:-/tmp/cache}/state/${domain}/${phase_name}.done"
    [ -f "${state_file}" ]
}

# mark_phase_done <domain> <phase_name>
# Creates the checkpoint file marking this phase as complete.
mark_phase_done() {
    local domain="$1"
    local phase_name="$2"
    local state_dir="${CACHE_DIR:-/tmp/cache}/state/${domain}"
    mkdir -p "${state_dir}"
    echo "$(date -u +%s)" > "${state_dir}/${phase_name}.done"
}

# reset_phase <domain> <phase_name>
# Removes the checkpoint, allowing the phase to re-run.
reset_phase() {
    local domain="$1"
    local phase_name="$2"
    local state_dir="${CACHE_DIR:-/tmp/cache}/state/${domain}"
    rm -f "${state_dir}/${phase_name}.done" "${state_dir}/${phase_name}.failed" 2>/dev/null || true
}

# skip_if_done <domain> <phase_name>
# Call at the top of a phase function. Exits with 0 if already done.
skip_if_done() {
    local domain="$1"
    local phase_name="$2"
    if is_phase_done "${domain}" "${phase_name}"; then
        log "INFO" "[idempotency] Phase ${phase_name} already done for ${domain}, skipping" \
            2>/dev/null || echo "[*] Phase ${phase_name} already done, skipping"
        return 0
    fi
    return 1
}

export -f is_phase_output_valid is_phase_done mark_phase_done reset_phase skip_if_done
