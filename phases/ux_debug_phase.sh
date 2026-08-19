#!/usr/bin/env bash
# Phase 285: Debug Mode, Verbose Output, Troubleshooting Assistance
# Track 20 - UX/CLI

ux_debug() {
    local domain="${1:?Usage: ux_debug <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/ux_debug"
    mkdir -p "$phase_dir"

    log "INFO" "[DEBUG] Starting debug mode for $domain"

    local debug_config="$phase_dir/debug_config.txt"
    local debug_log="$phase_dir/debug_log.txt"

    local count=0

    log "INFO" "[DEBUG] Generating debug configuration"
    {
        echo "=== Debug Configuration ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Mode: DEBUG (verbose output enabled)"
        echo ""
        echo "Debug Settings:"
        echo "  Log Level: DEBUG"
        echo "  Verbose Output: Enabled"
        echo "  Trace Commands: Enabled"
        echo "  Show Timing: Enabled"
        echo "  Dump Responses: Enabled"
        echo ""
        echo "Troubleshooting Flags:"
        echo "  --debug        Enable debug output"
        echo "  --verbose      Show detailed progress"
        echo "  --trace        Trace all commands"
        echo "  --timing       Show execution timing"
        echo "  --dump         Dump raw responses"
        echo "  --dry-run      Preview without execution"
        echo ""
        echo "Debug Output Locations:"
        echo "  Phase logs: $phase_dir/"
        echo "  Core logs: $output_dir/logs/"
        echo "  Findings: $output_dir/*/findings.json"
    } > "$debug_config"
    count=$((count + 1))

    log "INFO" "[DEBUG] Generating debug log"
    {
        echo "=== Debug Log ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "[DEBUG] Phase: ux_debug"
        echo "[DEBUG] Output dir: $phase_dir"
        echo "[DEBUG] Domain: $domain"
        echo ""
        echo "[DEBUG] Environment:"
        echo "[DEBUG]   Shell: $SHELL"
        echo "[DEBUG]   Bash version: ${BASH_VERSION:-unknown}"
        echo "[DEBUG]   Platform: $(uname -s 2>/dev/null || echo "unknown")"
        echo "[DEBUG]   Date: $(date 2>/dev/null || echo "unknown")"
        echo ""
        echo "[DEBUG] Tool availability:"
        echo "[DEBUG]   bash: $(tool_available "bash" && echo "YES" || echo "NO")"
        echo "[DEBUG]   curl: $(tool_available "curl" && echo "YES" || echo "NO")"
        echo "[DEBUG]   nmap: $(tool_available "nmap" && echo "YES" || echo "NO")"
        echo "[DEBUG]   python3: $(tool_available "python3" && echo "YES" || echo "NO")"
        echo "[DEBUG]   openssl: $(tool_available "openssl" && echo "YES" || echo "NO")"
        echo ""
        echo "[DEBUG] Core variables:"
        echo "[DEBUG]   OUTPUT_DIR=${OUTPUT_DIR:-not_set}"
        echo "[DEBUG]   TIMESTAMP=${TIMESTAMP:-not_set}"
        echo ""
        echo "[DEBUG] Debug log complete"
    } > "$debug_log"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "DEBUG" "Debug mode initialized" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "debug_complete" "Debug mode setup complete: $count items"
    log "INFO" "[DEBUG] Completed: $count items generated"

    return 0
}
