#!/usr/bin/env bash
# Phase 289: Exit Code Documentation, Error Code Reference, Troubleshooting Guide
# Track 20 - UX/CLI

ux_exit_codes() {
    local domain="${1:?Usage: ux_exit_codes <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/ux_exit_codes"
    mkdir -p "$phase_dir"

    log "INFO" "[EXIT_CODES] Generating exit code documentation for $domain"

    local exit_codes="$phase_dir/exit_codes.json"
    local error_reference="$phase_dir/error_reference.txt"

    local count=0

    cat > "$exit_codes" <<ECEOF
{
  "domain": "$domain",
  "timestamp": "$TIMESTAMP",
  "exit_codes": [
    {"code": 0, "name": "SUCCESS", "description": "Operation completed successfully"},
    {"code": 1, "name": "GENERAL_ERROR", "description": "General/unknown error"},
    {"code": 2, "name": "USAGE_ERROR", "description": "Incorrect command usage"},
    {"code": 3, "name": "DOMAIN_ERROR", "description": "Invalid or unreachable domain"},
    {"code": 4, "name": "TOOL_MISSING", "description": "Required tool not available"},
    {"code": 5, "name": "NETWORK_ERROR", "description": "Network connectivity issue"},
    {"code": 6, "name": "TIMEOUT", "description": "Operation timed out"},
    {"code": 7, "name": "PERMISSION_DENIED", "description": "Insufficient permissions"},
    {"code": 8, "name": "OUTPUT_ERROR", "description": "Cannot write to output directory"},
    {"code": 9, "name": "PHASE_FAILED", "description": "Phase execution failed"},
    {"code": 10, "name": "CONFIG_ERROR", "description": "Configuration error"},
    {"code": 11, "name": "DEPENDENCY_ERROR", "description": "Missing dependency"},
    {"code": 12, "name": "RATE_LIMITED", "description": "Rate limit exceeded"},
    {"code": 13, "name": "AUTH_REQUIRED", "description": "Authentication required"},
    {"code": 14, "name": "SANDBOX_VIOLATION", "description": "Sandbox restriction violated"},
    {"code": 15, "name": "PLUGIN_ERROR", "description": "Plugin execution error"}
  ]
}
ECEOF
    count=$((count + 1))

    log "INFO" "[EXIT_CODES] Generating error reference"
    {
        echo "=== Error Reference Guide ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Exit Code Reference:"
        echo ""
        echo "  0  SUCCESS           Operation completed successfully"
        echo "  1  GENERAL_ERROR     General/unknown error occurred"
        echo "  2  USAGE_ERROR       Check command syntax and arguments"
        echo "  3  DOMAIN_ERROR      Domain is invalid or unreachable"
        echo "  4  TOOL_MISSING      Install required tool (see tool_available)"
        echo "  5  NETWORK_ERROR     Check network connectivity"
        echo "  6  TIMEOUT           Increase timeout or check target"
        echo "  7  PERMISSION_DENIED Run with appropriate privileges"
        echo "  8  OUTPUT_ERROR      Check OUTPUT_DIR permissions"
        echo "  9  PHASE_FAILED      Check phase logs for details"
        echo " 10  CONFIG_ERROR      Review configuration files"
        echo " 11  DEPENDENCY_ERROR  Install missing dependencies"
        echo " 12  RATE_LIMITED      Wait and retry with delay"
        echo " 13  AUTH_REQUIRED     Provide authentication credentials"
        echo " 14  SANDBOX_VIOLATION Check sandbox restrictions"
        echo " 15  PLUGIN_ERROR      Review plugin logs"
        echo ""
        echo "Troubleshooting:"
        echo ""
        echo "  - Check phase output in $output_dir/"
        echo "  - Review count.txt for completion status"
        echo "  - Enable --debug for verbose output"
        echo "  - Use --dry-run to preview execution"
        echo "  - Check tool availability with tool_available"
    } > "$error_reference"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "EXIT_CODES" "Exit code documentation generated" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "exit_codes_complete" "Exit codes documentation complete: $count items"
    log "INFO" "[EXIT_CODES] Completed: $count items generated"

    return 0
}
