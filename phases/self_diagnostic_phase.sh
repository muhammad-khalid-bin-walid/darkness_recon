#!/bin/bash
# Track 9 - ML/Triage/Future: Self-diagnostic health checks, tool availability, config validation

self_diagnostic_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/self_diagnostic"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting self-diagnostic phase for $domain"
    py_log "INFO" "self_diagnostic_phase_start" --phase "self_diagnostic" --target "$domain" 2>/dev/null || true

    local diagnostic_report="$phase_dir/diagnostic_report.json"
    local health_status="$phase_dir/health_status.txt"
    local count=0

    log "INFO" "Running self-diagnostic health checks..."

    # Tool availability checks
    local tools_to_check=(
        "subfinder" "httpx" "nuclei" "katana" "nmap" "ffuf" "jq"
        "python3" "curl" "dig" "whois" "git" "go"
    )

    local tool_results=()
    for tool in "${tools_to_check[@]}"; do
        if tool_available "$tool" 2>/dev/null; then
            tool_results+=("{\"tool\":\"$tool\",\"status\":\"available\",\"version\":\"$(command -v "$tool" 2>/dev/null || echo 'unknown')\"}")
        else
            tool_results+=("{\"tool\":\"$tool\",\"status\":\"missing\",\"version\":\"N/A\"}")
        fi
    done

    # Config validation
    local config_valid=true
    local config_issues=()

    if [ ! -d "$OUTPUT_DIR" ]; then
        config_valid=false
        config_issues+=("OUTPUT_DIR does not exist: $OUTPUT_DIR")
    fi

    if [ ! -d "$LOGS_DIR" ] 2>/dev/null; then
        config_valid=false
        config_issues+=("LOGS_DIR does not exist")
    fi

    if [ ! -d "$CACHE_DIR" ] 2>/dev/null; then
        config_valid=false
        config_issues+=("CACHE_DIR does not exist")
    fi

    # Directory structure validation
    local dirs_to_check=(
        "$OUTPUT_DIR/$domain"
        "$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    )

    local dir_results=()
    for d in "${dirs_to_check[@]}"; do
        if [ -d "$d" ]; then
            dir_results+=("{\"path\":\"$d\",\"exists\":true,\"writable\":$([ -w "$d" ] && echo true || echo false)}")
        else
            dir_results+=("{\"path\":\"$d\",\"exists\":false,\"writable\":false}")
        fi
    done

    # Disk space check
    local disk_avail=0
    if command -v df >/dev/null 2>&1; then
        disk_avail=$(df -m "$OUTPUT_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
    fi

    # Python availability
    local python_ok=false
    if command -v python3 >/dev/null 2>&1; then
        python_ok=true
    fi

    # Phase bridge availability
    local bridge_ok=false
    if declare -f write_finding >/dev/null 2>&1; then
        bridge_ok=true
    fi

    # Write diagnostic report
    python3 -c "
import json, os, sys

tool_results = [$(printf '%s,' "${tool_results[@]}" | sed 's/,$//')]
dir_results = [$(printf '%s,' "${dir_results[@]}" | sed 's/,$//')]
config_issues = $(printf '"%s",' "${config_issues[@]}" | sed 's/,$//')

report = {
    'domain': '$domain',
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'overall_health': 'healthy' if '$config_valid' == 'true' and len(config_issues) == 0 else 'degraded',
    'tool_availability': tool_results,
    'tools_available': sum(1 for t in tool_results if t.get('status') == 'available'),
    'tools_missing': sum(1 for t in tool_results if t.get('status') == 'missing'),
    'config_validation': {
        'valid': '$config_valid' == 'true',
        'issues': config_issues
    },
    'directory_structure': dir_results,
    'disk_space_mb': int('$disk_avail'),
    'python_available': '$python_ok' == 'true',
    'phase_bridge_available': '$bridge_ok' == 'true',
    'checks_performed': len(tool_results) + len(dir_results) + 3
}

with open(os.path.join('$phase_dir', 'diagnostic_report.json'), 'w') as f:
    json.dump(report, f, indent=2)

print(report['checks_performed'])
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    # Write health status text
    {
        echo "Self-Diagnostic Report - $domain"
        echo "=================================================="
        echo ""
        echo "Overall Health: $([ "$config_valid" = true ] && echo HEALTHY || echo DEGRADED)"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Tool Availability:"
        for result in "${tool_results[@]}"; do
            local tool_name
            tool_name=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin)['tool'])" 2>/dev/null || echo "?")
            local tool_status
            tool_status=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "?")
            echo "  $tool_name: $tool_status"
        done
        echo ""
        echo "Config Valid: $config_valid"
        echo "Python Available: $python_ok"
        echo "Phase Bridge Available: $bridge_ok"
        echo "Disk Space: ${disk_avail}MB available"
        echo ""
        echo "Checks Performed: $count"
    } > "$phase_dir/health_status.txt" 2>/dev/null || true

    if [ -f "$diagnostic_report" ]; then
        write_finding "{\"type\":\"self_diagnostic_complete\",\"target\":\"$domain\",\"checks_performed\":$count,\"method\":\"health_check\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_diagnostic.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Self-diagnostic phase complete: $count checks performed for $domain"
    py_log "INFO" "self_diagnostic_phase_complete" --phase "self_diagnostic" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
