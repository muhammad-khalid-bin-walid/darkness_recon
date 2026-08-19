#!/bin/bash
# Track 7 - Distributed Scale: Priority scan lanes phase
# Critical path optimization, resource reservation, lane management

priority_lanes_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/priority_lanes"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting priority lanes phase for $domain"
    py_log "INFO" "priority_lanes_phase_start" --phase "priority_lanes" --target "$domain" 2>/dev/null || true

    local priority_config="$phase_dir/priority_config.json"
    local lane_status="$phase_dir/lane_status.txt"
    local count=0

    # Define priority lanes
    local critical_phases=("subdomain_bruteforce" "live_host_detection" "port_scan")
    local high_phases=("web_crawl" "technology_fingerprint" "ssl_analysis")
    local normal_phases=("osint_collection" "metadata_harvest" "dns_analysis")
    local low_phases=("historical_lookup" "report_generation" "archive_export")

    # Resource allocation per lane
    local total_cpu=1
    if command -v nproc >/dev/null 2>&1; then
        total_cpu=$(nproc 2>/dev/null || echo 1)
    fi

    local critical_cpu=$((total_cpu * 40 / 100))
    local high_cpu=$((total_cpu * 30 / 100))
    local normal_cpu=$((total_cpu * 20 / 100))
    local low_cpu=$((total_cpu * 10 / 100))
    [ "$critical_cpu" -lt 1 ] && critical_cpu=1
    [ "$high_cpu" -lt 1 ] && high_cpu=1

    cat > "$priority_config" <<JSONEOF
{
    "domain": "$domain",
    "lanes": {
        "critical": {
            "priority": 1,
            "cpu_allocation": $critical_cpu,
            "max_concurrent": 4,
            "timeout_seconds": 600,
            "preempt_lower": true,
            "phases": [$(printf '"%s",' "${critical_phases[@]}" | sed 's/,$//')]
        },
        "high": {
            "priority": 2,
            "cpu_allocation": $high_cpu,
            "max_concurrent": 8,
            "timeout_seconds": 900,
            "preempt_lower": true,
            "phases": [$(printf '"%s",' "${high_phases[@]}" | sed 's/,$//')]
        },
        "normal": {
            "priority": 3,
            "cpu_allocation": $normal_cpu,
            "max_concurrent": 16,
            "timeout_seconds": 1800,
            "preempt_lower": false,
            "phases": [$(printf '"%s",' "${normal_phases[@]}" | sed 's/,$//')]
        },
        "low": {
            "priority": 4,
            "cpu_allocation": $low_cpu,
            "max_concurrent": 32,
            "timeout_seconds": 3600,
            "preempt_lower": false,
            "phases": [$(printf '"%s",' "${low_phases[@]}" | sed 's/,$//')]
        }
    },
    "scheduling": {
        "algorithm": "weighted_priority",
        "aging_enabled": true,
        "aging_factor": 0.1,
        "max_starvation_seconds": 600,
        "resource_reservation": true
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    cat > "$lane_status" <<STATUSEOF
Priority Lane Status
====================
Domain: $domain
Total CPU Cores: $total_cpu
Critical Lane: ${critical_cpu} cores (${#critical_phases[@]} phases)
High Lane: ${high_cpu} cores (${#high_phases[@]} phases)
Normal Lane: ${normal_cpu} cores (${#normal_phases[@]} phases)
Low Lane: ${low_cpu} cores (${#low_phases[@]} phases)
Total Phases: $((${#critical_phases[@]} + ${#high_phases[@]} + ${#normal_phases[@]} + ${#low_phases[@]}))
Scheduling: Weighted priority with aging
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
    count=$((count + 1))

    write_finding "{\"type\":\"priority_lanes_configured\",\"domain\":\"$domain\",\"lanes\":4,\"total_phases\":$((${#critical_phases[@]} + ${#high_phases[@]} + ${#normal_phases[@]} + ${#low_phases[@]}))}" "$phase_dir/finding_lanes.json" 2>/dev/null || true

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Priority lanes phase complete: $count results"
    py_log "INFO" "priority_lanes_phase_complete" --phase "priority_lanes" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}

export -f priority_lanes_phase
