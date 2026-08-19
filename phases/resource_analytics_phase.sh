#!/bin/bash
# Track 7 - Distributed Scale: Resource usage analytics phase
# Performance metrics, capacity planning, trend analysis

resource_analytics_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/resource_analytics"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting resource analytics phase for $domain"
    py_log "INFO" "resource_analytics_phase_start" --phase "resource_analytics" --target "$domain" 2>/dev/null || true

    local analytics_config="$phase_dir/analytics_config.json"
    local usage_metrics="$phase_dir/usage_metrics.txt"
    local count=0

    # Collect comprehensive system metrics
    local cpu_cores=1
    local cpu_usage_pct=0
    local mem_total_mb=0
    local mem_used_mb=0
    local mem_avail_mb=0
    local disk_total_gb=0
    local disk_used_gb=0
    local load_1=0
    local load_5=0
    local load_15=0

    if command -v nproc >/dev/null 2>&1; then
        cpu_cores=$(nproc 2>/dev/null || echo 1)
    fi

    if command -v free >/dev/null 2>&1; then
        mem_total_mb=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo 0)
        mem_used_mb=$(free -m 2>/dev/null | awk '/Mem:/ {print $3}' || echo 0)
        mem_avail_mb=$(free -m 2>/dev/null | awk '/Mem:/ {print $7}' || echo 0)
        if [ "$mem_total_mb" -gt 0 ] 2>/dev/null; then
            cpu_usage_pct=$((mem_used_mb * 100 / mem_total_mb))
        fi
    fi

    if command -v df >/dev/null 2>&1; then
        disk_total_gb=$(df -BG "$OUTPUT_DIR" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$2); print $2}' || echo 0)
        disk_used_gb=$(df -BG "$OUTPUT_DIR" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$3); print $3}' || echo 0)
    fi

    if [ -f /proc/loadavg ] 2>/dev/null; then
        read -r load_1 load_5 load_15 _ < /proc/loadavg 2>/dev/null || true
    fi

    # Count phase outputs
    local total_findings=0
    local total_assets=0
    local total_endpoints=0
    local phase_dirs=0

    if [ -d "$output_dir" ]; then
        phase_dirs=$(find "$output_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l || echo 0)
        total_findings=$(find "$output_dir" -name "finding_*.json" -type f 2>/dev/null | wc -l || echo 0)
        total_assets=$(find "$output_dir" -name "asset_*.json" -type f 2>/dev/null | wc -l || echo 0)
        total_endpoints=$(find "$output_dir" -name "endpoint_*.json" -type f 2>/dev/null | wc -l || echo 0)
    fi

    # Scan duration
    local scan_start_time=""
    local scan_duration_s=0
    if [ -f "$output_dir/.scan_start" ]; then
        scan_start_time=$(cat "$output_dir/.scan_start" 2>/dev/null || echo "")
    fi
    local now_ts
    now_ts=$(date +%s 2>/dev/null || date +%s)
    if [ -n "$scan_start_time" ]; then
        scan_duration_s=$((now_ts - scan_start_time))
    fi

    cat > "$analytics_config" <<JSONEOF
{
    "domain": "$domain",
    "system_metrics": {
        "cpu_cores": $cpu_cores,
        "memory_total_mb": $mem_total_mb,
        "memory_used_mb": $mem_used_mb,
        "memory_available_mb": $mem_avail_mb,
        "memory_usage_pct": $cpu_usage_pct,
        "disk_total_gb": $disk_total_gb,
        "disk_used_gb": $disk_used_gb,
        "load_average": {"1m": $load_1, "5m": $load_5, "15m": $load_15}
    },
    "scan_metrics": {
        "phase_directories": $phase_dirs,
        "total_findings": $total_findings,
        "total_assets": $total_assets,
        "total_endpoints": $total_endpoints,
        "scan_duration_seconds": $scan_duration_s
    },
    "performance": {
        "findings_per_second": "$(awk "BEGIN {printf \"%.4f\", ($total_findings / ($scan_duration_s > 0 ? $scan_duration_s : 1))}" 2>/dev/null || echo 0)",
        "phases_completed": $phase_dirs,
        "avg_time_per_phase": "$(awk "BEGIN {printf \"%.1f\", ($scan_duration_s / ($phase_dirs > 0 ? $phase_dirs : 1))}" 2>/dev/null || echo 0)"
    },
    "capacity_planning": {
        "estimated_total_scan_gb": "$(awk "BEGIN {printf \"%.2f\", $disk_used_gb * 1.5}" 2>/dev/null || echo 0)",
        "recommended_min_memory_mb": $((mem_used_mb * 2)),
        "recommended_min_cpu_cores": $((cpu_cores > 4 ? cpu_cores : 4)),
        "bottleneck": "$([ "$cpu_usage_pct" -gt 80 ] && echo "memory" || echo "none")"
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    cat > "$usage_metrics" <<STATUSEOF
Resource Analytics Metrics
==========================
Domain: $domain
CPU Cores: $cpu_cores
Memory: ${mem_used_mb}/${mem_total_mb}MB (${cpu_usage_pct}%)
Disk: ${disk_used_gb}/${disk_total_gb}GB
Load Average: $load_1 / $load_5 / $load_15
Scan Duration: ${scan_duration_s}s
Phase Directories: $phase_dirs
Total Findings: $total_findings
Total Assets: $total_assets
Total Endpoints: $total_endpoints
Findings/sec: $(awk "BEGIN {printf \"%.4f\", ($total_findings / ($scan_duration_s > 0 ? $scan_duration_s : 1))}" 2>/dev/null || echo 0)
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
    count=$((count + 1))

    write_finding "{\"type\":\"resource_analytics\",\"domain\":\"$domain\",\"findings\":$total_findings,\"phases\":$phase_dirs,\"duration\":$scan_duration_s,\"memory_pct\":$cpu_usage_pct}" "$phase_dir/finding_analytics.json" 2>/dev/null || true

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Resource analytics phase complete: $count results"
    py_log "INFO" "resource_analytics_phase_complete" --phase "resource_analytics" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}

export -f resource_analytics_phase
