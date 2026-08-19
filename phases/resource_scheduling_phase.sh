#!/bin/bash
# Track 7 - Distributed Scale: Resource-aware scheduling phase
# CPU/memory/disk constraints, priority-based allocation

resource_scheduling_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/resource_scheduling"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting resource scheduling phase for $domain"
    py_log "INFO" "resource_scheduling_phase_start" --phase "resource_scheduling" --target "$domain" 2>/dev/null || true

    local schedule_config="$phase_dir/schedule_config.json"
    local resource_usage="$phase_dir/resource_usage.txt"
    local count=0

    # Collect system resources
    local cpu_cores=1
    local mem_total_mb=0
    local mem_available_mb=0
    local disk_available_mb=0

    if command -v nproc >/dev/null 2>&1; then
        cpu_cores=$(nproc 2>/dev/null || echo 1)
    fi

    if command -v free >/dev/null 2>&1; then
        mem_total_mb=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo 0)
        mem_available_mb=$(free -m 2>/dev/null | awk '/Mem:/ {print $7}' || echo 0)
    fi

    if command -v df >/dev/null 2>&1; then
        disk_available_mb=$(df -m "$OUTPUT_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
    fi

    # Define scan priorities and resource budgets
    local high_priority_pct=50
    local medium_priority_pct=30
    local low_priority_pct=20

    local high_cpu=$((cpu_cores * high_priority_pct / 100))
    local med_cpu=$((cpu_cores * medium_priority_pct / 100))
    local low_cpu=$((cpu_cores * low_priority_pct / 100))

    [ "$high_cpu" -lt 1 ] && high_cpu=1
    [ "$med_cpu" -lt 1 ] && med_cpu=1
    [ "$low_cpu" -lt 1 ] && low_cpu=1

    local high_mem=$((mem_total_mb * high_priority_pct / 100))
    local med_mem=$((mem_total_mb * medium_priority_pct / 100))
    local low_mem=$((mem_total_mb * low_priority_pct / 100))

    cat > "$schedule_config" <<JSONEOF
{
    "domain": "$domain",
    "system_resources": {
        "cpu_cores": $cpu_cores,
        "memory_total_mb": $mem_total_mb,
        "memory_available_mb": $mem_available_mb,
        "disk_available_mb": $disk_available_mb
    },
    "priority_allocation": {
        "high": {
            "cpu_cores": $high_cpu,
            "memory_mb": $high_mem,
            "disk_mb": $((disk_available_mb * high_priority_pct / 100)),
            "phases": ["subdomain", "live_detection", "port_scan"]
        },
        "medium": {
            "cpu_cores": $med_cpu,
            "memory_mb": $med_mem,
            "disk_mb": $((disk_available_mb * medium_priority_pct / 100)),
            "phases": ["web_analysis", "technology_detection", "ssl_analysis"]
        },
        "low": {
            "cpu_cores": $low_cpu,
            "memory_mb": $low_mem,
            "disk_mb": $((disk_available_mb * low_priority_pct / 100)),
            "phases": ["osint", "historical", "reporting"]
        }
    },
    "scheduling_policy": {
        "preemption_enabled": true,
        "fair_share": false,
        "max_concurrent_high": 4,
        "max_concurrent_medium": 8,
        "max_concurrent_low": 16,
        "resource_reclaim_timeout_seconds": 300
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    cat > "$resource_usage" <<STATUSEOF
Resource Scheduling Status
==========================
Domain: $domain
CPU Cores: $cpu_cores
Memory Total: ${mem_total_mb}MB
Memory Available: ${mem_available_mb}MB
Disk Available: ${disk_available_mb}MB
High Priority Budget: ${high_cpu} cores, ${high_mem}MB
Medium Priority Budget: ${med_cpu} cores, ${med_mem}MB
Low Priority Budget: ${low_cpu} cores, ${low_mem}MB
Scheduling Policy: Priority-based with preemption
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
    count=$((count + 1))

    write_finding "{\"type\":\"resource_scheduling_configured\",\"domain\":\"$domain\",\"cpu_cores\":$cpu_cores,\"memory_mb\":$mem_total_mb,\"disk_mb\":$disk_available_mb}" "$phase_dir/finding_schedule.json" 2>/dev/null || true

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Resource scheduling phase complete: $count results"
    py_log "INFO" "resource_scheduling_phase_complete" --phase "resource_scheduling" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}

export -f resource_scheduling_phase
