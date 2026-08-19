#!/bin/bash
# Track 7 - Distributed Scale: Scan cost estimation phase
# Resource usage tracking, budget alerts, cost optimization

cost_estimation_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/cost_estimation"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting cost estimation phase for $domain"
    py_log "INFO" "cost_estimation_phase_start" --phase "cost_estimation" --target "$domain" 2>/dev/null || true

    local cost_estimate="$phase_dir/cost_estimate.json"
    local budget_status="$phase_dir/budget_status.txt"
    local count=0

    # Collect resource usage metrics
    local cpu_hours=0
    local mem_gb_hours=0
    local disk_gb=0
    local network_gb=0
    local api_calls=0

    # Estimate CPU usage
    local uptime_seconds=0
    if [ -f /proc/uptime ]; then
        uptime_seconds=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
    fi
    local cpu_cores=1
    if command -v nproc >/dev/null 2>&1; then
        cpu_cores=$(nproc 2>/dev/null || echo 1)
    fi
    cpu_hours=$(awk "BEGIN {printf \"%.2f\", ($uptime_seconds / 3600) * $cpu_cores}" 2>/dev/null || echo "0.01")

    # Estimate memory usage
    if command -v free >/dev/null 2>&1; then
        local mem_used_mb
        mem_used_mb=$(free -m 2>/dev/null | awk '/Mem:/ {print $3}' || echo 100)
        mem_gb_hours=$(awk "BEGIN {printf \"%.2f\", ($mem_used_mb / 1024) * ($uptime_seconds / 3600)}" 2>/dev/null || echo "0.10")
    fi

    # Estimate disk usage
    if command -v du >/dev/null 2>&1; then
        disk_gb=$(du -sm "$output_dir" 2>/dev/null | awk '{printf "%.2f", $1/1024}' || echo "0.01")
    fi

    # Count API calls (approximate from log files)
    if [ -d "$LOGS_DIR" ]; then
        api_calls=$(find "$LOGS_DIR" -name "*.log" -exec grep -c "HTTP" {} \; 2>/dev/null | awk '{s+=$1} END {print s+0}' || echo 0)
    fi

    # Cloud cost estimation (per-hour rates)
    local cpu_cost_per_hour="${CPU_COST_PER_HOUR:-0.042}"
    local mem_cost_per_gb_hour="${MEM_COST_PER_GB_HOUR:-0.005}"
    local disk_cost_per_gb_month="${DISK_COST_PER_GB_MONTH:-0.10}"
    local network_cost_per_gb="${NETWORK_COST_PER_GB:-0.09}"
    local api_cost_per_1000="${API_COST_PER_1000:-0.004}"

    local cpu_cost
    cpu_cost=$(awk "BEGIN {printf \"%.4f\", $cpu_hours * $cpu_cost_per_hour}" 2>/dev/null || echo "0.0001")
    local mem_cost
    mem_cost=$(awk "BEGIN {printf \"%.4f\", $mem_gb_hours * $mem_cost_per_gb_hour}" 2>/dev/null || echo "0.0001")
    local disk_cost
    disk_cost=$(awk "BEGIN {printf \"%.4f\", $disk_gb * $disk_cost_per_gb_month / 720}" 2>/dev/null || echo "0.0001")
    local network_cost
    network_cost=$(awk "BEGIN {printf \"%.4f\", $network_gb * $network_cost_per_gb}" 2>/dev/null || echo "0.0000")
    local api_cost
    api_cost=$(awk "BEGIN {printf \"%.4f\", ($api_calls / 1000) * $api_cost_per_1000}" 2>/dev/null || echo "0.0000")

    local total_cost
    total_cost=$(awk "BEGIN {printf \"%.4f\", $cpu_cost + $mem_cost + $disk_cost + $network_cost + $api_cost}" 2>/dev/null || echo "0.0003")

    cat > "$cost_estimate" <<JSONEOF
{
    "domain": "$domain",
    "resource_usage": {
        "cpu_hours": $cpu_hours,
        "cpu_cores": $cpu_cores,
        "mem_gb_hours": $mem_gb_hours,
        "disk_gb": $disk_gb,
        "network_gb": $network_gb,
        "api_calls": $api_calls
    },
    "cost_breakdown": {
        "cpu_cost": $cpu_cost,
        "memory_cost": $mem_cost,
        "disk_cost": $disk_cost,
        "network_cost": $network_cost,
        "api_cost": $api_cost,
        "total_estimated_cost": $total_cost,
        "currency": "USD"
    },
    "pricing_rates": {
        "cpu_per_hour": $cpu_cost_per_hour,
        "mem_per_gb_hour": $mem_cost_per_gb_hour,
        "disk_per_gb_month": $disk_cost_per_gb_month,
        "network_per_gb": $network_cost_per_gb,
        "api_per_1000": $api_cost_per_1000
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    # Budget check
    local budget_limit="${BUDGET_LIMIT:-10.00}"
    local budget_pct
    budget_pct=$(awk "BEGIN {printf \"%.1f\", ($total_cost / $budget_limit) * 100}" 2>/dev/null || echo "0.0")
    local budget_status_text="within_budget"
    if [ "$(awk "BEGIN {print ($total_cost >= $budget_limit) ? 1 : 0}")" = "1" ]; then
        budget_status_text="over_budget"
        log "WARN" "Scan cost (\$$total_cost) exceeds budget (\$$budget_limit)"
    fi

    cat > "$budget_status" <<STATUSEOF
Budget Status
=============
Domain: $domain
Budget Limit: \$$budget_limit
Estimated Cost: \$$total_cost
Budget Used: ${budget_pct}%
Status: $budget_status_text
CPU Cost: \$$cpu_cost
Memory Cost: \$$mem_cost
Disk Cost: \$$disk_cost
Network Cost: \$$network_cost
API Cost: \$$api_cost
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
    count=$((count + 1))

    write_finding "{\"type\":\"cost_estimation\",\"domain\":\"$domain\",\"total_cost\":$total_cost,\"budget_pct\":$budget_pct,\"status\":\"$budget_status_text\"}" "$phase_dir/finding_cost.json" 2>/dev/null || true

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Cost estimation phase complete: $count results (total: \$$total_cost)"
    py_log "INFO" "cost_estimation_phase_complete" --phase "cost_estimation" --target "$domain" --extra "{\"count\":$count,\"total_cost\":$total_cost}" 2>/dev/null || true
}

export -f cost_estimation_phase
