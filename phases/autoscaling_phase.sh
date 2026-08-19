#!/bin/bash
# Track 7 - Distributed Scale: Worker autoscaling phase
# Queue depth monitoring, resource-based scaling, scale-up/down policies

autoscaling_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/autoscaling"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting autoscaling phase for $domain"
    py_log "INFO" "autoscaling_phase_start" --phase "autoscaling" --target "$domain" 2>/dev/null || true

    local scaling_config="$phase_dir/scaling_config.json"
    local scaling_events="$phase_dir/scaling_events.txt"
    local count=0

    # Gather resource metrics
    local cpu_usage="0"
    local mem_usage="0"
    local disk_usage="0"
    local load_avg="0"

    if command -v free >/dev/null 2>&1; then
        local mem_total mem_used
        mem_total=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo 1)
        mem_used=$(free -m 2>/dev/null | awk '/Mem:/ {print $3}' || echo 0)
        if [ "$mem_total" -gt 0 ] 2>/dev/null; then
            mem_usage=$((mem_used * 100 / mem_total))
        fi
    fi

    if [ -f /proc/loadavg ] 2>/dev/null; then
        load_avg=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "0")
    elif command -v uptime >/dev/null 2>&1; then
        load_avg=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ' || echo "0")
    fi

    if command -v df >/dev/null 2>&1; then
        disk_usage=$(df -h / 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}' || echo "0")
    fi

    # Calculate scaling decision
    local min_workers="${SCALING_MIN_WORKERS:-2}"
    local max_workers="${SCALING_MAX_WORKERS:-16}"
    local current_workers="${CURRENT_WORKERS:-4}"
    local target_workers=$current_workers
    local scale_action="maintain"

    # Scale up conditions
    if [ "$cpu_usage" -gt 80 ] 2>/dev/null || [ "$mem_usage" -gt 85 ] 2>/dev/null; then
        target_workers=$((current_workers + 2))
        scale_action="scale_up"
    elif [ "$(echo "$load_avg > $current_workers" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
        target_workers=$((current_workers + 1))
        scale_action="scale_up"
    fi

    # Scale down conditions
    if [ "$cpu_usage" -lt 20 ] 2>/dev/null && [ "$mem_usage" -lt 30 ] 2>/dev/null; then
        target_workers=$((current_workers - 1))
        scale_action="scale_down"
    fi

    # Clamp
    [ "$target_workers" -lt "$min_workers" ] && target_workers=$min_workers
    [ "$target_workers" -gt "$max_workers" ] && target_workers=$max_workers

    # Record scaling event
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Action: $scale_action | Current: $current_workers -> Target: $target_workers | CPU: ${cpu_usage}% | MEM: ${mem_usage}% | Load: $load_avg" >> "$scaling_events"

    cat > "$scaling_config" <<JSONEOF
{
    "domain": "$domain",
    "scaling_policy": {
        "min_workers": $min_workers,
        "max_workers": $max_workers,
        "scale_up_threshold_cpu": 80,
        "scale_up_threshold_mem": 85,
        "scale_down_threshold_cpu": 20,
        "scale_down_threshold_mem": 30,
        "cooldown_seconds": 300,
        "scale_up_step": 2,
        "scale_down_step": 1
    },
    "current_metrics": {
        "cpu_usage_percent": $cpu_usage,
        "memory_usage_percent": $mem_usage,
        "disk_usage_percent": $disk_usage,
        "load_average": $load_avg
    },
    "scaling_decision": {
        "current_workers": $current_workers,
        "target_workers": $target_workers,
        "action": "$scale_action"
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    write_finding "{\"type\":\"autoscaling_configured\",\"domain\":\"$domain\",\"action\":\"$scale_action\",\"current\":$current_workers,\"target\":$target_workers,\"cpu\":$cpu_usage,\"mem\":$mem_usage}" "$phase_dir/finding_scaling.json" 2>/dev/null || true

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Autoscaling phase complete: $count results (action: $scale_action, $current_workers -> $target_workers)"
    py_log "INFO" "autoscaling_phase_complete" --phase "autoscaling" --target "$domain" --extra "{\"count\":$count,\"action\":\"$scale_action\"}" 2>/dev/null || true
}

export -f autoscaling_phase
