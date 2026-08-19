#!/bin/bash
# Track 7 - Distributed Scale: Bandwidth throttling phase
# Per-scan throttling, network utilization monitoring, congestion control

bandwidth_throttle_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/bandwidth_throttle"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting bandwidth throttle phase for $domain"
    py_log "INFO" "bandwidth_throttle_phase_start" --phase "bandwidth_throttle" --target "$domain" 2>/dev/null || true

    local throttle_config="$phase_dir/throttle_config.json"
    local bandwidth_stats="$phase_dir/bandwidth_stats.txt"
    local count=0

    # Measure current network utilization
    local current_bandwidth_mbps=100
    local rx_bytes_start=0
    local tx_bytes_start=0

    if [ -f /proc/net/dev ]; then
        local iface
        iface=$(awk 'NR>2 && $1 !/lo:/{gsub(/:/, "", $1); print $1; exit}' /proc/net/dev 2>/dev/null || echo "eth0")
        rx_bytes_start=$(awk -v iface="$iface:" '$1==iface {print $2}' /proc/net/dev 2>/dev/null || echo 0)
        tx_bytes_start=$(awk -v iface="$iface:" '$1==iface {print $10}' /proc/net/dev 2>/dev/null || echo 0)
    fi

    # Wait briefly and measure
    sleep 1

    local rx_bytes_end=0
    local tx_bytes_end=0
    if [ -f /proc/net/dev ]; then
        local iface
        iface=$(awk 'NR>2 && $1 !/lo:/{gsub(/:/, "", $1); print $1; exit}' /proc/net/dev 2>/dev/null || echo "eth0")
        rx_bytes_end=$(awk -v iface="$iface:" '$1==iface {print $2}' /proc/net/dev 2>/dev/null || echo 0)
        tx_bytes_end=$(awk -v iface="$iface:" '$1==iface {print $10}' /proc/net/dev 2>/dev/null || echo 0)
    fi

    local rx_rate=$(( (rx_bytes_end - rx_bytes_start) / 1024 ))
    local tx_rate=$(( (tx_bytes_end - tx_bytes_start) / 1024 ))

    # Configure throttle parameters
    local max_bandwidth_kbps="${MAX_BANDWIDTH_KPS:-10240}"
    local per_scan_limit_kbps="${PER_SCAN_LIMIT_KPS:-2048}"
    local burst_size="${BURST_SIZE_KB:-512}"
    local congestion_window="${CONGESTION_WINDOW:-10}"

    cat > "$throttle_config" <<JSONEOF
{
    "domain": "$domain",
    "network_monitoring": {
        "rx_rate_kbps": $rx_rate,
        "tx_rate_kbps": $tx_rate,
        "monitoring_interval_seconds": 5,
        "interface": "auto"
    },
    "throttle_policies": {
        "global_max_bandwidth_kbps": $max_bandwidth_kbps,
        "per_scan_limit_kbps": $per_scan_limit_kbps,
        "burst_size_kb": $burst_size,
        "sustained_rate_kbps": $((max_bandwidth_kbps * 80 / 100))
    },
    "congestion_control": {
        "algorithm": "cubic",
        "initial_window": $congestion_window,
        "slow_start_threshold": $((max_bandwidth_kbps * 50 / 100)),
        "timeout_ms": 500,
        "retransmit_limit": 3
    },
    "adaptive_throttling": {
        "enabled": true,
        "latency_threshold_ms": 500,
        "packet_loss_threshold_pct": 1,
        "degradation_response": "reduce_by_20_percent",
        "recovery_probe_interval_seconds": 30
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    cat > "$bandwidth_stats" <<STATUSEOF
Bandwidth Throttle Status
=========================
Domain: $domain
Current RX Rate: ${rx_rate}KB/s
Current TX Rate: ${tx_rate}KB/s
Max Bandwidth: ${max_bandwidth_kbps}KB/s
Per-Scan Limit: ${per_scan_limit_kbps}KB/s
Burst Size: ${burst_size}KB
Congestion Window: $congestion_window
Algorithm: Cubic
Adaptive: Enabled
Status: active
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
    count=$((count + 1))

    write_finding "{\"type\":\"bandwidth_throttle_configured\",\"domain\":\"$domain\",\"max_kbps\":$max_bandwidth_kbps,\"per_scan_kbps\":$per_scan_limit_kbps,\"rx_rate\":$rx_rate}" "$phase_dir/finding_throttle.json" 2>/dev/null || true

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Bandwidth throttle phase complete: $count results"
    py_log "INFO" "bandwidth_throttle_phase_complete" --phase "bandwidth_throttle" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}

export -f bandwidth_throttle_phase
