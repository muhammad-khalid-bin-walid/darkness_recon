#!/bin/bash
# Track 7 - Distributed Scale: Adaptive rate-limiting phase
# Dynamic adjustment based on target response, backoff strategies

adaptive_ratelimit_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/adaptive_ratelimit"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting adaptive rate-limit phase for $domain"
    py_log "INFO" "adaptive_ratelimit_phase_start" --phase "adaptive_ratelimit" --target "$domain" 2>/dev/null || true

    local ratelimit_config="$phase_dir/ratelimit_config.json"
    local adaptive_params="$phase_dir/adaptive_params.txt"
    local count=0

    # Probe target for baseline response
    local baseline_rtt=0
    local baseline_status=0
    local waf_detected=false

    if tool_available curl; then
        local probe_start
        probe_start=$(date +%s%N 2>/dev/null || date +%s)

        baseline_status=$(curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 10 --max-time 30 \
            "https://$domain" 2>/dev/null || echo "000")

        local probe_end
        probe_end=$(date +%s%N 2>/dev/null || date +%s)

        if [ "$probe_start" -gt 1000000000 ] 2>/dev/null; then
            baseline_rtt=$(( (probe_end - probe_start) / 1000000 ))
        else
            baseline_rtt=$(( (probe_end - probe_start) * 1000 ))
        fi

        log "INFO" "Baseline probe: HTTP $baseline_status, RTT ${baseline_rtt}ms"

        # Detect WAF presence
        local waf_headers
        waf_headers=$(curl -sI "https://$domain" 2>/dev/null || echo "")
        if echo "$waf_headers" | grep -qiE "cloudflare|akamai|incapsula|sucuri|awswaf|f5"; then
            waf_detected=true
            log "INFO" "WAF detected on target"
        fi
    fi

    # Calculate adaptive parameters
    local base_rate=100
    local min_rate=10
    local max_rate=500
    local adaptive_rate=$base_rate

    # Adjust based on response time
    if [ "$baseline_rtt" -gt 2000 ]; then
        adaptive_rate=$((base_rate / 4))
    elif [ "$baseline_rtt" -gt 1000 ]; then
        adaptive_rate=$((base_rate / 2))
    elif [ "$baseline_rtt" -lt 200 ]; then
        adaptive_rate=$((base_rate * 2))
    fi

    # Clamp to bounds
    [ "$adaptive_rate" -lt "$min_rate" ] && adaptive_rate=$min_rate
    [ "$adaptive_rate" -gt "$max_rate" ] && adaptive_rate=$max_rate

    # WAF penalty
    if [ "$waf_detected" = true ]; then
        adaptive_rate=$((adaptive_rate / 3))
        [ "$adaptive_rate" -lt "$min_rate" ] && adaptive_rate=$min_rate
    fi

    # Calculate backoff parameters
    local initial_backoff=1
    local max_backoff=300
    local backoff_multiplier=2
    local jitter_percent=25

    cat > "$ratelimit_config" <<JSONEOF
{
    "domain": "$domain",
    "baseline_rtt_ms": $baseline_rtt,
    "baseline_http_status": $baseline_status,
    "waf_detected": $waf_detected,
    "adaptive_rate_rps": $adaptive_rate,
    "rate_bounds": {"min": $min_rate, "max": $max_rate},
    "backoff_strategy": {
        "initial_seconds": $initial_backoff,
        "max_seconds": $max_backoff,
        "multiplier": $backoff_multiplier,
        "jitter_percent": $jitter_percent,
        "strategy": "exponential_with_jitter"
    },
    "429_handling": {
        "retry_after_header": true,
        "cooldown_seconds": 60,
        "rate_reduction_percent": 50,
        "recovery_rate_percent": 10
    },
    "5xx_handling": {
        "threshold": 5,
        "window_seconds": 60,
        "action": "pause_and_backoff"
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    write_finding "{\"type\":\"adaptive_ratelimit_configured\",\"domain\":\"$domain\",\"adaptive_rate\":$adaptive_rate,\"waf_detected\":$waf_detected,\"baseline_rtt\":$baseline_rtt}" "$phase_dir/finding_ratelimit.json" 2>/dev/null || true

    cat > "$adaptive_params" <<PARAMSEOF
Adaptive Rate Parameters
========================
Domain: $domain
Baseline RTT: ${baseline_rtt}ms
Baseline HTTP Status: $baseline_status
WAF Detected: $waf_detected
Adaptive Rate: ${adaptive_rate} requests/sec
Rate Range: ${min_rate}-${max_rate} rps
Backoff: Exponential with ${jitter_percent}% jitter
Initial Backoff: ${initial_backoff}s
Max Backoff: ${max_backoff}s
Backoff Multiplier: ${backoff_multiplier}x
429 Response: Reduce by 50%, cooldown 60s
5xx Threshold: 5 errors per 60s window
Recovery: +10% rate per successful interval
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
PARAMSEOF
    count=$((count + 1))

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Adaptive rate-limit phase complete: $count results"
    py_log "INFO" "adaptive_ratelimit_phase_complete" --phase "adaptive_ratelimit" --target "$domain" --extra "{\"count\":$count,\"adaptive_rate\":$adaptive_rate}" 2>/dev/null || true
}

export -f adaptive_ratelimit_phase
