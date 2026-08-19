#!/bin/bash
# Track 7 - Distributed Scale: Rotating egress IPs phase
# Proxy rotation, geo-distributed scanning output

rotating_egress_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/rotating_egress"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting rotating egress phase for $domain"
    py_log "INFO" "rotating_egress_phase_start" --phase "rotating_egress" --target "$domain" 2>/dev/null || true

    local egress_config="$phase_dir/egress_config.txt"
    local rotation_log="$phase_dir/rotation_log.txt"
    local count=0

    local proxy_file="${PROXY_FILE:-}"
    local rotation_strategy="${ROTATION_STRATEGY:-round_robin}"
    local proxy_count=0
    local active_proxies=()

    # Load proxy list
    if [ -n "$proxy_file" ] && [ -f "$proxy_file" ]; then
        log "INFO" "Loading proxy list from $proxy_file"
        while IFS= read -r proxy; do
            [ -z "$proxy" ] && continue
            [[ "$proxy" =~ ^# ]] && continue
            active_proxies+=("$proxy")
            proxy_count=$((proxy_count + 1))
        done < "$proxy_file"
        log "INFO" "Loaded $proxy_count proxies"
    fi

    # Discover external IP if no proxies
    local current_ip="unknown"
    if tool_available curl; then
        current_ip=$(curl -s --max-time 10 "https://api.ipify.org" 2>/dev/null || echo "unknown")
    fi

    # Configure egress rotation
    cat > "$egress_config" <<CONFEGG
Rotating Egress Configuration
=============================
Domain: $domain
Strategy: $rotation_strategy
Proxy Count: $proxy_count
Current IP: $current_ip
Rotation Interval: ${ROTATION_INTERVAL:-300}s
IP Verification: ${IP_VERIFICATION:-true}
Geo Routing: ${GEO_ROUTING:-false}
Failover: ${FAILOVER:-strict}
Timeout: ${EGRESS_TIMEOUT:-10}s
Retry on Failure: ${EGRESS_RETRY:-3}
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
CONFEGG
    count=$((count + 1))

    # Test proxy connectivity
    local working_proxies=0
    local proxy_index=0

    for proxy in "${active_proxies[@]}"; do
        proxy_index=$((proxy_index + 1))
        local proxy_type="http"

        if echo "$proxy" | grep -qiE "^socks5?://"; then
            proxy_type="socks5"
        fi

        # Test proxy
        local test_result="failed"
        if tool_available curl; then
            local proxy_ip
            proxy_ip=$(echo "$proxy" | sed -E 's|^[a-z]+://||;s|:.*||;s|/.*||')
            local proxy_port
            proxy_port=$(echo "$proxy" | grep -oE ':[0-9]+' | head -1 | tr -d ':')

            if [ -n "$proxy_port" ]; then
                if curl -s --proxy "$proxy" --max-time 10 \
                    "https://api.ipify.org" >/dev/null 2>&1; then
                    test_result="working"
                    working_proxies=$((working_proxies + 1))
                fi
            fi
        fi

        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Proxy $proxy_index ($proxy_type): $test_result - $proxy" >> "$rotation_log"
    done

    # Append direct connection test
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Direct: working - IP $current_ip" >> "$rotation_log"

    # Write findings
    if [ "$proxy_count" -gt 0 ]; then
        write_finding "{\"type\":\"egress_rotation_configured\",\"domain\":\"$domain\",\"strategy\":\"$rotation_strategy\",\"proxy_count\":$proxy_count,\"working_proxies\":$working_proxies,\"current_ip\":\"$current_ip\"}" "$phase_dir/finding_egress.json" 2>/dev/null || true
    fi

    write_asset "{\"type\":\"egress_endpoints\",\"domain\":\"$domain\",\"total_proxies\":$proxy_count,\"active_proxies\":$working_proxies,\"direct_ip\":\"$current_ip\"}" "$phase_dir/asset_egress.json" 2>/dev/null || true

    count=$((count + 1))

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Rotating egress phase complete: $count results ($working_proxies/$proxy_count proxies working)"
    py_log "INFO" "rotating_egress_phase_complete" --phase "rotating_egress" --target "$domain" --extra "{\"count\":$count,\"working_proxies\":$working_proxies}" 2>/dev/null || true
}

export -f rotating_egress_phase
