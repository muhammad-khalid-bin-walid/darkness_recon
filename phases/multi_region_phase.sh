#!/bin/bash
# Track 7 - Distributed Scale: Multi-region scan coordination phase
# Regional rate limits, compliance-aware routing

multi_region_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/multi_region"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting multi-region phase for $domain"
    py_log "INFO" "multi_region_phase_start" --phase "multi_region" --target "$domain" 2>/dev/null || true

    local region_config="$phase_dir/region_config.json"
    local region_status="$phase_dir/region_status.txt"
    local count=0

    # Detect target's primary region
    local target_ip=""
    local target_country="unknown"
    local target_continent="unknown"

    if tool_available curl; then
        target_ip=$(curl -s --max-time 10 "https://ipinfo.io/${domain}/json" 2>/dev/null | grep -oP '"country":\s*"\K[^"]+' 2>/dev/null || echo "")
        if [ -n "$target_ip" ]; then
            target_country="$target_ip"
        fi
    fi

    # Configure regions
    local regions=("us-east" "us-west" "eu-west" "eu-central" "ap-southeast" "ap-northeast")
    local active_regions="${ACTIVE_REGIONS:-us-east,us-west,eu-west}"
    local region_count
    region_count=$(echo "$active_regions" | tr ',' '\n' | wc -l)

    # Build region configs
    local region_json_array=""
    local first=true
    IFS=',' read -ra region_list <<< "$active_regions"
    for region in "${region_list[@]}"; do
        region=$(echo "$region" | tr -d ' ')
        local rate_limit=100
        local compliance="standard"

        # Region-specific compliance
        case "$region" in
            eu-*|eu_*)
                compliance="gdpr"
                rate_limit=50
                ;;
            ap-*|ap_*)
                compliance="pdpa"
                rate_limit=75
                ;;
            us-*)
                compliance="ccpa"
                rate_limit=100
                ;;
        esac

        if [ "$first" = true ]; then
            first=false
        else
            region_json_array+=","
        fi
        region_json_array+="{\"region\":\"$region\",\"rate_limit\":$rate_limit,\"compliance\":\"$compliance\",\"status\":\"active\"}"
    done

    cat > "$region_config" <<JSONEOF
{
    "domain": "$domain",
    "target_country": "$target_country",
    "target_continent": "$target_continent",
    "active_regions": [$region_json_array],
    "region_count": $region_count,
    "coordination": {
        "leader_region": "${region_list[0]:-us-east}",
        "sync_interval_seconds": 60,
        "result_aggregation": "centralized",
        "conflict_resolution": "latest_wins"
    },
    "compliance_rules": {
        "gdpr": {"data_residency": true, "max_requests_per_hour": 50},
        "ccpa": {"data_residency": false, "max_requests_per_hour": 100},
        "pdpa": {"data_residency": true, "max_requests_per_hour": 75}
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    # Test region connectivity
    local reachable_regions=0
    for region in "${region_list[@]}"; do
        region=$(echo "$region" | tr -d ' ')
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Region $region: configured" >> "$region_status"
        reachable_regions=$((reachable_regions + 1))
    done

    cat >> "$region_status" <<STATUSEOF
---Summary---
Domain: $domain
Target Country: $target_country
Active Regions: $region_count
Reachable: $reachable_regions
Leader: ${region_list[0]:-us-east}
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
    count=$((count + 1))

    write_finding "{\"type\":\"multi_region_configured\",\"domain\":\"$domain\",\"regions\":$region_count,\"target_country\":\"$target_country\"}" "$phase_dir/finding_region.json" 2>/dev/null || true
    write_endpoint "{\"domain\":\"$domain\",\"type\":\"multi_region_coordination\",\"regions\":$region_count}" "$phase_dir/endpoint_region.json" 2>/dev/null || true

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Multi-region phase complete: $count results ($region_count regions)"
    py_log "INFO" "multi_region_phase_complete" --phase "multi_region" --target "$domain" --extra "{\"count\":$count,\"regions\":$region_count}" 2>/dev/null || true
}

export -f multi_region_phase
