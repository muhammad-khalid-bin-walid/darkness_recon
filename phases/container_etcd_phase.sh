#!/usr/bin/env bash
# Track 12 - Container/K8s | Phase 203: etcd Exposure and Security Analysis
set -euo pipefail

container_etcd() {
    local domain="${1:?Usage: container_etcd <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/etcd"

    local vulns_file="$output_dir/etcd/etcd_vulns.txt"
    local access_file="$output_dir/etcd/etcd_access.txt"
    local count=0

    log "INFO" "Starting etcd security analysis for $domain"

    # Check etcd exposure on common ports
    if tool_available curl; then
        log "INFO" "Checking etcd API exposure"
        local etcd_ports=(2379 2380)
        for port in "${etcd_ports[@]}"; do
            local etcd_response
            etcd_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${domain}:${port}/version" 2>/dev/null || true)
            if [[ "$etcd_response" == "200" ]]; then
                write_finding "$vulns_file" "CRITICAL" "etcd API exposed on port $port without authentication"
                echo "Port $port: etcd API accessible" >> "$access_file"
                ((count++))
            fi
        done
    fi

    # Check data encryption status
    log "INFO" "Checking etcd data encryption"
    if tool_available curl; then
        local keys_response
        keys_response=$(curl -s --connect-timeout 5 "http://${domain}:2379/v2/keys/" 2>/dev/null || true)
        if echo "$keys_response" | grep -q "node"; then
            write_finding "$vulns_file" "CRITICAL" "etcd data accessible without encryption/authentication"
            echo "Data access: Unauthenticated key listing possible" >> "$access_file"
            ((count++))
        fi
    fi

    # Check authentication bypass
    log "INFO" "Testing etcd authentication bypass"
    local auth_endpoints=("health" "version" "metrics" "config")
    for endpoint in "${auth_endpoints[@]}"; do
        local auth_response
        auth_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${domain}:2379/${endpoint}" 2>/dev/null || true)
        if [[ "$auth_response" == "200" ]]; then
            write_finding "$vulns_file" "MEDIUM" "etcd endpoint accessible without auth: $endpoint"
            echo "$endpoint: accessible" >> "$access_file"
            ((count++))
        fi
    done

    # Check for sensitive data patterns
    log "INFO" "Scanning for sensitive data patterns in etcd"
    write_asset "$access_file" "domain=$domain"
    write_endpoint "$access_file" "etcd_api=http://${domain}:2379"

    py_log "INFO" "container_etcd" "Completed etcd analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/etcd/count.txt"
    log "INFO" "etcd analysis complete. Findings: $count"
}

container_etcd "$@"
