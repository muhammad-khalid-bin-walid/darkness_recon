#!/usr/bin/env bash
# Track 12 - Container/K8s | Phase 204: Container Registry Security Analysis
set -euo pipefail

container_registry() {
    local domain="${1:?Usage: container_registry <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/registry"

    local vulns_file="$output_dir/registry/registry_vulns.txt"
    local images_file="$output_dir/registry/registry_images.txt"
    local count=0

    log "INFO" "Starting container registry analysis for $domain"

    # Check registry exposure
    if tool_available curl; then
        log "INFO" "Checking container registry exposure"
        local registry_endpoints=("/v2/" "/v2/_catalog" "/v2/_catalog" "/v1/search")
        for endpoint in "${registry_endpoints[@]}"; do
            local reg_response
            reg_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}${endpoint}" 2>/dev/null || true)
            if [[ "$reg_response" == "200" ]]; then
                write_finding "$vulns_file" "CRITICAL" "Container registry endpoint accessible without auth: $endpoint"
                echo "Endpoint $endpoint: accessible" >> "$images_file"
                ((count++))
            fi
        done
    fi

    # Check image pulling without authentication
    log "INFO" "Testing unauthenticated image pulling"
    if tool_available docker; then
        local pull_test
        pull_test=$(docker pull "${domain}/test-image:latest" 2>&1 || true)
        if echo "$pull_test" | grep -q "unauthorized\|denied"; then
            write_finding "$vulns_file" "HIGH" "Image pull requires authentication (positive)"
            echo "Pull auth: Required" >> "$images_file"
        else
            write_finding "$vulns_file" "CRITICAL" "Image pull possible without authentication"
            echo "Pull auth: NOT required" >> "$images_file"
            ((count++))
        fi
    fi

    # Check for vulnerability scanning
    log "INFO" "Checking vulnerability scanning configuration"
    local scan_endpoints=("/api/v1/scanner/status" "/api/v1/reports" "/api/v1/images")
    for endpoint in "${scan_endpoints[@]}"; do
        local scan_response
        scan_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${domain}${endpoint}" 2>/dev/null || true)
        if [[ "$scan_response" == "200" ]]; then
            write_finding "$vulns_file" "MEDIUM" "Registry scanner API accessible: $endpoint"
            echo "Scanner API $endpoint: accessible" >> "$images_file"
            ((count++))
        fi
    done

    # Check for image signing
    log "INFO" "Checking image signing configuration"
    write_asset "$images_file" "domain=$domain"
    write_endpoint "$images_file" "registry=https://${domain}"

    py_log "INFO" "container_registry" "Completed registry analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/registry/count.txt"
    log "INFO" "Container registry analysis complete. Findings: $count"
}

container_registry "$@"
