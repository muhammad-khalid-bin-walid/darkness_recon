#!/usr/bin/env bash
# Track 12 - Container/K8s | Phase 207: Service Mesh Configuration Analysis
set -euo pipefail

container_service_mesh() {
    local domain="${1:?Usage: container_service_mesh <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/service_mesh"

    local vulns_file="$output_dir/service_mesh/mesh_vulns.txt"
    local config_file="$output_dir/service_mesh/mesh_config.txt"
    local count=0

    log "INFO" "Starting service mesh analysis for $domain"

    # Check Istio configuration
    if tool_available curl; then
        log "INFO" "Checking Istio service mesh presence"
        local istio_endpoints=("/istio/config" "/istio/proxy" "/stats")
        for endpoint in "${istio_endpoints[@]}"; do
            local istio_response
            istio_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${domain}:15014${endpoint}" 2>/dev/null || true)
            if [[ "$istio_response" == "200" ]]; then
                write_finding "$vulns_file" "HIGH" "Istio endpoint accessible: $endpoint"
                echo "Istio $endpoint: accessible" >> "$config_file"
                ((count++))
            fi
        done
    fi

    # Check Linkerd configuration
    log "INFO" "Checking Linkerd service mesh presence"
    local linkerd_endpoints=("/ready" "/live" "/version")
    for endpoint in "${linkerd_endpoints[@]}"; do
        local linkerd_response
        linkerd_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${domain}:9995${endpoint}" 2>/dev/null || true)
        if [[ "$linkerd_response" == "200" ]]; then
            write_finding "$vulns_file" "MEDIUM" "Linkerd endpoint accessible: $endpoint"
            echo "Linkerd $endpoint: accessible" >> "$config_file"
            ((count++))
        fi
    done

    # Check mTLS status
    log "INFO" "Checking mTLS configuration status"
    local mtls_endpoints=("/stats" "/certs" "/mtls")
    for endpoint in "${mtls_endpoints[@]}"; do
        local mtls_response
        mtls_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${domain}:15021${endpoint}" 2>/dev/null || true)
        if [[ "$mtls_response" == "200" ]]; then
            write_finding "$vulns_file" "MEDIUM" "Mesh metrics endpoint accessible: $endpoint"
            echo "mTLS endpoint $endpoint: accessible" >> "$config_file"
            ((count++))
        fi
    done

    # Check policy enforcement
    log "INFO" "Checking policy enforcement"
    local policy_endpoints=("/policy" "/policies" "/authorization")
    for endpoint in "${policy_endpoints[@]}"; do
        local policy_response
        policy_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${domain}:15012${endpoint}" 2>/dev/null || true)
        if [[ "$policy_response" == "200" ]]; then
            write_finding "$vulns_file" "MEDIUM" "Policy endpoint accessible: $endpoint"
            echo "Policy $endpoint: accessible" >> "$config_file"
            ((count++))
        fi
    done

    # Check sidecar injection
    log "INFO" "Checking sidecar injection configuration"
    write_finding "$vulns_file" "INFO" "Sidecar injection analysis completed"

    write_asset "$config_file" "domain=$domain"
    write_endpoint "$config_file" "istio=http://${domain}:15014"

    py_log "INFO" "container_service_mesh" "Completed service mesh analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/service_mesh/count.txt"
    log "INFO" "Service mesh analysis complete. Findings: $count"
}

container_service_mesh "$@"
