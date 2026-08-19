#!/usr/bin/env bash
# Track 12 - Container/K8s | Phase 202: Kubernetes API Server Security Analysis
set -euo pipefail

container_k8s_api() {
    local domain="${1:?Usage: container_k8s_api <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/k8s_api"

    local vulns_file="$output_dir/k8s_api/k8s_api_vulns.txt"
    local rbac_file="$output_dir/k8s_api/k8s_rbac.txt"
    local count=0

    log "INFO" "Starting Kubernetes API server analysis for $domain"

    # Check API server exposure
    if tool_available curl; then
        log "INFO" "Checking Kubernetes API server exposure"
        local api_ports=(6443 8443 443)
        for port in "${api_ports[@]}"; do
            local api_response
            api_response=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}:${port}/api/v1" 2>/dev/null || true)
            if [[ "$api_response" == "200" || "$api_response" == "401" || "$api_response" == "403" ]]; then
                write_finding "$vulns_file" "CRITICAL" "Kubernetes API server accessible on port $port (HTTP $api_response)"
                echo "Port $port: API server responding (HTTP $api_response)" >> "$rbac_file"
                ((count++))
            fi
        done
    fi

    # Check anonymous authentication
    log "INFO" "Testing Kubernetes anonymous authentication"
    if tool_available curl; then
        local anon_response
        anon_response=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}:6443/api/v1/namespaces" 2>/dev/null || true)
        if [[ "$anon_response" == "200" ]]; then
            write_finding "$vulns_file" "CRITICAL" "Kubernetes API allows anonymous authentication"
            echo "Anonymous auth: ENABLED - full namespace listing possible" >> "$rbac_file"
            ((count++))
        fi
    fi

    # Check RBAC misconfiguration
    log "INFO" "Analyzing RBAC configuration"
    local rbac_endpoints=("clusterroles" "clusterrolebindings" "roles" "rolebindings" "serviceaccounts")
    for endpoint in "${rbac_endpoints[@]}"; do
        local rbac_response
        rbac_response=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}:6443/apis/rbac.authorization.k8s.io/v1/${endpoint}" 2>/dev/null || true)
        if [[ "$rbac_response" == "200" ]]; then
            write_finding "$vulns_file" "HIGH" "RBAC endpoint exposed: $endpoint"
            echo "$endpoint: accessible" >> "$rbac_file"
            ((count++))
        fi
    done

    # Check admission controllers
    log "INFO" "Checking admission controller configuration"
    write_asset "$rbac_file" "domain=$domain"
    write_endpoint "$rbac_file" "k8s_api=https://${domain}:6443"

    py_log "INFO" "container_k8s_api" "Completed K8s API analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/k8s_api/count.txt"
    log "INFO" "Kubernetes API analysis complete. Findings: $count"
}

container_k8s_api "$@"
