#!/usr/bin/env bash
# Track 12 - Container/K8s | Phase 205: Kubelet API Security Analysis
set -euo pipefail

container_kubelet() {
    local domain="${1:?Usage: container_kubelet <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/kubelet"

    local vulns_file="$output_dir/kubelet/kubelet_vulns.txt"
    local access_file="$output_dir/kubelet/kubelet_access.txt"
    local count=0

    log "INFO" "Starting kubelet API analysis for $domain"

    # Check kubelet API exposure
    if tool_available curl; then
        log "INFO" "Checking kubelet API on common ports"
        local kubelet_ports=(10250 10255)
        for port in "${kubelet_ports[@]}"; do
            local kubelet_response
            kubelet_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}:${port}/pods" 2>/dev/null || true)
            if [[ "$kubelet_response" == "200" || "$kubelet_response" == "403" ]]; then
                write_finding "$vulns_file" "CRITICAL" "Kubelet API accessible on port $port (HTTP $kubelet_response)"
                echo "Port $port: Kubelet API responding" >> "$access_file"
                ((count++))
            fi
        done
    fi

    # Check pod exec access
    log "INFO" "Testing pod exec access"
    if tool_available curl; then
        local exec_response
        exec_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}:10250/run/default/test-container" 2>/dev/null || true)
        if [[ "$exec_response" == "200" || "$exec_response" == "404" ]]; then
            write_finding "$vulns_file" "CRITICAL" "Pod exec access available on kubelet"
            echo "Pod exec: ACCESSIBLE" >> "$access_file"
            ((count++))
        fi
    fi

    # Check log retrieval
    log "INFO" "Testing log retrieval capability"
    if tool_available curl; then
        local log_response
        log_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}:10250/containerLogs/default/test-pod" 2>/dev/null || true)
        if [[ "$log_response" == "200" || "$log_response" == "404" ]]; then
            write_finding "$vulns_file" "HIGH" "Log retrieval accessible via kubelet"
            echo "Log retrieval: ACCESSIBLE" >> "$access_file"
            ((count++))
        fi
    fi

    # Check metrics endpoint
    log "INFO" "Checking kubelet metrics endpoint"
    local metrics_endpoints=("/metrics" "/metrics/cadvisor" "/healthz")
    for endpoint in "${metrics_endpoints[@]}"; do
        local metrics_response
        metrics_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${domain}:10255${endpoint}" 2>/dev/null || true)
        if [[ "$metrics_response" == "200" ]]; then
            write_finding "$vulns_file" "MEDIUM" "Kubelet metrics endpoint accessible: $endpoint"
            echo "$endpoint: accessible" >> "$access_file"
            ((count++))
        fi
    done

    write_asset "$access_file" "domain=$domain"
    write_endpoint "$access_file" "kubelet_api=https://${domain}:10250"

    py_log "INFO" "container_kubelet" "Completed kubelet analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/kubelet/count.txt"
    log "INFO" "Kubelet analysis complete. Findings: $count"
}

container_kubelet "$@"
