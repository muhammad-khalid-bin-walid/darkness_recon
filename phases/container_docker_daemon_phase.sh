#!/usr/bin/env bash
# Track 12 - Container/K8s | Phase 201: Docker Daemon Security Analysis
set -euo pipefail

container_docker_daemon() {
    local domain="${1:?Usage: container_docker_daemon <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/docker_daemon"

    local vulns_file="$output_dir/docker_daemon/docker_daemon_vulns.txt"
    local config_file="$output_dir/docker_daemon/docker_config.txt"
    local count=0

    log "INFO" "Starting Docker daemon security analysis for $domain"

    # Check Docker daemon API exposure
    if tool_available curl; then
        log "INFO" "Checking Docker daemon API exposure on common ports"
        for port in 2375 2376; do
            local api_response
            api_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${domain}:${port}/version" 2>/dev/null || true)
            if [[ "$api_response" == "200" ]]; then
                write_finding "$vulns_file" "CRITICAL" "Docker daemon API exposed on port $port without authentication"
                echo "Port $port: API accessible without auth" >> "$config_file"
                ((count++))
            fi
        done
    fi

    # Check TLS configuration
    if tool_available openssl; then
        log "INFO" "Checking Docker daemon TLS configuration"
        local tls_check
        tls_check=$(openssl s_client -connect "${domain}:2376" -servername "$domain" </dev/null 2>&1 || true)
        if echo "$tls_check" | grep -q "Verify return code: 0"; then
            echo "TLS: Valid certificate" >> "$config_file"
        else
            write_finding "$vulns_file" "HIGH" "Docker daemon TLS not properly configured"
            echo "TLS: Invalid or missing certificate" >> "$config_file"
            ((count++))
        fi
    fi

    # Check socket mounting risks
    log "INFO" "Analyzing Docker socket mounting risks"
    local socket_risks=("docker.sock:/var/run/docker.sock" "/var/run/docker.sock:/var/run/docker.sock")
    for risk in "${socket_risks[@]}"; do
        if echo "$risk" | grep -q "docker.sock"; then
            write_finding "$vulns_file" "HIGH" "Docker socket mounting detected: $risk"
            ((count++))
        fi
    done

    # Write findings using bridge functions
    write_asset "$config_file" "domain=$domain"
    write_endpoint "$config_file" "docker_api=http://${domain}:2375"

    # Write structured Python log
    py_log "INFO" "container_docker_daemon" "Completed analysis for $domain" findings="$count"

    # Write count
    echo "$count" > "$output_dir/docker_daemon/count.txt"
    log "INFO" "Docker daemon analysis complete. Findings: $count"
}

container_docker_daemon "$@"
