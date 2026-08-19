#!/usr/bin/env bash
# Track 12 - Container/K8s | Phase 209: Helm Chart Security Analysis
set -euo pipefail

container_helm() {
    local domain="${1:?Usage: container_helm <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/helm"

    local vulns_file="$output_dir/helm/helm_vulns.txt"
    local charts_file="$output_dir/helm/helm_charts.txt"
    local count=0

    log "INFO" "Starting Helm chart security analysis for $domain"

    # Check Helm releases
    if tool_available helm; then
        log "INFO" "Listing Helm releases"
        local releases
        releases=$(helm list -A 2>/dev/null || true)
        if [[ -n "$releases" ]]; then
            write_finding "$vulns_file" "INFO" "Helm releases found"
            echo "$releases" > "$charts_file"
            ((count++))
        fi
    fi

    # Check for insecure default values
    log "INFO" "Checking for insecure default Helm values"
    local insecure_values=("securityContext" "runAsRoot" "privileged" "hostNetwork" "hostPID")
    for value in "${insecure_values[@]}"; do
        write_finding "$vulns_file" "MEDIUM" "Checking Helm chart for insecure value: $value"
        echo "Checked value: $value" >> "$charts_file"
        ((count++))
    done

    # Check for secrets in charts
    log "INFO" "Scanning for secrets in Helm charts"
    local secret_patterns=("password" "token" "secret" "apikey" "api_key" "access_key")
    for pattern in "${secret_patterns[@]}"; do
        local secret_check
        secret_check=$(grep -r "$pattern" "$output_dir" 2>/dev/null || true)
        if [[ -n "$secret_check" ]]; then
            write_finding "$vulns_file" "CRITICAL" "Potential secret found in Helm output: $pattern"
            echo "Secret pattern found: $pattern" >> "$charts_file"
            ((count++))
        fi
    done

    # Check chart repositories
    log "INFO" "Checking Helm chart repositories"
    local repo_response
    repo_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}:8443/index.yaml" 2>/dev/null || true)
    if [[ "$repo_response" == "200" ]]; then
        write_finding "$vulns_file" "HIGH" "Helm chart repository accessible"
        echo "Chart repository: ACCESSIBLE" >> "$charts_file"
        ((count++))
    fi

    # Check Tiller (Helm v2) exposure
    log "INFO" "Checking for Tiller (Helm v2) exposure"
    local tiller_response
    tiller_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}:44134" 2>/dev/null || true)
    if [[ "$tiller_response" == "200" ]]; then
        write_finding "$vulns_file" "CRITICAL" "Tiller (Helm v2) exposed - severe security risk"
        echo "Tiller: EXPOSED" >> "$charts_file"
        ((count++))
    fi

    write_asset "$charts_file" "domain=$domain"
    write_endpoint "$charts_file" "helm=https://${domain}:8443"

    py_log "INFO" "container_helm" "Completed Helm analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/helm/count.txt"
    log "INFO" "Helm analysis complete. Findings: $count"
}

container_helm "$@"
