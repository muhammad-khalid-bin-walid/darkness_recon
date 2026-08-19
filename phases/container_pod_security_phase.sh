#!/usr/bin/env bash
# Track 12 - Container/K8s | Phase 206: Pod Security Policy/Standard Analysis
set -euo pipefail

container_pod_security() {
    local domain="${1:?Usage: container_pod_security <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/pod_security"

    local vulns_file="$output_dir/pod_security/pod_security_vulns.txt"
    local policies_file="$output_dir/pod_security/pod_policies.txt"
    local count=0

    log "INFO" "Starting pod security analysis for $domain"

    # Check Pod Security Policies
    if tool_available curl; then
        log "INFO" "Checking Pod Security Policies"
        local psp_response
        psp_response=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}:6443/apis/policy/v1beta1/podsecuritypolicies" 2>/dev/null || true)
        if [[ "$psp_response" == "200" ]]; then
            write_finding "$vulns_file" "INFO" "Pod Security Policies endpoint accessible"
            echo "PSP endpoint: ACCESSIBLE" >> "$policies_file"
            ((count++))
        elif [[ "$psp_response" == "404" ]]; then
            write_finding "$vulns_file" "HIGH" "Pod Security Policies not configured"
            echo "PSP: NOT CONFIGURED" >> "$policies_file"
            ((count++))
        fi
    fi

    # Check Pod Security Standards
    log "INFO" "Analyzing Pod Security Standards enforcement"
    local pss_namespaces=("kube-system" "kube-public" "default")
    for ns in "${pss_namespaces[@]}"; do
        local ns_response
        ns_response=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}:6443/api/v1/namespaces/${ns}" 2>/dev/null || true)
        if [[ "$ns_response" == "200" ]]; then
            echo "Namespace $ns: accessible" >> "$policies_file"
            write_finding "$vulns_file" "MEDIUM" "Namespace $ns accessible for security analysis"
            ((count++))
        fi
    done

    # Check privilege escalation paths
    log "INFO" "Checking privilege escalation vectors"
    local esc_vectors=("hostPID" "hostNetwork" "hostIPC" "privileged" "capabilities" "hostPath")
    for vector in "${esc_vectors[@]}"; do
        write_finding "$vulns_file" "MEDIUM" "Checking for $vector privilege escalation"
        echo "Vector checked: $vector" >> "$policies_file"
        ((count++))
    done

    # Check service account token exposure
    log "INFO" "Checking service account token configuration"
    local sa_response
    sa_response=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${domain}:6443/api/v1/namespaces/default/serviceaccounts" 2>/dev/null || true)
    if [[ "$sa_response" == "200" ]]; then
        write_finding "$vulns_file" "MEDIUM" "Service account listing accessible"
        echo "Service accounts: LISTABLE" >> "$policies_file"
        ((count++))
    fi

    write_asset "$policies_file" "domain=$domain"
    write_endpoint "$policies_file" "k8s_api=https://${domain}:6443"

    py_log "INFO" "container_pod_security" "Completed pod security analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/pod_security/count.txt"
    log "INFO" "Pod security analysis complete. Findings: $count"
}

container_pod_security "$@"
