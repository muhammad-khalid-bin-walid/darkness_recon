#!/usr/bin/env bash
# k8s_scan_phase.sh - Kubernetes misconfiguration checks, API server exposure,
# etcd access, RBAC issues.

k8s_scan_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "k8s_scan_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/k8s_scan"

    local results=0
    local vulns_file="$output_dir/k8s_scan/k8s_vulns.txt"
    local misconfigs_file="$output_dir/k8s_scan/k8s_misconfigs.txt"
    local findings_file="$output_dir/k8s_scan/findings.json"

    log "INFO" "Starting k8s scan phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Kubernetes API server exposure ---
    local k8s_hosts=(
        "${domain}"
        "k8s.${domain}"
        "kubernetes.${domain}"
        "api.${domain}"
        "api-server.${domain}"
        "control.${domain}"
        "${domain}:6443"
        "${domain}:8443"
        "k8s.${domain}:6443"
    )

    local k8s_api_paths=(
        "/"
        "/api"
        "/api/v1"
        "/apis"
        "/healthz"
        "/healthz/ready"
        "/healthz/live"
        "/version"
        "/version/api"
        "/openapi/v2"
        "/swagger.json"
        "/swagger-ui"
        "/metrics"
    )

    for khost in "${k8s_hosts[@]}"; do
        for kpath in "${k8s_api_paths[@]}"; do
            local k8s_url="https://${khost}${kpath}"
            local k8s_status k8s_body
            k8s_body=$(curl -s -m 10 -k -w "\n%{http_code}" "$k8s_url" 2>/dev/null || true)
            k8s_status=$(echo "$k8s_body" | tail -1)

            if [[ "$k8s_status" == "200" ]]; then
                local content
                content=$(echo "$k8s_body" | head -n -1)

                # Verify it's actually Kubernetes
                if echo "$content" | grep -qiE '(serverAddressByClientCIDRs|gitVersion|minClientVersion|versions|kubernetes)' 2>/dev/null; then
                    log "INFO" "Kubernetes API found: $k8s_url"

                    echo "[K8S-API] $k8s_url - Kubernetes API accessible (HTTP 200)" >> "$vulns_file"
                    ((results++)) || true

                    write_endpoint "{\"url\":\"$k8s_url\",\"method\":\"GET\",\"status\":200,\"phase\":\"k8s_scan\"}" \
                        "$findings_file" 2>/dev/null || true

                    # Extract version info
                    local version
                    version=$(echo "$content" | grep -oE '"gitVersion":"[^"]*"' 2>/dev/null || true)
                    if [[ -n "$version" ]]; then
                        echo "[K8S-VERSION] $k8s_url - $version" >> "$misconfigs_file"
                    fi

                    # Check for unauthenticated access
                    echo "[K8S-NO-AUTH] $k8s_url - API accessible without authentication" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"k8s_api_no_auth\",\"url\":\"$k8s_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Kubernetes API server accessible without authentication\"}" \
                        "$findings_file" 2>/dev/null || true
                fi
            fi
        done
    done

    # --- etcd access check ---
    local etcd_hosts=(
        "${domain}:2379"
        "${domain}:2380"
        "etcd.${domain}:2379"
        "etcd.${domain}:2380"
        "etcd0.${domain}:2379"
        "etcd1.${domain}:2379"
        "etcd2.${domain}:2379"
    )

    local etcd_paths=(
        "/v2/keys/"
        "/v2/keys/?recursive=true"
        "/v3/kv/range"
        "/v3/cluster/names"
        "/health"
        "/version"
    )

    for ehost in "${etcd_hosts[@]}"; do
        for epath in "${etcd_paths[@]}"; do
            local etcd_url="https://${ehost}${epath}"
            local etcd_status etcd_body
            etcd_body=$(curl -s -m 10 -k -w "\n%{http_code}" "$etcd_url" 2>/dev/null || true)
            etcd_status=$(echo "$etcd_body" | tail -1)

            if [[ "$etcd_status" == "200" ]]; then
                log "INFO" "etcd accessible: $etcd_url"

                echo "[ETCD-ACCESS] $etcd_url - etcd accessible without auth (HTTP 200)" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"etcd_exposed\",\"url\":\"$etcd_url\",\"severity\":\"CRITICAL\",\"evidence\":\"etcd accessible without authentication - full cluster state exposed\"}" \
                    "$findings_file" 2>/dev/null || true

                local etcd_content
                etcd_content=$(echo "$etcd_body" | head -n -1)

                # Check for secrets in etcd
                echo "$etcd_content" | grep -qiE '(password|secret|token|key|certificate)' 2>/dev/null && {
                    echo "[ETCD-SECRETS] $etcd_url - Secrets found in etcd data" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"etcd_secrets_exposed\",\"url\":\"$etcd_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Kubernetes secrets found in exposed etcd\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true
            fi
        done
    done

    # --- RBAC and access control checks ---
    local k8s_rbac_paths=(
        "/apis/rbac.authorization.k8s.io/v1/clusterroles"
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
        "/apis/rbac.authorization.k8s.io/v1/roles"
        "/apis/rbac.authorization.k8s.io/v1/rolebindings"
        "/api/v1/namespaces"
        "/api/v1/namespaces/default/pods"
        "/api/v1/namespaces/kube-system/pods"
        "/api/v1/secrets"
        "/api/v1/configmaps"
        "/api/v1/serviceaccounts"
        "/apis/apps/v1/namespaces/default/deployments"
        "/apis/apps/v1/namespaces/default/daemonsets"
    )

    for khost in "${k8s_hosts[@]:0:3}"; do
        for rpath in "${k8s_rbac_paths[@]}"; do
            local rbac_url="https://${khost}${rpath}"
            local rbac_status
            rbac_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -k "$rbac_url" 2>/dev/null || echo "000")

            if [[ "$rbac_status" == "200" ]]; then
                echo "[K8S-RBAC] $rbac_url - RBAC resource accessible" >> "$misconfigs_file"
                ((results++)) || true

                local rbac_severity="HIGH"
                echo "$rpath" | grep -qE '(secrets|configmaps)' && rbac_severity="CRITICAL" || true

                write_finding "{\"type\":\"k8s_rbac_exposed\",\"url\":\"$rbac_url\",\"severity\":\"$rbac_severity\",\"evidence\":\"Kubernetes RBAC resource accessible without auth\"}" \
                    "$findings_file" 2>/dev/null || true
            fi
        done
    done

    # --- Check kubelet API ---
    local kubelet_paths=(
        "/pods"
        "/containers"
        "/logs"
        "/run/"
        "/exec/"
        "/attach/"
        "/portForward/"
        "/metrics"
        "/spec"
    )

    for khost in "${k8s_hosts[@]:0:2}"; do
        for kpath in "${kubelet_paths[@]}"; do
            local kubelet_url="https://${khost}:10250${kpath}"
            local kubelet_status
            kubelet_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -k "$kubelet_url" 2>/dev/null || echo "000")

            if [[ "$kubelet_status" == "200" ]]; then
                echo "[KUBELET-EXPOSED] $kubelet_url - Kubelet API accessible" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"kubelet_exposed\",\"url\":\"$kubelet_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Kubelet API accessible without auth\"}" \
                    "$findings_file" 2>/dev/null || true
            fi
        done
    done

    # --- Check for exposed kubeconfig ---
    local kubeconfig_paths=(
        "/.kube/config"
        "/kubeconfig"
        "/config"
        "/admin.conf"
        "/.kube/config.yaml"
        "/k8s/config"
    )

    for kpath in "${kubeconfig_paths[@]}"; do
        local kc_status
        kc_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://${domain}${kpath}" 2>/dev/null || echo "000")

        if [[ "$kc_status" == "200" ]]; then
            echo "[KUBECONFIG-EXPOSED] https://${domain}${kpath} - kubeconfig accessible" >> "$vulns_file"
            ((results++)) || true

            write_finding "{\"type\":\"kubeconfig_exposed\",\"url\":\"https://${domain}${kpath}\",\"severity\":\"CRITICAL\",\"evidence\":\"kubeconfig file publicly accessible\"}" \
                "$findings_file" 2>/dev/null || true
        fi
    done

    # Write count
    echo "$results" > "$output_dir/k8s_scan/count.txt"

    py_log "INFO" "k8s_scan_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "K8s scan phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    k8s_scan_phase "$@"
fi
