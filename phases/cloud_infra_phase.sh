#!/bin/bash
# Combined Phase 11: Cloud & Infrastructure Enumeration
# Encompasses: cloud_phase, Kubernetes, Docker, cloud IAM, asset enumeration
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

cloud_infra_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local cloud_dir="$output_dir/cloud"

    mkdir -p "$cloud_dir"

    log "INFO" "Starting cloud & infrastructure enumeration for $domain"

    # Kubernetes enumeration
    if tool_available "kubectl"; then
        log "INFO" "Enumerating Kubernetes resources..."
        kubectl get all -A 2>>"$LOGS_DIR/kubectl.log" >> "$cloud_dir/k8s_resources.txt" 2>/dev/null || true
        kubectl get ingress -A 2>>"$LOGS_DIR/kubectl.log" >> "$cloud_dir/k8s_ingress.txt" 2>/dev/null || true
    fi

    # Docker daemon detection
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking for exposed Docker API..."
        curl -s "http://$domain:2375/version" 2>>"$LOGS_DIR/docker.log" >> "$cloud_dir/docker_api.txt" || true
        curl -s "http://$domain:2376/version" 2>>"$LOGS_DIR/docker.log" >> "$cloud_dir/docker_api.txt" || true
    fi

    # Cloud IAM enumeration (cloud-specific)
    if [ -f "$HOME/.aws/config" ] || command -v aws >/dev/null 2>&1; then
        log "INFO" "Checking AWS IAM exposure..."
        aws iam list-users 2>>"$LOGS_DIR/aws.log" >> "$cloud_dir/aws_iam.txt" 2>/dev/null || true
    fi

    # Container registry exposure
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking container registry exposure..."
        # Check for public registry endpoints
        curl -sI "https://$domain" 2>>"$LOGS_DIR/registry.log" | grep -E "X-Registry-|Docker" >> "$cloud_dir/registry.txt" || true
    fi

    # Cloud asset correlation
    # Look for common cloud patterns in subdomains
    if [ -f "$output_dir/subdomains/subdomains.txt" ]; then
        grep -iE "\.s3\.amazonaws\.com|\.blob\.core\.windows\.net|\.storage\.googleapis\.com" \
            "$output_dir/subdomains/subdomains.txt" >> "$cloud_dir/cloud_endpoints.txt" 2>/dev/null || true
    fi

    local cloud_count
    cloud_count=$(wc -l < "$cloud_dir/cloud_endpoints.txt" 2>/dev/null || echo 0)

    phase_log "INFO" "Cloud & infrastructure enumeration complete: $cloud_count cloud assets found" "cloud_infra" "$domain"

    # Write assets
    while IFS= read -r asset; do
        [ -z "$asset" ] && continue
        write_asset "{\"type\":\"cloud_asset\",\"value\":\"$asset\",\"source\":\"cloud_enumeration\",\"phase\":\"cloud_infra_enumeration\"}" \
            "$cloud_dir/assets.jsonl" 2>/dev/null || true
    done < "$cloud_dir/cloud_endpoints.txt"

    echo "$cloud_count" > "$cloud_dir/count.txt"

    py_log "INFO" "cloud_infra_phase" "Completed for $domain"
}