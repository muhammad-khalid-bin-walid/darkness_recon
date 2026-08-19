#!/bin/bash
# Cloud infrastructure scanning phase

cloud_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local cloud_dir="$output_dir/cloud"

    mkdir -p "$cloud_dir"

    log "INFO" "Starting cloud infrastructure scanning for $domain"

    if command -v aws >/dev/null 2>&1; then
        log "INFO" "Querying AWS for cloud assets..."
        aws s3 ls 2>/dev/null >> "$cloud_dir/aws_s3.txt" || true
        aws ec2 describe-instances 2>/dev/null | jq -r '.Reservations[].Instances[].PublicIpAddress' 2>/dev/null >> "$cloud_dir/aws_ips.txt" || true
    fi

    if command -v az >/dev/null 2>&1; then
        log "INFO" "Querying Azure for cloud assets..."
        az storage account list 2>/dev/null | jq -r '.[].name' 2>/dev/null >> "$cloud_dir/azure_storage.txt" || true
    fi

    if command -v gcloud >/dev/null 2>&1; then
        log "INFO" "Querying GCP for cloud assets..."
        gcloud storage buckets list 2>/dev/null >> "$cloud_dir/gcp_buckets.txt" || true
    fi

    if command -v grep >/dev/null 2>&1; then
        log "INFO" "Searching for cloud-related endpoints..."
        if [ -f "$output_dir/crawl/endpoints.txt" ]; then
            grep -iE "(amazonaws|azure|gcp|cloud\.google|cloudflare|fastly|akamai|jsdelivr|unpkg|cdnjs)" "$output_dir/crawl/endpoints.txt" 2>/dev/null | \
                sort -u > "$cloud_dir/cloud_endpoints.txt" || true
        fi
    fi

    if command -v grep >/dev/null 2>&1; then
        log "INFO" "Searching for Docker/K8s related endpoints..."
        if [ -f "$output_dir/crawl/endpoints.txt" ]; then
            grep -iE "(docker|container|kubernetes|k8s|helm|kube|pod|namespace|manifest|image|registry)" "$output_dir/crawl/endpoints.txt" 2>/dev/null | \
                sort -u > "$cloud_dir/docker_k8s_endpoints.txt" || true
        fi
    fi

    local cloud_count
    cloud_count=$(wc -l < "$cloud_dir/cloud_endpoints.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "Cloud infrastructure scanning complete: $cloud_count cloud assets found" "cloud" "$domain"

    # Write assets for cloud endpoints
    while IFS= read -r endpoint; do
        [ -z "$endpoint" ] && continue
        write_asset "{\"type\":\"cloud_endpoint\",\"url\":\"$endpoint\",\"phase\":\"cloud\"}" \
            "$cloud_dir/assets.jsonl" 2>/dev/null || true
    done < "$cloud_dir/cloud_endpoints.txt" 2>/dev/null

    # Write findings for Docker/K8s endpoints
    if [ -f "$cloud_dir/docker_k8s_endpoints.txt" ]; then
        local k8s_count
        k8s_count=$(wc -l < "$cloud_dir/docker_k8s_endpoints.txt" 2>/dev/null || echo 0)
        if [ "$k8s_count" -gt 0 ]; then
            write_finding "{\"type\":\"kubernetes_exposure\",\"severity\":\"medium\",\"count\":$k8s_count,\"phase\":\"cloud\"}" \
                "$cloud_dir/findings.jsonl" 2>/dev/null || true
        fi
    fi

    echo "$cloud_count" > "$cloud_dir/count.txt"

    py_log "INFO" "cloud_phase" "Completed for $domain"
}