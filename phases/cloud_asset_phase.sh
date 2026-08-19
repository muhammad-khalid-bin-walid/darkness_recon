#!/usr/bin/env bash
# Cloud Asset Phase - Cloud service and storage bucket discovery
set -euo pipefail

cloud_asset_phase() {
    local domain="$1"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/cloud_asset"
    mkdir -p "$phase_dir"

    log "INFO" "[cloud_asset] Starting cloud asset discovery for $domain"
    py_log "phase_start" "cloud_asset" "$domain"

    local count=0

    # cloud_enum for multi-cloud enumeration
    if tool_available "cloud_enum"; then
        log "INFO" "[cloud_asset] Running cloud_enum"
        cloud_enum -k "$domain" 2>/dev/null \
            | tee "$phase_dir/cloud_enum_raw.txt" || true
    else
        log "WARN" "[cloud_asset] cloud_enum not available"
    fi

    # S3 scanner
    if tool_available "s3scanner"; then
        log "INFO" "[cloud_asset] Running s3scanner"
        s3scanner scan -bucket "$domain" 2>/dev/null \
            >> "$phase_dir/s3_raw.txt" || true
    fi

    # Loudoun for Azure/GCS enumeration
    if tool_available "loudoun"; then
        log "INFO" "[cloud_asset] Running loudoun"
        loudoun -d "$domain" 2>/dev/null \
            >> "$phase_dir/loudoun_raw.txt" || true
    fi

    # Check common S3 bucket naming patterns
    log "INFO" "[cloud_asset] Checking common bucket naming patterns"
    local prefixes=("dev" "staging" "prod" "backup" "logs" "assets" "media" "cdn" "static" "data")
    for prefix in "${prefixes[@]}"; do
        curl -sI "https://${prefix}-${domain}.s3.amazonaws.com" 2>/dev/null \
            >> "$phase_dir/s3_probe.txt" || true
        curl -sI "https://${domain}-${prefix}.s3.amazonaws.com" 2>/dev/null \
            >> "$phase_dir/s3_probe.txt" || true
        curl -sI "https://${prefix}${domain}.s3.amazonaws.com" 2>/dev/null \
            >> "$phase_dir/s3_probe.txt" || true
    done

    # GCS bucket checks
    log "INFO" "[cloud_asset] Checking GCS bucket patterns"
    for prefix in "${prefixes[@]}"; do
        curl -sI "https://${prefix}-${domain}.storage.googleapis.com" 2>/dev/null \
            >> "$phase_dir/gcs_probe.txt" || true
        curl -sI "https://${domain}-${prefix}.storage.googleapis.com" 2>/dev/null \
            >> "$phase_dir/gcs_probe.txt" || true
    done

    # Combine and deduplicate results
    cat "$phase_dir/cloud_enum_raw.txt" "$phase_dir/s3_raw.txt" \
        "$phase_dir/loudoun_raw.txt" "$phase_dir/s3_probe.txt" \
        "$phase_dir/gcs_probe.txt" 2>/dev/null \
        | grep -viE '(^$|not found|404|error|denied|forbidden)' \
        | sort -u > "$phase_dir/cloud_assets.txt" || true

    # Filter storage buckets specifically
    grep -iE '(s3|storage|bucket|blob|container)' "$phase_dir/cloud_assets.txt" 2>/dev/null \
        > "$phase_dir/storage_buckets.txt" || true

    count=$(wc -l < "$phase_dir/cloud_assets.txt" 2>/dev/null || echo 0)
    echo "$count" > "$phase_dir/count.txt"

    write_finding "$domain" "cloud_asset" "info" \
        "Discovered $count cloud assets" || true
    write_asset "$domain" "cloud" "$phase_dir/cloud_assets.txt" || true

    log "INFO" "[cloud_asset] Complete: $count cloud assets found"
    py_log "phase_complete" "cloud_asset" "$domain" "count=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    cloud_asset_phase "${1:?Usage: cloud_asset_phase <domain>}"
fi
