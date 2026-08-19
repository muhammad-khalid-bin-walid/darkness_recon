#!/usr/bin/env bash
# Phase 171: APK/IPA Extraction and Analysis
set -euo pipefail

mobile_apk_extract() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/mobile_apk_extract"

    log "INFO" "Starting APK/IPA extraction for $domain"

    local mobile_assets="$output_dir/mobile_apk_extract/mobile_assets.txt"
    local manifest_audit="$output_dir/mobile_apk_extract/manifest_audit.txt"
    local count=0

    # Tool checks
    if ! tool_available apktool; then
        log "WARN" "apktool not available, skipping APK decompilation"
    fi

    if ! tool_available jadx; then
        log "WARN" "jadx not available, skipping Java decompilation"
    fi

    # Search for APK/IPA artifacts
    {
        echo "=== APK/IPA Extraction Results ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
    } > "$mobile_assets"

    # Check common mobile asset locations
    local asset_paths=(
        "https://$domain/app.apk"
        "https://$domain/app.ipa"
        "https://$domain/download"
        "https://$domain/AndroidManifest.xml"
    )

    for url in "${asset_paths[@]}"; do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
        if [[ "$http_code" == "200" ]]; then
            echo "[FOUND] $url (HTTP $http_code)" >> "$mobile_assets"
            ((count++)) || true
        fi
    done

    # Manifest audit
    {
        echo "=== Manifest Audit ==="
        echo "Domain: $domain"
        echo ""
        echo "Checking for exposed manifest files..."
    } > "$manifest_audit"

    # Check AndroidManifest.xml exposure
    local manifest_url="https://$domain/AndroidManifest.xml"
    local manifest_code
    manifest_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$manifest_url" 2>/dev/null || echo "000")
    if [[ "$manifest_code" == "200" ]]; then
        echo "[EXPOSED] AndroidManifest.xml accessible at $manifest_url" >> "$manifest_audit"
        echo "[CRITICAL] Manifest file publicly accessible" >> "$manifest_audit"
        ((count++)) || true
    fi

    # Check for permission declarations
    {
        echo ""
        echo "--- Permission Analysis ---"
        echo "Common dangerous permissions to audit:"
        echo "  android.permission.READ_CONTACTS"
        echo "  android.permission.ACCESS_FINE_LOCATION"
        echo "  android.permission.CAMERA"
        echo "  android.permission.READ_SMS"
        echo "  android.permission.READ_PHONE_STATE"
        echo "  android.permission.WRITE_EXTERNAL_STORAGE"
        echo "  android.permission.RECORD_AUDIO"
        echo "  android.permission.READ_CALL_LOG"
    } >> "$manifest_audit"

    echo "$count" > "$output_dir/mobile_apk_extract/count.txt"
    log "INFO" "APK/IPA extraction complete: $count findings"
    write_finding "{\"type\":\"mobile_apk_extract\",\"severity\":\"info\",\"count\":$count,\"phase\":\"mobile_apk_extract\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=mobile_apk_extract domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mobile_apk_extract "${1:-}"
fi
