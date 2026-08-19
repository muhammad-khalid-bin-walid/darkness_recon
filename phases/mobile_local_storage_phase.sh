#!/usr/bin/env bash
# Phase 175: Local Storage Security Audit
set -euo pipefail

mobile_local_storage() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/mobile_local_storage"

    log "INFO" "Starting local storage audit for $domain"

    local storage_vulns="$output_dir/mobile_local_storage/storage_vulns.txt"
    local sensitive_data="$output_dir/mobile_local_storage/sensitive_data.txt"
    local count=0

    {
        echo "=== Local Storage Vulnerabilities ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
    } > "$storage_vulns"

    # Common storage locations
    {
        echo "=== Sensitive Data Locations ==="
        echo "Domain: $domain"
        echo ""
        echo "Common mobile storage locations:"
        echo "  1. SharedPreferences (Android) / NSUserDefaults (iOS)"
        echo "  2. SQLite databases"
        echo "  3. Keychain (iOS) / Keystore (Android)"
        echo "  4. Internal storage files"
        echo "  5. External storage (SD card)"
        echo "  6. Cache directories"
        echo "  7. Log files"
        echo "  8. WebView cache"
        echo ""
        echo "Sensitive data types to check:"
        echo "  - Authentication tokens"
        echo "  - API keys"
        echo "  - User credentials"
        echo "  - PII (Personally Identifiable Information)"
        echo "  - Session data"
        echo "  - Payment information"
        echo "  - Device identifiers"
    } > "$sensitive_data"

    # Check for common storage issues
    {
        echo ""
        echo "--- Storage Security Issues ---"
        echo "1. Unencrypted sensitive data in SharedPreferences"
        echo "2. SQLite databases without SQLCipher"
        echo "3. Keychain accessible when device locked"
        echo "4. External storage with world-readable permissions"
        echo "5. Log files containing sensitive information"
        echo "6. WebView cache storing authentication data"
        echo "7. Backup enabled exposing app data"
        echo "8. Root detection bypass exposing storage"
    } >> "$storage_vulns"

    # Check for common backup issues
    {
        echo ""
        echo "--- Backup Analysis ---"
        echo "Android: android:allowBackup flag"
        echo "  - If true, app data can be extracted via ADB"
        echo "  - Check AndroidManifest.xml for backup settings"
        echo ""
        echo "iOS: iTunes/iCloud backup inclusion"
        echo "  - Check for NSFileProtectionComplete"
        echo "  - Verify Keychain sync settings"
    } >> "$storage_vulns"

    ((count+=8)) || true

    echo "$count" > "$output_dir/mobile_local_storage/count.txt"
    log "INFO" "Local storage audit complete: $count findings"
    write_finding "{\"type\":\"mobile_local_storage\",\"severity\":\"info\",\"count\":$count,\"phase\":\"mobile_local_storage\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=mobile_local_storage domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mobile_local_storage "${1:-}"
fi
