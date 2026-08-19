#!/usr/bin/env bash
# Phase 181: In-App Purchase Review
set -euo pipefail

mobile_iap() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/mobile_iap"

    log "INFO" "Starting in-app purchase review for $domain"

    local iap_vulns="$output_dir/mobile_iap/iap_vulns.txt"
    local receipt_issues="$output_dir/mobile_iap/receipt_issues.txt"
    local count=0

    {
        echo "=== In-App Purchase Vulnerabilities ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Common IAP security issues:"
        echo "  1. Receipt validation bypass"
        echo "  2. Client-side receipt verification"
        echo "  3. Hardcoded product IDs"
        echo "  4. Missing server-side validation"
        echo "  5. Price manipulation"
        echo "  6. Subscription abuse"
        echo "  7. Refund fraud"
        echo "  8. License key bypass"
    } > "$iap_vulns"

    {
        echo "=== Receipt Issues ==="
        echo "Domain: $domain"
        echo ""
        echo "Receipt validation analysis:"
        echo "  - Apple App Store receipt verification"
        echo "  - Google Play billing receipt verification"
        echo "  - Server-side receipt validation endpoint"
        echo "  - Receipt tampering detection"
        echo "  - Replay attack prevention"
        echo ""
        echo "Subscription abuse vectors:"
        echo "  1. Shared subscription accounts"
        echo "  2. Receipt sharing"
        echo "  3. Trial period abuse"
        echo "  4. Cancellation/renewal manipulation"
        echo "  5. Family sharing exploitation"
        echo "  6. Refund abuse patterns"
        echo ""
        echo "License key security:"
        echo "  - Key generation algorithm"
        echo "  - Key validation logic"
        echo "  - Offline vs online validation"
        echo "  - Key rotation mechanism"
    } > "$receipt_issues"

    # Check for IAP-related endpoints
    local iap_endpoints=(
        "/iap/verify"
        "/api/purchase"
        "/subscription/verify"
        "/receipt/validate"
    )

    for endpoint in "${iap_endpoints[@]}"; do
        local url="https://$domain$endpoint"
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
        if [[ "$http_code" =~ ^(200|301|302|401|403)$ ]]; then
            echo "[IAP] $endpoint accessible (HTTP $http_code)" >> "$iap_vulns"
            ((count++)) || true
        fi
    done

    echo "$count" > "$output_dir/mobile_iap/count.txt"
    log "INFO" "In-app purchase review complete: $count findings"
    write_finding "{\"type\":\"mobile_iap\",\"severity\":\"info\",\"count\":$count,\"phase\":\"mobile_iap\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=mobile_iap domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mobile_iap "${1:-}"
fi
