#!/usr/bin/env bash
# Phase 174: Deep-link and URI Scheme Testing
set -euo pipefail

mobile_deeplink() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/mobile_deeplink"

    log "INFO" "Starting deep-link testing for $domain"

    local deeplink_vulns="$output_dir/mobile_deeplink/deeplink_vulns.txt"
    local uri_schemes="$output_dir/mobile_deeplink/uri_schemes.txt"
    local count=0

    {
        echo "=== Deep-link Vulnerabilities ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
    } > "$deeplink_vulns"

    # Common URI schemes
    local schemes=(
        "$domain://"
        "https://$domain/"
        "myapp://"
        "app://"
        "intent://"
    )

    {
        echo "=== URI Schemes ==="
        echo "Domain: $domain"
        echo ""
        echo "Common URI schemes to test:"
    } > "$uri_schemes"

    for scheme in "${schemes[@]}"; do
        echo "  - $scheme" >> "$uri_schemes"
    done

    # Test common deep-link paths
    local deeplink_paths=(
        "/deeplink"
        "/callback"
        "/oauth"
        "/redirect"
        "/invite"
        "/ref"
    )

    for path in "${deeplink_paths[@]}"; do
        local url="https://$domain$path"
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
        if [[ "$http_code" =~ ^(200|301|302)$ ]]; then
            echo "[DEEPLINK] $url (HTTP $http_code)" >> "$deeplink_vulns"
            ((count++)) || true
        fi
    done

    # Intent hijacking analysis
    {
        echo ""
        echo "--- Intent Hijacking Analysis ---"
        echo "Check for:"
        echo "  - Unprotected intent handlers"
        echo "  - Missing intent filters"
        echo "  - Exported activities"
        echo "  - Custom scheme abuse"
        echo ""
        echo "--- Custom Scheme Abuse ---"
        echo "Test for:"
        echo "  - URL parameter injection"
        echo "  - Open redirect via deep-links"
        echo "  - Authentication bypass through deep-links"
    } >> "$deeplink_vulns"

    echo "$count" > "$output_dir/mobile_deeplink/count.txt"
    log "INFO" "Deep-link testing complete: $count findings"
    write_finding "{\"type\":\"mobile_deeplink\",\"severity\":\"info\",\"count\":$count,\"phase\":\"mobile_deeplink\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=mobile_deeplink domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mobile_deeplink "${1:-}"
fi
