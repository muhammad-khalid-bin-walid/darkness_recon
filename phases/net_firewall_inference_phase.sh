#!/usr/bin/env bash
# Phase 200: Firewall Rule Inference and WAF Detection
set -euo pipefail

net_firewall_inference() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/net_firewall_inference"

    log "INFO" "Starting firewall inference for $domain"

    local firewall_rules="$output_dir/net_firewall_inference/firewall_rules.txt"
    local filtering_analysis="$output_dir/net_firewall_inference/filtering_analysis.txt"
    local count=0

    {
        echo "=== Firewall Rules ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Firewall detection methods:"
        echo "  1. Port scan analysis"
        echo "  2. Packet filtering behavior"
        echo "  3. Rule inference"
        echo "  4. Bypass techniques"
        echo "  5. WAF detection"
        echo "  6. Rate limiting"
        echo "  7. Geo-blocking"
        echo "  8. IP reputation filtering"
    } > "$firewall_rules"

    {
        echo "=== Filtering Analysis ==="
        echo "Domain: $domain"
        echo ""
        echo "Firewall types to identify:"
        echo "  - Packet filtering (stateless)"
        echo "  - Stateful inspection"
        echo "  - Application layer (WAF)"
        echo "  - Next-generation firewall"
        echo "  - Cloud-based WAF"
        echo ""
        echo "WAF detection indicators:"
        echo "  - HTTP error codes (403, 406, 429, 503)"
        echo "  - Custom error pages"
        echo "  - Rate limiting headers"
        echo "  - Challenge pages (CAPTCHA)"
        echo "  - JavaScript challenges"
        echo "  - Bot detection"
        echo ""
        echo "Common WAF signatures:"
        echo "  - Cloudflare: cf-ray header"
        echo "  - AWS WAF: x-amzn-waf-header"
        echo "  - Akamai: x-akamai-transformed"
        echo "  - Imperva: x-imperva-header"
    } > "$filtering_analysis"

    # Test for WAF
    local waf_tests=(
        "/<script>alert(1)</script>"
        "/etc/passwd"
        "/../../../etc/passwd"
        "/?id=1' OR '1'='1"
    )

    for path in "${waf_tests[@]}"; do
        local url="https://$domain$path"
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
        if [[ "$http_code" =~ ^(403|406|429|503)$ ]]; then
            echo "[WAF] Blocked request: $path (HTTP $http_code)" >> "$filtering_analysis"
            ((count++)) || true
        fi
    done

    # Check for security headers
    local sec_headers
    sec_headers=$(curl -sI "https://$domain" 2>/dev/null || echo "")
    if [[ -n "$sec_headers" ]]; then
        if echo "$sec_headers" | grep -qi "x-frame-options"; then
            echo "[FW] X-Frame-Options header present" >> "$firewall_rules"
            ((count++)) || true
        fi
        if echo "$sec_headers" | grep -qi "content-security-policy"; then
            echo "[FW] Content-Security-Policy present" >> "$firewall_rules"
            ((count++)) || true
        fi
    fi

    echo "$count" > "$output_dir/net_firewall_inference/count.txt"
    log "INFO" "Firewall inference complete: $count findings"
    write_finding "{\"type\":\"net_firewall_inference\",\"severity\":\"info\",\"count\":$count,\"phase\":\"net_firewall_inference\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=net_firewall_inference domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    net_firewall_inference "${1:-}"
fi
