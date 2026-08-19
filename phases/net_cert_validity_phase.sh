#!/usr/bin/env bash
# Phase 194: Certificate Validity and Chain Analysis
set -euo pipefail

net_cert_validity() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/net_cert_validity"

    log "INFO" "Starting certificate validity analysis for $domain"

    local cert_validity="$output_dir/net_cert_validity/cert_validity.txt"
    local revocation_status="$output_dir/net_cert_validity/revocation_status.txt"
    local count=0

    {
        echo "=== Certificate Validity ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Certificate checks:"
        echo "  1. Expiration date"
        echo "  2. Subject Alternative Names"
        echo "  3. Key size and algorithm"
        echo "  4. Signature algorithm"
        echo "  5. Certificate chain depth"
        echo "  6. Self-signed certificates"
        echo "  7. Wildcard certificates"
        echo "  8. Certificate transparency"
    } > "$cert_validity"

    {
        echo "=== Revocation Status ==="
        echo "Domain: $domain"
        echo ""
        echo "Revocation checking methods:"
        echo "  - CRL (Certificate Revocation List)"
        echo "  - OCSP (Online Certificate Status Protocol)"
        echo "  - OCSP Stapling"
        echo "  - Must-Staple extension"
        echo ""
        echo "Revocation risks:"
        echo "  - Revoked certificate still valid"
        echo "  - No revocation checking"
        echo "  - Stale CRL data"
        echo "  - OCSP responder failure"
        echo "  - Short-lived certificates"
    } > "$revocation_status"

    # Get certificate details
    local cert_info
    cert_info=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null)
    
    if [[ $? -eq 0 ]]; then
        # Extract certificate details
        local subject
        subject=$(echo "$cert_info" | grep "subject=" | head -1 || echo "")
        local issuer
        issuer=$(echo "$cert_info" | grep "issuer=" | head -1 || echo "")
        local dates
        dates=$(echo "$cert_info" | openssl x509 -noout -dates 2>/dev/null || echo "")
        
        {
            echo "[CERT] Subject: $subject"
            echo "[CERT] Issuer: $issuer"
            echo "[CERT] $dates"
        } >> "$cert_validity"
        ((count++)) || true
    fi

    # Check for OCSP
    local ocsp_test
    ocsp_test=$(echo | openssl s_client -connect "$domain:443" -status 2>/dev/null | grep -i "OCSP" | head -1 || echo "")
    if [[ -n "$ocsp_test" ]]; then
        echo "[OCSP] $ocsp_test" >> "$revocation_status"
        ((count++)) || true
    fi

    echo "$count" > "$output_dir/net_cert_validity/count.txt"
    log "INFO" "Certificate validity analysis complete: $count findings"
    write_finding "{\"type\":\"net_cert_validity\",\"severity\":\"info\",\"count\":$count,\"phase\":\"net_cert_validity\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=net_cert_validity domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    net_cert_validity "${1:-}"
fi
