#!/usr/bin/env bash
# TLS Chain Phase - Certificate chain and TLS configuration analysis
set -euo pipefail

tls_chain_phase() {
    local domain="$1"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/tls_chain"
    mkdir -p "$phase_dir"

    log "INFO" "[tls_chain] Starting TLS chain analysis for $domain"
    py_log "phase_start" "tls_chain" "$domain"

    local count=0

    # sslyze certificate chain analysis
    if tool_available "sslyze"; then
        log "INFO" "[tls_chain] Running sslyze certificate scan"
        sslyze --json_out "$phase_dir/sslyze_output.json" "$domain" 2>/dev/null || true

        # Parse sslyze JSON for chain details
        python3 -c "
import json, sys
try:
    data = json.load(open('$phase_dir/sslyze_output.json'))
    for server in data.get('server_scan_results', []):
        cert_info = server.get('certificate_info', {})
        chain = cert_info.get('certificate_chain', [])
        for i, cert in enumerate(chain):
            subject = cert.get('parsed', {}).get('subject', {})
            issuer = cert.get('parsed', {}).get('issuer', {})
            not_after = cert.get('parsed', {}).get('validity', {}).get('not_after', '')
            sans = cert.get('parsed', {}).get('subject_alt_name', {}).get('dns_names', [])
            print(f'Chain #{i}:')
            print(f'  Subject: {subject}')
            print(f'  Issuer: {issuer}')
            print(f'  Expiry: {not_after}')
            print(f'  SANs: {sans}')
            print()
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
" > "$phase_dir/cert_chains.txt" 2>/dev/null || true

        # Extract weak ciphers
        python3 -c "
import json
try:
    data = json.load(open('$phase_dir/sslyze_output.json'))
    for server in data.get('server_scan_results', []):
        cipher_info = server.get('cipher_suite', {})
        for suite in cipher_info.get('accepted_cipher_list', []):
            name = suite.get('name', '')
            strength = suite.get('key_size', 0)
            proto = suite.get('protocol', '')
            if strength < 128 or 'RC4' in name or 'DES' in name or 'NULL' in name or 'EXPORT' in name:
                print(f'WEAK: {name} ({proto}, {strength}-bit)')
except: pass
" > "$phase_dir/weak_ciphers.txt" 2>/dev/null || true
    else
        log "WARN" "[tls_chain] sslyze not available, using openssl"
        # Fallback to openssl
        log "INFO" "[tls_chain] Using openssl for certificate chain"
        echo | openssl s_client -connect "$domain:443" -showcerts 2>/dev/null \
            > "$phase_dir/openssl_chain.txt" || true
        openssl s_client -connect "$domain:443" 2>/dev/null \
            | openssl x509 -noout -text 2>/dev/null \
            > "$phase_dir/cert_details.txt" || true
    fi

    # Certificate transparency log search
    log "INFO" "[tls_chain] Querying CT logs for certificate history"
    curl -s "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null \
        > "$phase_dir/crtsh_raw.json" 2>/dev/null || true

    # Parse CT log for SANs
    python3 -c "
import json
try:
    data = json.load(open('$phase_dir/crtsh_raw.json'))
    all_sans = set()
    for entry in data:
        name = entry.get('name_value', '')
        for n in name.split('\n'):
            n = n.strip().lower()
            if n:
                all_sans.add(n)
    for san in sorted(all_sans):
        print(san)
except: pass
" > "$phase_dir/san_domains.txt" 2>/dev/null || true

    # Check certificate expiry
    log "INFO" "[tls_chain] Checking certificate expiry"
    local expiry_date
    expiry_date=$(echo | openssl s_client -connect "$domain:443" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    if [[ -n "$expiry_date" ]]; then
        echo "Certificate Expiry: $expiry_date" >> "$phase_dir/cert_chains.txt"
    fi

    # Check for HSTS
    local hsts_header
    hsts_header=$(curl -sI "https://$domain" 2>/dev/null | grep -i strict-transport)
    if [[ -n "$hsts_header" ]]; then
        echo "HSTS: $hsts_header" >> "$phase_dir/cert_chains.txt"
    else
        echo "HSTS: Not configured" >> "$phase_dir/cert_chains.txt"
    fi

    count=$(wc -l < "$phase_dir/san_domains.txt" 2>/dev/null || echo 0)
    echo "$count" > "$phase_dir/count.txt"

    write_finding "$domain" "tls_chain" "info" \
        "Analyzed TLS chain: $count SAN domains, $(wc -l < "$phase_dir/weak_ciphers.txt" 2>/dev/null || echo 0) weak ciphers" || true

    log "INFO" "[tls_chain] Complete: $count SAN domains found"
    py_log "phase_complete" "tls_chain" "$domain" "count=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    tls_chain_phase "${1:?Usage: tls_chain_phase <domain>}"
fi
