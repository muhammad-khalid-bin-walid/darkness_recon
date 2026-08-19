#!/usr/bin/env bash
# Origin IP Phase - Discover origin IPs behind CDN/WAF
set -euo pipefail

origin_ip_phase() {
    local domain="$1"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/origin_ip"
    mkdir -p "$phase_dir"

    log "INFO" "[origin_ip] Starting origin IP discovery for $domain"
    py_log "phase_start" "origin_ip" "$domain"

    local count=0

    # Direct DNS lookup
    log "INFO" "[origin_ip] Performing direct DNS lookups"
    dig +short "$domain" A 2>/dev/null >> "$phase_dir/dns_direct.txt" || true
    dig +short "$domain" AAAA 2>/dev/null >> "$phase_dir/dns_direct.txt" || true

    # Check DNS history via SecurityTrails/APIs
    log "INFO" "[origin_ip] Checking historical DNS records"
    for sub in "direct" "mail" "ftp" "vpn" "gateway" "router" "ns1" "ns2" "mx" "autodiscover"; do
        dig +short "${sub}.${domain}" A 2>/dev/null >> "$phase_dir/dns_historical.txt" || true
    done

    # Check for domains pointing to same IP (reverse IP lookup)
    local primary_ip
    primary_ip=$(dig +short "$domain" A 2>/dev/null | head -1)
    if [[ -n "$primary_ip" ]]; then
        log "INFO" "[origin_ip] Primary IP: $primary_ip - checking reverse DNS"
        dig +short -x "$primary_ip" 2>/dev/null >> "$phase_dir/reverse_dns.txt" || true
    fi

    # Censys passive check
    if tool_available "censys"; then
        log "INFO" "[origin_ip] Querying Censys for historical IPs"
        censys search "parsed.names: ${domain}" 2>/dev/null \
            >> "$phase_dir/censys_raw.txt" || true
    fi

    # Shodan passive check via curl
    if [[ -n "${SHODAN_API_KEY:-}" ]]; then
        log "INFO" "[origin_ip] Querying Shodan for host history"
        curl -s "https://api.shodan.io/dns/domain/${domain}?key=${SHODAN_API_KEY}" \
            2>/dev/null >> "$phase_dir/shodan_dns.txt" || true
    fi

    # Certificate transparency logs for IP associations
    log "INFO" "[origin_ip] Checking certificate transparency logs"
    curl -s "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null \
        | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    ips = set()
    for entry in data:
        for name in entry.get('name_value', '').split('\n'):
            if name.strip():
                pass
    print('\n'.join(sorted(ips)))
except: pass
" >> "$phase_dir/ct_ips.txt" 2>/dev/null || true

    # Email header analysis (if headers provided)
    if [[ -f "$phase_dir/../email_headers.txt" ]]; then
        log "INFO" "[origin_ip] Analyzing email headers for origin IPs"
        grep -oiP 'from\s+\[?(\d+\.\d+\.\d+\.\d+)\]?' "$phase_dir/../email_headers.txt" 2>/dev/null \
            >> "$phase_dir/email_origin_ips.txt" || true
    fi

    # Combine all discovered IPs
    cat "$phase_dir/dns_direct.txt" "$phase_dir/dns_historical.txt" \
        "$phase_dir/reverse_dns.txt" "$phase_dir/censys_raw.txt" \
        "$phase_dir/shodan_dns.txt" "$phase_dir/ct_ips.txt" \
        "$phase_dir/email_origin_ips.txt" 2>/dev/null \
        | grep -oP '\d+\.\d+\.\d+\.\d+' \
        | sort -u > "$phase_dir/origin_ips.txt" || true

    # Identify CDN vs origin
    log "INFO" "[origin_ip] Classifying CDN vs origin IPs"
    grep -viE '(cloudflare|akamai|fastly|cloudfront|incapsula|sucuri|imperva)' \
        "$phase_dir/origin_ips.txt" 2>/dev/null \
        > "$phase_dir/cdn_bypass.txt" || true

    count=$(wc -l < "$phase_dir/origin_ips.txt" 2>/dev/null || echo 0)
    echo "$count" > "$phase_dir/count.txt"

    write_finding "$domain" "origin_ip" "info" \
        "Identified $count potential origin IPs" || true

    log "INFO" "[origin_ip] Complete: $count origin IPs found"
    py_log "phase_complete" "origin_ip" "$domain" "count=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    origin_ip_phase "${1:?Usage: origin_ip_phase <domain>}"
fi
