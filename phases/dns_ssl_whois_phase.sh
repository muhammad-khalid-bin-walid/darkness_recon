#!/bin/bash
# DNS/SSL/WHOIS analysis phase

dns_ssl_whois_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local dns_ssl_dir="$output_dir/dns_ssl_whois"
    local subdomains_file="$output_dir/subdomains/subdomains.txt"

    mkdir -p "$dns_ssl_dir"

    log "INFO" "Starting DNS/SSL/WHOIS analysis for $domain"

    if tool_available "whois"; then
        log "INFO" "Running WHOIS lookups..."
        whois "$domain" > "$dns_ssl_dir/whois_main.txt" 2>>"$LOGS_DIR/whois.log" || true
        if [ -f "$subdomains_file" ]; then
            while IFS= read -r sub; do
                [ -z "$sub" ] && continue
                whois "$sub" > "$dns_ssl_dir/whois_$(echo "$sub" | sed 's|\.|_|g').txt" 2>>"$LOGS_DIR/whois.log" || true
            done < <(head -20 "$subdomains_file")
        fi
    fi

    if tool_available "dig"; then
        log "INFO" "Running DNS record analysis..."
        dig "$domain" ANY +noall +answer > "$dns_ssl_dir/dns_records.txt" 2>>"$LOGS_DIR/dig.log" || true
        dig "$domain" TXT +short >> "$dns_ssl_dir/dns_records.txt" 2>/dev/null || true
        dig "$domain" MX +short >> "$dns_ssl_dir/dns_records.txt" 2>/dev/null || true
        dig "$domain" NS +short >> "$dns_ssl_dir/dns_records.txt" 2>/dev/null || true
    fi

    if tool_available "rdap"; then
        log "INFO" "Running RDAP lookups..."
        rdap "$domain" > "$dns_ssl_dir/rdap_main.txt" 2>>"$LOGS_DIR/rdap.log" || true
    fi

    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying SecurityTrails for DNS history..."
        if [ -n "${SECURITYTRAILS_API_KEY:-}" ]; then
            curl -s "https://api.securitytrails.com/v1/domain/$domain/dns_records" \
                -H "Accept: application/json" 2>/dev/null | \
                jq -r '.records[] | "\(.type) \(.value)"' 2>/dev/null >> "$dns_ssl_dir/securitytrails_dns.txt" || true
        fi
    fi

    if command -v grep >/dev/null 2>&1; then
        log "INFO" "Analyzing DNS records for anomalies..."
        if [ -f "$dns_ssl_dir/dns_records.txt" ]; then
            grep -iE "(mx|ns|txt|spf|dkim|dmarc)" "$dns_ssl_dir/dns_records.txt" 2>/dev/null | \
                sort -u > "$dns_ssl_dir/key_records.txt" || true
        fi
    fi

    local dns_ssl_count
    dns_ssl_count=$(wc -l < "$dns_ssl_dir/dns_records.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "DNS/SSL/WHOIS analysis complete: $dns_ssl_count records found" "dns_ssl_whois" "$domain"

    # Write assets for WHOIS information
    if [ -f "$dns_ssl_dir/whois_main.txt" ]; then
        local registrar=$(grep -i "registrar:" "$dns_ssl_dir/whois_main.txt" | head -1 | sed 's/.*registrar: *//i')
        if [ -n "$registrar" ]; then
            write_asset "{\"type\":\"domain_registration\",\"domain\":\"$domain\",\"registrar\":\"$registrar\",\"phase\":\"dns_ssl_whois\"}" \
                "$dns_ssl_dir/assets.jsonl" 2>/dev/null || true
        fi
    fi

    # Write findings for DNS misconfigurations
    if [ -f "$dns_ssl_dir/key_records.txt" ]; then
        if ! grep -qi "spf" "$dns_ssl_dir/key_records.txt" 2>/dev/null; then
            write_finding "{\"type\":\"missing_spf\",\"severity\":\"medium\",\"domain\":\"$domain\",\"phase\":\"dns_ssl_whois\"}" \
                "$dns_ssl_dir/findings.jsonl" 2>/dev/null || true
        fi
        if ! grep -qi "dmarc" "$dns_ssl_dir/key_records.txt" 2>/dev/null; then
            write_finding "{\"type\":\"missing_dmarc\",\"severity\":\"medium\",\"domain\":\"$domain\",\"phase\":\"dns_ssl_whois\"}" \
                "$dns_ssl_dir/findings.jsonl" 2>/dev/null || true
        fi
    fi

    echo "$dns_ssl_count" > "$dns_ssl_dir/count.txt"

    py_log "INFO" "dns_ssl_whois_phase" "Completed for $domain"
}