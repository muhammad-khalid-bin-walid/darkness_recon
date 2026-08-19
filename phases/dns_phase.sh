#!/bin/bash
# DNS reconnaissance phase

dns_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local dns_dir="$output_dir/dns"
    local subdomains_file="$output_dir/subdomains/subdomains.txt"

    mkdir -p "$dns_dir"

    log "INFO" "Starting DNS reconnaissance for $domain"

    if [ ! -f "$subdomains_file" ]; then
        log "WARN" "No subdomains file found, using domain as target"
        echo "$domain" > "$subdomains_file"
    fi

    if tool_available "dig"; then
        log "INFO" "Running DNS record enumeration..."
        while IFS= read -r sub; do
            [ -z "$sub" ] && continue
            dig +short "$sub" ANY 2>/dev/null >> "$dns_dir/dns_records.txt" || true
            dig +short "$sub" A 2>/dev/null >> "$dns_dir/a_records.txt" || true
            dig +short "$sub" MX 2>/dev/null >> "$dns_dir/mx_records.txt" || true
            dig +short "$sub" TXT 2>/dev/null >> "$dns_dir/txt_records.txt" || true
            dig +short "$sub" NS 2>/dev/null >> "$dns_dir/ns_records.txt" || true
            dig +short "$sub" CNAME 2>/dev/null >> "$dns_dir/cname_records.txt" || true
        done < <(head -100 "$subdomains_file")
    fi

    if tool_available "dnsrecon"; then
        log "INFO" "Running dnsrecon..."
        dnsrecon -d "$domain" -t std 2>>"$LOGS_DIR/dnsrecon.log" >> "$dns_dir/dnsrecon.txt" || true
    fi

    if tool_available "dnsx"; then
        log "INFO" "Running dnsx for DNS resolution..."
        dnsx -l "$subdomains_file" -a -mx -txt -ns -cname -silent 2>>"$LOGS_DIR/dnsx.log" >> "$dns_dir/dnsx_results.txt" || true
    fi

    if command -v host >/dev/null 2>&1; then
        log "INFO" "Running host command for zone transfer check..."
        while IFS= read -r ns; do
            [ -z "$ns" ] && continue
            host -t AXFR "$domain" "$ns" 2>&1 | grep -v ";" >> "$dns_dir/zonetransfer.txt" 2>/dev/null || true
        done < <(dig +short NS "$domain" 2>/dev/null | head -5)
    fi

    local dns_count
    dns_count=$(wc -l < "$dns_dir/dns_records.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "DNS reconnaissance complete: $dns_count DNS records found" "dns" "$domain"

    # Write assets for discovered DNS records
    while IFS= read -r record; do
        [ -z "$record" ] && continue
        write_asset "{\"type\":\"dns_record\",\"value\":\"$record\",\"domain\":\"$domain\",\"source\":\"dns_recon\",\"phase\":\"dns\"}" \
            "$dns_dir/assets.jsonl" 2>/dev/null || true
    done < "$dns_dir/dns_records.txt" 2>/dev/null

    # Check for zone transfer vulnerability (finding)
    if [ -f "$dns_dir/zonetransfer.txt" ] && grep -q "Transfer successful" "$dns_dir/zonetransfer.txt" 2>/dev/null; then
        write_finding "{\"type\":\"zone_transfer\",\"severity\":\"high\",\"domain\":\"$domain\",\"description\":\"DNS zone transfer enabled\",\"phase\":\"dns\"}" \
            "$dns_dir/findings.jsonl" 2>/dev/null || true
    fi

    echo "$dns_count" > "$dns_dir/count.txt"

    py_log "INFO" "dns_phase" "Completed for $domain"
}