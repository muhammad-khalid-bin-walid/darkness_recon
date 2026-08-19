#!/usr/bin/env bash
# DNS Provider API Exposure & Key Leakage Detection
# Checks for exposed DNS management APIs, API key leakage, zone manipulation

dns_api_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "dns_api_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/dns_api"
    mkdir -p "$phase_dir"

    log "INFO" "Starting dns_api_phase for $domain"

    local dns_api_vulns="$phase_dir/dns_api_vulns.txt"
    local dns_api_keys="$phase_dir/dns_api_keys.txt"
    local count=0

    # --- Check common DNS API endpoints ---
    log "INFO" "Probing DNS provider API endpoints..."

    local api_endpoints=(
        "https://api.cloudflare.com/client/v4/zones?name=$domain"
        "https://api.digitalocean.com/v2/domains/$domain"
        "https://route53.amazonaws.com/2013-04-01/hostedzone"
        "https://dns.google/v2/domains/$domain"
        "https://api.godaddy.com/v1/domains/$domain"
        "https://api.namecheap.com/xml.response"
        "https://api.ns1.com/v2/zones/$domain"
        "https://dnsimple.com/v2/$domain"
        "https://api.gcloud.com/dns/v1/zones"
    )

    for endpoint in "${api_endpoints[@]}"; do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$endpoint" 2>/dev/null) || true
        if [[ "$http_code" != "000" ]] && [[ "$http_code" != "404" ]]; then
            echo "[VULN] DNS API endpoint accessible: $endpoint (HTTP $http_code)" >> "$dns_api_vulns"
            ((count++)) || true
        fi
    done

    # --- Check for exposed DNS API keys in source code / common files ---
    log "INFO" "Checking for leaked DNS API keys..."

    local api_key_patterns=(
        "CF_API_KEY|CLOUDFLARE_API_KEY|CF_TOKEN"
        "DO_API_TOKEN|DIGITALOCEAN_TOKEN"
        "AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY"
        "GODADDY_API_KEY|GODADDY_API_SECRET"
        "NS1_API_KEY|NS1_ZONE_KEY"
        "DNSIMPLE_TOKEN"
        "NAMECHEAP_API_USER|NAMECHEAP_API_KEY"
    )

    # Check common exposed paths for API keys
    local key_paths=(
        "/.env"
        "/wp-config.php.bak"
        "/config.php.bak"
        "/.git/config"
        "/server-status"
        "/server-info"
        "/phpinfo.php"
        "/info.php"
    )

    for path in "${key_paths[@]}"; do
        local response
        response=$(curl -s -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ -n "$response" ]]; then
            for pattern in "${api_key_patterns[@]}"; do
                if echo "$response" | grep -qiE "$pattern"; then
                    echo "[VULN] DNS API key potentially exposed at $path" >> "$dns_api_vulns"
                    echo "$path: $(echo "$response" | grep -oiE "$pattern=[^\"' ]+" | head -3)" >> "$dns_api_keys"
                    ((count++)) || true
                fi
            done
        fi
    done

    # --- Check DNS zone transfer ---
    log "INFO" "Testing DNS zone transfer..."
    local ns_records
    ns_records=$(dig +short "$domain" NS 2>/dev/null) || true
    while IFS= read -r ns; do
        [[ -z "$ns" ]] && continue
        ns=$(echo "$ns" | sed 's/\.$//')
        local zone_result
        zone_result=$(timeout 10 dig @"$ns" "$domain" AXFR 2>/dev/null) || true
        if echo "$zone_result" | grep -qi "ANSWER SECTION"; then
            echo "[VULN] Zone transfer allowed from $ns" >> "$dns_api_vulns"
            echo "$zone_result" | head -50 >> "$phase_dir/zone_transfer_$ns.txt"
            ((count++)) || true
        fi
    done <<< "$ns_records"

    # --- Check for DNS-over-HTTPS exposure ---
    local doh_endpoints=(
        "https://dns.google/resolve?name=$domain&type=ANY"
        "https://cloudflare-dns.com/dns-query?name=$domain&type=ANY"
        "https://dns.quad9.net/dns-query?name=$domain&type=ANY"
    )

    for endpoint in "${doh_endpoints[@]}"; do
        local doh_resp
        doh_resp=$(curl -s -m 5 -H "accept: application/dns-json" "$endpoint" 2>/dev/null) || true
        if [[ -n "$doh_resp" ]] && echo "$doh_resp" | grep -q '"Answer"'; then
            echo "[CONFIG] DoH response from $endpoint reveals zone data" >> "$dns_api_vulns"
            ((count++)) || true
        fi
    done

    # --- Check DNSSEC status ---
    local dnssec
    dnssec=$(dig +dnssec "$domain" +short 2>/dev/null) || true
    if [[ -z "$dnssec" ]]; then
        echo "[VULN] DNSSEC not enabled - zone data can be forged" >> "$dns_api_vulns"
        ((count++)) || true
    fi

    # --- Write structured findings ---
    if [[ -f "$dns_api_vulns" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "dns_api" "" "" ""
        done < "$dns_api_vulns"
    fi

    if [[ -f "$dns_api_keys" ]]; then
        while IFS= read -r key_entry; do
            write_finding "$phase_dir" "$key_entry" "dns_api" "" "" ""
        done < "$dns_api_keys"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "dns_api_phase" "domain=$domain findings=$count"

    log "INFO" "dns_api_phase complete: $count findings"
    return 0
}

dns_api_phase "$@"
