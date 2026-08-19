#!/bin/bash
# OSINT intelligence gathering phase

osint_intel_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local osint_dir="$output_dir/osint"

    mkdir -p "$osint_dir"

    log "INFO" "Starting OSINT intelligence gathering for $domain"

    if command -v theHarvester >/dev/null 2>&1; then
        log "INFO" "Running theHarvester..."
        theHarvester -d "$domain" -b all -f "$osint_dir/theharvester.json" 2>>"$LOGS_DIR/theharvester.log" || true
    fi

    if command -v hunter >/dev/null 2>&1; then
        log "INFO" "Running Hunter.io for email enumeration..."
        hunter domain "$domain" --output json > "$osint_dir/hunter_emails.json" 2>>"$LOGS_DIR/hunter.log" || true
    fi

    if command -v sherlock >/dev/null 2>&1; then
        log "INFO" "Running Sherlock for social media enumeration..."
        sherlock --no-color "$domain" --output "$osint_dir/sherlock_results.txt" 2>>"$LOGS_DIR/sherlock.log" || true
    fi

    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying Google Dorking results..."
        curl -s "https://www.google.com/search?q=site:$domain" \
            -H "User-Agent: Mozilla/5.0" 2>/dev/null | \
            grep -oP 'href="[^"]*"' 2>/dev/null | sed 's/href="//;s/"//' | \
            sort -u > "$osint_dir/google_dork_results.txt" || true
    fi

    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying Shodan for host information..."
        if [ -n "${SHODAN_API_KEY:-}" ]; then
            curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=$domain" \
                2>/dev/null | jq -r '.matches[] | .ip_str' 2>/dev/null > "$osint_dir/shodan_ips.txt" || true
        fi
    fi

    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying Censys for host information..."
        if [ -n "${CENSYS_API_ID:-}" ] && [ -n "${CENSYS_API_SECRET:-}" ]; then
            curl -s -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
                "https://search.censys.io/api/v2/hosts/search?q=$domain" \
                2>/dev/null | jq -r '.result.hits[].ip' 2>/dev/null > "$osint_dir/censys_ips.txt" || true
        fi
    fi

    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying Have I Been Pwned..."
        curl -s "https://haveibeenpwned.com/api/v2/breachedaccount/$domain" \
            2>/dev/null | jq -r '.[].Name' 2>/dev/null > "$osint_dir/hibp_breaches.txt" || true
    fi

    local osint_count
    osint_count=$(find "$osint_dir" -type f -name "*.txt" -o -name "*.json" 2>/dev/null | wc -l)
    log "INFO" "OSINT intelligence gathering complete: $osint_count data sources queried"

    echo "$osint_count" > "$osint_dir/count.txt"

    write_finding "{\"type\":\"osint_intel\",\"severity\":\"info\",\"domain\":\"$domain\",\"data_sources\":$osint_count,\"phase\":\"osint_intel\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "osint_intel_phase" "Completed for $domain — $osint_count sources"
}