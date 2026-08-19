#!/bin/bash
# Combined Phase 17: OSINT & Social Intelligence
# Encompasses: theHarvester, sherock, LinkedIn dorking, email enumeration, social media intelligence
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

osint_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local osint_dir="$output_dir/osint"

    mkdir -p "$osint_dir"

    log "INFO" "Starting OSINT & social intelligence gathering for $domain"

    # theHarvester for email/OSINT
    if tool_available "theHarvester"; then
        log "INFO" "Running theHarvester..."
        theHarvester -d "$domain" -l 500 -b all 2>>"$LOGS_DIR/osint.log" >> "$osint_dir/harvester.txt" || true
    fi

    # sherock for username/credential discovery
    if tool_available "sherock"; then
        log "INFO" "Running sherock..."
        sherock -d "$domain" 2>>"$LOGS_DIR/osint.log" >> "$osint_dir/sherock.txt" || true
    fi

    # Email enumeration
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Enumerating email addresses..."
        # Common email pattern discovery
        curl -s "https://maillookup.net/$domain" 2>>"$LOGS_DIR/osint.log" >> "$osint_dir/emails.txt" || true
    fi

    # LinkedIn/Google dorking patterns (passive only)
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Running Google dork patterns..."
        # Placeholder for dork queries
        curl -s "https://www.google.com/search?q=site:linkedin.com/in/ $domain" 2>>"$LOGS_DIR/osint.log" >> "$osint_dir/dorks.txt" || true
    fi

    # Social media profile checking (username exposure)
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking for leaked social profiles..."
        # Placeholder for social media checks
        curl -s "https://sherlock-project.com/lookup/$domain" 2>>"$LOGS_DIR/osint.log" >> "$osint_dir/social.txt" || true
    fi

    # Consolidate OSINT findings
    cat "$osint_dir"/*.txt 2>/dev/null | grep -v "^$" | sort -u > "$osint_dir/consolidated.txt"

    local osint_count
    osint_count=$(wc -l < "$osint_dir/consolidated.txt" 2>/dev/null || echo 0)

    phase_log "INFO" "OSINT & social intelligence complete: $osint_count findings" "osint" "$domain"

    # Write assets
    while IFS= read -r finding; do
        [ -z "$finding" ] && continue
        write_asset "{\"type\":\"osint_finding\",\"value\":\"$finding\",\"source\":\"osint_gathering\",\"phase\":\"osint_social_intelligence\"}" \
            "$osint_dir/assets.jsonl" 2>/dev/null || true
    done < "$osint_dir/consolidated.txt"

    echo "$osint_count" > "$osint_dir/count.txt"

    write_finding "{\"type\":\"osint_gathering\",\"severity\":\"info\",\"count\":$osint_count,\"phase\":\"osint_social_intelligence\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "osint_phase" "Completed for $domain"
}