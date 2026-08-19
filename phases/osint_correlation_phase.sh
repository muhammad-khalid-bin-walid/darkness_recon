#!/usr/bin/env bash
# OSINT Correlation Phase - Passive OSINT intelligence gathering
set -euo pipefail

osint_correlation_phase() {
    local domain="$1"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/osint_correlation"
    mkdir -p "$phase_dir"

    log "INFO" "[osint_correlation] Starting OSINT correlation for $domain"
    py_log "phase_start" "osint_correlation" "$domain"

    local count=0

    # SpiderFoot automated OSINT
    if tool_available "sf"; then
        log "INFO" "[osint_correlation] Running SpiderFoot"
        sf -s "$domain" -o JSON 2>/dev/null \
            | tee "$phase_dir/spiderfoot_raw.json" || true
    else
        log "WARN" "[osint_correlation] SpiderFoot not available"
    fi

    # theHarvester for email and subdomain discovery
    if tool_available "theHarvester"; then
        log "INFO" "[osint_correlation] Running theHarvester"
        theHarvester -d "$domain" -b all 2>/dev/null \
            | tee "$phase_dir/harvester_raw.txt" || true
    else
        log "WARN" "[osint_correlation] theHarvester not available"
    fi

    # GitHub dorks for exposed secrets
    log "INFO" "[osint_correlation] Checking GitHub dorks"
    local dorks=(
        "\"${domain}\" password"
        "\"${domain}\" api_key"
        "\"${domain}\" secret"
        "\"${domain}\" credentials"
        "\"${domain}\" config"
        "\"${domain}\" .env"
        "\"${domain}\" DATABASE_URL"
    )
    for dork in "${dorks[@]}"; do
        curl -sH "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/search/code?q=${dork// /+}" \
            2>/dev/null >> "$phase_dir/github_dorks.json" || true
    done

    # Pastebin scraping via search
    log "INFO" "[osint_correlation] Searching Pastebin for leaked data"
    curl -sL "https://www.google.com/search?q=site:pastebin.com+\"${domain}\"" \
        -H "User-Agent: Mozilla/5.0" 2>/dev/null \
        | grep -oP 'https://pastebin\.com/[a-zA-Z0-9]+' \
        | sort -u > "$phase_dir/pastebin_urls.txt" || true

    # Extract emails from harvester output
    log "INFO" "[osint_correlation] Extracting email addresses"
    grep -oiP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
        "$phase_dir/harvester_raw.txt" 2>/dev/null \
        | grep -i "$domain" | sort -u > "$phase_dir/email_addresses.txt" || true

    # Parse SpiderFoot JSON for findings
    if [[ -f "$phase_dir/spiderfoot_raw.json" ]]; then
        python3 -c "
import json, sys
try:
    data = json.load(open('$phase_dir/spiderfoot_raw.json'))
    for item in data:
        if 'data' in item:
            print(item['data'])
except: pass
" >> "$phase_dir/spiderfoot_parsed.txt" 2>/dev/null || true
    fi

    # Combine all OSINT intel
    cat "$phase_dir/harvester_raw.txt" "$phase_dir/spiderfoot_parsed.txt" \
        "$phase_dir/github_dorks.json" "$phase_dir/pastebin_urls.txt" \
        2>/dev/null | sort -u > "$phase_dir/osint_intel.txt" || true

    # Extract exposed data patterns (API keys, tokens, etc.)
    grep -oiE '(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{48}|xox[bpsar]-[a-zA-Z0-9-]+)' \
        "$phase_dir/osint_intel.txt" 2>/dev/null \
        | sort -u > "$phase_dir/exposed_data.txt" || true

    count=$(wc -l < "$phase_dir/osint_intel.txt" 2>/dev/null || echo 0)
    echo "$count" > "$phase_dir/count.txt"

    write_finding "$domain" "osint_correlation" "info" \
        "Gathered $count OSINT intel entries" || true

    log "INFO" "[osint_correlation] Complete: $count OSINT entries found"
    py_log "phase_complete" "osint_correlation" "$domain" "count=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    osint_correlation_phase "${1:?Usage: osint_correlation_phase <domain>}"
fi
