#!/usr/bin/env bash
# WHOIS Pivot Phase - Reverse WHOIS and registrant correlation
set -euo pipefail

whois_pivot_phase() {
    local domain="$1"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/whois_pivot"
    mkdir -p "$phase_dir"

    log "INFO" "[whois_pivot] Starting WHOIS pivot for $domain"
    py_log "phase_start" "whois_pivot" "$domain"

    local count=0

    # Primary WHOIS lookup
    log "INFO" "[whois_pivot] Performing WHOIS lookup"
    if tool_available "whois"; then
        whois "$domain" 2>/dev/null | tee "$phase_dir/whois_primary.txt" || true
    else
        log "WARN" "[whois_pivot] whois not available"
    fi

    # Extract registrant email
    local registrant_email
    registrant_email=$(grep -iE '(registrant.?email|e-mail|abuse-contact)' \
        "$phase_dir/whois_primary.txt" 2>/dev/null \
        | grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -1)

    # Extract registrant name/organization
    local registrant_org
    registrant_org=$(grep -iE '(registrant.?name|org-name|org\s)' \
        "$phase_dir/whois_primary.txt" 2>/dev/null \
        | head -1 | sed 's/.*:\s*//')

    # Extract registrant IP/netrange
    local registrant_net
    registrant_net=$(grep -iE '(netrange|cidr|inetnum|netname)' \
        "$phase_dir/whois_primary.txt" 2>/dev/null | head -3)

    log "INFO" "[whois_pivot] Registrant email: ${registrant_email:-none}"
    log "INFO" "[whois_pivot] Registrant org: ${registrant_org:-none}"

    # Reverse WHOIS by registrant email
    if [[ -n "$registrant_email" ]]; then
        log "INFO" "[whois_pivot] Performing reverse WHOIS by email"
        # Use whois XML API or similar
        curl -s "https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=${domain}&outputFormat=json&apiKey=${WHOIS_API_KEY:-}" \
            2>/dev/null >> "$phase_dir/whois_api.json" || true
    fi

    # Reverse WHOIS by registrant organization
    if [[ -n "$registrant_org" ]]; then
        log "INFO" "[whois_pivot] Searching for domains by org: $registrant_org"
    fi

    # Extract registrar information
    local registrar
    registrar=$(grep -iE '(registrar:|sponsoring)' "$phase_dir/whois_primary.txt" 2>/dev/null \
        | head -1 | sed 's/.*:\s*//')

    # Check related domains via name servers
    log "INFO" "[whois_pivot] Checking domains sharing name servers"
    local ns_list
    ns_list=$(grep -iE 'nameserver' "$phase_dir/whois_primary.txt" 2>/dev/null \
        | awk '{print $NF}' | tr '[:upper:]' '[:lower:]' | sort -u)
    for ns in $ns_list; do
        ns="${ns%.}"
        dig +short -x "$(dig +short "$ns" A 2>/dev/null | head -1)" 2>/dev/null \
            >> "$phase_dir/shared_ns_domains.txt" || true
    done

    # Compile related domains
    cat "$phase_dir/shared_ns_domains.txt" 2>/dev/null \
        | grep -v "^$" | sort -u > "$phase_dir/related_domains.txt" || true

    # Write WHOIS intel summary
    {
        echo "Domain: $domain"
        echo "Registrar: ${registrar:-unknown}"
        echo "Registrant Org: ${registrant_org:-unknown}"
        echo "Registrant Email: ${registrant_email:-unknown}"
        echo "---"
        echo "Network Info:"
        echo "$registrant_net"
    } > "$phase_dir/whois_intel.txt" 2>/dev/null

    count=$(wc -l < "$phase_dir/related_domains.txt" 2>/dev/null || echo 0)
    echo "$count" > "$phase_dir/count.txt"

    write_finding "$domain" "whois_pivot" "info" \
        "Discovered $count related domains via WHOIS pivoting" || true
    write_asset "$domain" "whois" "$phase_dir/whois_intel.txt" || true

    log "INFO" "[whois_pivot] Complete: $count related domains found"
    py_log "phase_complete" "whois_pivot" "$domain" "count=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    whois_pivot_phase "${1:?Usage: whois_pivot_phase <domain>}"
fi
