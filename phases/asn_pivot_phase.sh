#!/usr/bin/env bash
# ASN Pivot Phase - Discover all IP ranges owned by the target's ASN
set -euo pipefail

asn_pivot_phase() {
    local domain="$1"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/asn_pivot"
    mkdir -p "$phase_dir"

    log "INFO" "[asn_pivot] Starting ASN pivot for $domain"
    py_log "phase_start" "asn_pivot" "$domain"

    local count=0

    # Discover ASN via amass intel
    if tool_available "amass"; then
        log "INFO" "[asn_pivot] Running amass intel for ASN discovery"
        amass intel -active -asn -d "$domain" 2>/dev/null \
            | tee "$phase_dir/asn_raw.txt" || true
    else
        log "WARN" "[asn_pivot] amass not available, skipping"
    fi

    # Query BGP.he.net via curl
    log "INFO" "[asn_pivot] Querying bgp.he.net for ASN data"
    local asn_list
    asn_list=$(grep -oP 'AS\d+' "$phase_dir/asn_raw.txt" 2>/dev/null || true)
    for asn in $asn_list; do
        curl -sL "https://bgp.he.net/${asn}?format=txt" \
            >> "$phase_dir/bgp_raw.txt" 2>/dev/null || true
    done

    # Whois on discovered ASNs
    if tool_available "whois"; then
        log "INFO" "[asn_pivot] Running whois on discovered ASNs"
        while IFS= read -r asn; do
            [[ -z "$asn" ]] && continue
            whois "$asn" 2>/dev/null >> "$phase_dir/whois_asn.txt" || true
        done <<< "$asn_list"
    fi

    # Map CIDR ranges
    if tool_available "mapcidr"; then
        log "INFO" "[asn_pivot] Expanding CIDR ranges with mapcidr"
        grep -oP '\d+\.\d+\.\d+\.\d+/\d+' "$phase_dir/bgp_raw.txt" 2>/dev/null \
            | mapcidr 2>/dev/null >> "$phase_dir/ip_blocks_raw.txt" || true
    fi

    # Deduplicate and write outputs
    sort -u "$phase_dir/bgp_raw.txt" 2>/dev/null > "$phase_dir/asn_ranges.txt" || true
    sort -u "$phase_dir/ip_blocks_raw.txt" 2>/dev/null > "$phase_dir/ip_blocks.txt" || true

    # Extract related organizations
    grep -iE '(OrgName|org-name|descr|netname|OrgId)' "$phase_dir/whois_asn.txt" 2>/dev/null \
        | sort -u > "$phase_dir/related_orgs.txt" || true

    count=$(wc -l < "$phase_dir/ip_blocks.txt" 2>/dev/null || echo 0)
    echo "$count" > "$phase_dir/count.txt"

    write_finding "$domain" "asn_pivot" "info" \
        "Discovered $count IP blocks from ASN pivoting" || true

    log "INFO" "[asn_pivot] Complete: $count IP blocks found"
    py_log "phase_complete" "asn_pivot" "$domain" "count=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    asn_pivot_phase "${1:?Usage: asn_pivot_phase <domain>}"
fi
