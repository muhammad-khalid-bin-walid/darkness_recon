#!/usr/bin/env bash
# DNS Checks Phase - DNS security and misconfiguration analysis
set -euo pipefail

dns_checks_phase() {
    local domain="$1"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/dns_checks"
    mkdir -p "$phase_dir"

    log "INFO" "[dns_checks] Starting DNS checks for $domain"
    py_log "phase_start" "dns_checks" "$domain"

    local count=0

    # DNS zone transfer attempt (passive - from public resolvers)
    log "INFO" "[dns_checks] Attempting DNS zone transfer (passive)"
    local ns_servers
    ns_servers=$(dig +short NS "$domain" 2>/dev/null)
    for ns in $ns_servers; do
        ns="${ns%.}"
        log "INFO" "[dns_checks] Testing zone transfer against $ns"
        dig AXFR "$domain" "@${ns}" 2>/dev/null >> "$phase_dir/zone_transfer.txt" || true
    done

    # DNS misconfiguration checks
    log "INFO" "[dns_checks] Checking DNS misconfigurations"
    # Wildcard DNS
    dig +short "randomtest12345.${domain}" A 2>/dev/null >> "$phase_dir/misconfigs.txt" || true
    # Null MX
    dig +short "$domain" MX 2>/dev/null > "$phase_dir/mx_records.txt" || true
    # SPF check
    dig +short "$domain" TXT 2>/dev/null | grep -i spf > "$phase_dir/spf_records.txt" || true
    # DMARC check
    dig +short "_dmarc.${domain}" TXT 2>/dev/null > "$phase_dir/dmarc_records.txt" || true
    # DKIM selectors
    for selector in default google selector1 selector2 s1 s2 dkim mail; do
        dig +short "${selector}._domainkey.${domain}" TXT 2>/dev/null \
            >> "$phase_dir/dkim_records.txt" || true
    done
    # CAA records
    dig +short "$domain" CAA 2>/dev/null > "$phase_dir/caa_records.txt" || true

    # DNSSEC validation
    log "INFO" "[dns_checks] Checking DNSSEC status"
    dig +dnssec +short "$domain" DNSKEY 2>/dev/null > "$phase_dir/dnssec_keys.txt" || true
    if [[ -s "$phase_dir/dnssec_keys.txt" ]]; then
        echo "DNSSEC: ENABLED" > "$phase_dir/dnssec_status.txt"
    else
        echo "DNSSEC: DISABLED" > "$phase_dir/dnssec_status.txt"
    fi

    # Analyze DMARC policy
    local dmarc_policy
    dmarc_policy=$(cat "$phase_dir/dmarc_records.txt" 2>/dev/null)
    if [[ -z "$dmarc_policy" ]]; then
        echo "DMARC: MISSING" >> "$phase_dir/dnssec_status.txt"
    elif echo "$dmarc_policy" | grep -q "p=none"; then
        echo "DMARC: WEAK (p=none)" >> "$phase_dir/dnssec_status.txt"
    else
        echo "DMARC: PRESENT" >> "$phase_dir/dnssec_status.txt"
    fi

    # Analyze SPF
    local spf_record
    spf_record=$(cat "$phase_dir/spf_records.txt" 2>/dev/null)
    if [[ -z "$spf_record" ]]; then
        echo "SPF: MISSING" >> "$phase_dir/dnssec_status.txt"
    else
        echo "SPF: PRESENT" >> "$phase_dir/dnssec_status.txt"
    fi

    # Write misconfigurations found
    local misconfig_count=0
    [[ -z "$dmarc_policy" ]] && echo "Missing DMARC record" >> "$phase_dir/misconfigs_summary.txt" && ((misconfig_count++))
    [[ -z "$spf_record" ]] && echo "Missing SPF record" >> "$phase_dir/misconfigs_summary.txt" && ((misconfig_count++))
    grep -q "p=none" <<< "$dmarc_policy" 2>/dev/null && echo "Weak DMARC policy (p=none)" >> "$phase_dir/misconfigs_summary.txt" && ((misconfig_count++))
    [[ -s "$phase_dir/zone_transfer.txt" ]] && echo "Zone transfer possible" >> "$phase_dir/misconfigs_summary.txt" && ((misconfig_count++))

    # Combine DNS misconfig outputs
    cat "$phase_dir/misconfigs.txt" "$phase_dir/misconfigs_summary.txt" 2>/dev/null \
        | sort -u > "$phase_dir/dns_misconfigs.txt" || true

    count=$misconfig_count
    echo "$count" > "$phase_dir/count.txt"

    write_finding "$domain" "dns_checks" "warning" \
        "Found $count DNS misconfigurations" || true

    log "INFO" "[dns_checks] Complete: $count misconfigurations found"
    py_log "phase_complete" "dns_checks" "$domain" "count=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    dns_checks_phase "${1:?Usage: dns_checks_phase <domain>}"
fi
