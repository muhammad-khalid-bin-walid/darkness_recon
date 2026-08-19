#!/bin/bash
# Combined Phase 1: Subdomain & Asset Enumeration
# Encompasses: subdomain_phase, dns_phase, amass, findomain, assetfinder, subfinder, sublist3r, crt.sh queries
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

subdomain_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local subdomains_file="$output_dir/subdomains/subdomains.txt"
    local cache_dir="$CACHE_DIR/subdomains"

    mkdir -p "$output_dir/subdomains" "$cache_dir"

    log "INFO" "Starting subdomain enumeration for $domain"

    local all_subs="$cache_dir/all_subs.txt"
    : > "$all_subs"

    # subfinder
    if tool_available "subfinder"; then
        log "INFO" "Running subfinder..."
        subfinder -d "$domain" -silent -o "$cache_dir/subfinder.txt" 2>>"$LOGS_DIR/subfinder.log" || true
        [ -f "$cache_dir/subfinder.txt" ] && cat "$cache_dir/subfinder.txt" >> "$all_subs"
    fi

    # assetfinder
    if tool_available "assetfinder"; then
        log "INFO" "Running assetfinder..."
        assetfinder --subs-only "$domain" 2>>"$LOGS_DIR/assetfinder.log" >> "$cache_dir/assetfinder.txt" || true
        [ -f "$cache_dir/assetfinder.txt" ] && cat "$cache_dir/assetfinder.txt" >> "$all_subs"
    fi

    # findomain
    if tool_available "findomain"; then
        log "INFO" "Running findomain..."
        findomain -t "$domain" -q 2>>"$LOGS_DIR/findomain.log" >> "$cache_dir/findomain.txt" || true
        [ -f "$cache_dir/findomain.txt" ] && cat "$cache_dir/findomain.txt" >> "$all_subs"
    fi

    # crt.sh
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying crt.sh..."
        curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>>"$LOGS_DIR/crtsh.log" | \
            jq -r '.[].name_value' 2>/dev/null | \
            grep -E "^[a-zA-Z0-9.-]+\.$domain$" | sort -u >> "$cache_dir/crtsh.txt" 2>/dev/null || true
        [ -f "$cache_dir/crtsh.txt" ] && cat "$cache_dir/crtsh.txt" >> "$all_subs"
    fi

    # sublist3r
    if tool_available "sublist3r"; then
        log "INFO" "Running sublist3r..."
        sublist3r -d "$domain" -o "$cache_dir/sublist3r.txt" -t "$THREADS" -n 2>>"$LOGS_DIR/sublist3r.log" || true
        [ -f "$cache_dir/sublist3r.txt" ] && cat "$cache_dir/sublist3r.txt" >> "$all_subs"
    fi

    # amass
    if tool_available "amass"; then
        log "INFO" "Running amass enum..."
        amass enum -passive -d "$domain" -o "$cache_dir/amass.txt" -timeout 10 2>>"$LOGS_DIR/amass.log" || true
        [ -f "$cache_dir/amass.txt" ] && cat "$cache_dir/amass.txt" >> "$all_subs"
    fi

    # Deduplicate and write
    sort -u "$all_subs" | grep -E "^[a-zA-Z0-9.-]+\.$domain$" | anew "$subdomains_file" 2>/dev/null || \
        sort -u "$all_subs" | grep -E "^[a-zA-Z0-9.-]+\.$domain$" > "$subdomains_file"

    local sub_count
    sub_count=$(wc -l < "$subdomains_file" 2>/dev/null || echo 0)

    phase_log "INFO" "Subdomain enumeration complete: $sub_count subdomains found" "subdomains" "$domain"

    # Write assets
    while IFS= read -r sub; do
        [ -z "$sub" ] && continue
        write_asset "{\"type\":\"subdomain\",\"value\":\"$sub\",\"source\":\"subdomain_enum\",\"phase\":\"subdomain_asset_enumeration\"}" \
            "$output_dir/subdomains/assets.jsonl" 2>/dev/null || true
    done < "$subdomains_file"

    echo "$sub_count" > "$output_dir/subdomains/count.txt"

    write_finding "{\"type\":\"subdomain_enum\",\"severity\":\"info\",\"count\":$sub_count,\"phase\":\"subdomain_asset_enumeration\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "subdomain_phase" "Completed for $domain"
}