#!/bin/bash
# Combined Phase 4: URL & Endpoint Discovery
# Encompasses: waybackurls, waymore, gauplus, gospider, hakrawler, parameter discovery
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

url_endpoint_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local subdomains_file="$output_dir/subdomains/subdomains.txt"
    local crawl_dir="$output_dir/crawl"

    mkdir -p "$crawl_dir"

    log "INFO" "Starting URL & endpoint discovery for $domain"

    # waybackurls - historical URLs from Wayback Machine
    if tool_available "waybackurls"; then
        log "INFO" "Running waybackurls..."
        waybackurls "$domain" 2>>"$LOGS_DIR/waybackurls.log" >> "$crawl_dir/wayback.txt" || true
    fi

    # waymore - extended Wayback harvesting
    if tool_available "waymore"; then
        log "INFO" "Running waymore..."
        waymore -i "$domain" -oW "$crawl_dir/waymore.txt" 2>>"$LOGS_DIR/waymore.log" || true
    fi

    # gauplus - URL discovery with parameters
    if tool_available "gauplus"; then
        log "INFO" "Running gauplus..."
        gauplus -urls "$domain" 2>>"$LOGS_DIR/gauplus.log" >> "$crawl_dir/gauplus.txt" || true
    fi

    # gospider for crawler discovery
    if tool_available "gospider"; then
        log "INFO" "Running gospider..."
        gospider -s "$domain" -c 10 -d 3 -t 2>>"$LOGS_DIR/gospider.log" -o "$crawl_dir/gospider.csv" || true
    fi

    # hakrawler for simple link discovery
    if tool_available "hakrawler"; then
        log "INFO" "Running hakrawler..."
        cat "$subdomains_file" | hakrawler 2>>"$LOGS_DIR/hakrawler.log" >> "$crawl_dir/hakrawler.txt" || true
    fi

    # parameter discovery with unfurl/arjun
    if tool_available "unfurl"; then
        log "INFO" "Running unfurl parameter discovery..."
        cat "$subdomains_file" | unfurl params 2>>"$LOGS_DIR/unfurl.log" >> "$crawl_dir/param_keys.txt" || true
    fi

    # Consolidate all discovered endpoints
    cat "$crawl_dir"/*.txt 2>/dev/null | grep -v "^$" | sort -u > "$crawl_dir/endpoints.txt"

    local endpoint_count
    endpoint_count=$(wc -l < "$crawl_dir/endpoints.txt" 2>/dev/null || echo 0)

    phase_log "INFO" "URL & endpoint discovery complete: $endpoint_count endpoints found" "url_endpoints" "$domain"

    # Write assets
    while IFS= read -r endpoint; do
        [ -z "$endpoint" ] && continue
        write_asset "{\"type\":\"endpoint\",\"value\":\"$endpoint\",\"source\":\"url_discovery\",\"phase\":\"url_endpoint_discovery\"}" \
            "$crawl_dir/assets.jsonl" 2>/dev/null || true
    done < "$crawl_dir/endpoints.txt"

    echo "$endpoint_count" > "$crawl_dir/count.txt"

    py_log "INFO" "url_endpoint_phase" "Completed for $domain"
}