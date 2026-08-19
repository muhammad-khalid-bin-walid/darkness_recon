#!/bin/bash
# Live host detection phase

live_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local live_dir="$output_dir/live"
    local subdomains_file="$output_dir/subdomains/subdomains.txt"

    mkdir -p "$live_dir"

    log "INFO" "Starting live host detection for $domain"

    if [ ! -f "$subdomains_file" ]; then
        log "WARN" "No subdomains file found, skipping live host detection"
        return 1
    fi

    if tool_available "httpx"; then
        log "INFO" "Running httpx for live host detection..."
        httpx -l "$subdomains_file" -silent -status-code -content-length -server -tech-detect \
            -follow-redirects -timeout 10 -retries 2 \
            -o "$live_dir/httpx_results.txt" 2>>"$LOGS_DIR/httpx.log" || true
    fi

    if tool_available "whatweb"; then
        log "INFO" "Running WhatWeb for technology fingerprinting..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            whatweb "$url" 2>>"$LOGS_DIR/whatweb.log" >> "$live_dir/whatweb.txt" || true
        done < <(head -50 "$subdomains_file")
    fi

    if tool_available "nmap"; then
        log "INFO" "Running nmap for service detection..."
        nmap -sV -T4 --top-ports 1000 -iL "$subdomains_file" \
            -oN "$live_dir/nmap_results.txt" 2>>"$LOGS_DIR/nmap.log" || true
    fi

    if [ -f "$live_dir/httpx_results.txt" ]; then
        local live_count
        live_count=$(wc -l < "$live_dir/httpx_results.txt" 2>/dev/null || echo 0)
        
        phase_log "INFO" "Live host detection complete: $live_count live hosts found" "live" "$domain"

        # Write assets for live hosts
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local url=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)
            local status=$(echo "$line" | grep -oE '\[[0-9]+\]' | tr -d '[]')
            local tech=$(echo "$line" | grep -oE 'server: [^ ]+' | cut -d' ' -f2)
            
            if [ -n "$url" ]; then
                write_asset "{\"type\":\"live_host\",\"url\":\"$url\",\"status\":\"${status:-unknown}\",\"tech\":\"${tech:-unknown}\",\"phase\":\"live\"}" \
                    "$live_dir/assets.jsonl" 2>/dev/null || true
                
                # Write endpoint for each live host
                write_endpoint "{\"url\":\"$url\",\"method\":\"GET\",\"status\":${status:-0},\"phase\":\"live\"}" \
                    "$live_dir/endpoints.jsonl" 2>/dev/null || true
            fi
        done < "$live_dir/httpx_results.txt"

        echo "$live_count" > "$live_dir/count.txt"
    else
        log "WARN" "No live hosts detected"
        echo 0 > "$live_dir/count.txt"
    fi

    write_finding "{\"type\":\"live_hosts\",\"severity\":\"info\",\"count\":$live_count,\"phase\":\"live\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "live_phase" "Completed for $domain"
}