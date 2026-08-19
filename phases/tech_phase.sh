#!/bin/bash
# Technology fingerprinting phase

tech_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local tech_dir="$output_dir/tech"
    local live_file="$output_dir/live/httpx_results.txt"

    mkdir -p "$tech_dir"

    log "INFO" "Starting technology fingerprinting for $domain"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, skipping technology fingerprinting"
        return 1
    fi

    if tool_available "whatweb"; then
        log "INFO" "Running WhatWeb for technology detection..."
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local url
            url=$(echo "$line" | awk '{print $1}')
            whatweb "$url" 2>>"$LOGS_DIR/whatweb.log" >> "$tech_dir/whatweb.txt" || true
        done < <(head -50 "$live_file")
    fi

    if tool_available "wappalyzer"; then
        log "INFO" "Running Wappalyzer..."
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local url
            url=$(echo "$line" | awk '{print $1}')
            wappalyzer "$url" 2>>"$LOGS_DIR/wappalyzer.log" >> "$tech_dir/wappalyzer.txt" || true
        done < <(head -50 "$live_file")
    fi

    if tool_available "builtwith"; then
        log "INFO" "Running BuiltWith..."
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local url
            url=$(echo "$line" | awk '{print $1}')
            builtwith "$url" 2>>"$LOGS_DIR/builtwith.log" >> "$tech_dir/builtwith.txt" || true
        done < <(head -50 "$live_file")
    fi

    if tool_available "shodan"; then
        log "INFO" "Querying Shodan for technology data..."
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local ip
            ip=$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
            [ -z "$ip" ] && continue
            shodan host "$ip" 2>>"$LOGS_DIR/shodan.log" >> "$tech_dir/shodan.txt" || true
        done < <(head -20 "$live_file")
    fi

    local tech_count
    tech_count=$(wc -l < "$tech_dir/whatweb.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "Technology fingerprinting complete: $tech_count results" "tech" "$domain"

    # Write assets for discovered technologies
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local tech_name=$(echo "$line" | grep -oE '\[[^]]+\]' | head -1 | tr -d '[]')
        local url=$(echo "$line" | awk '{print $1}')
        
        if [ -n "$tech_name" ] && [ -n "$url" ]; then
            write_asset "{\"type\":\"technology\",\"name\":\"$tech_name\",\"url\":\"$url\",\"source\":\"whatweb\",\"phase\":\"tech\"}" \
                "$tech_dir/assets.jsonl" 2>/dev/null || true
        fi
    done < "$tech_dir/whatweb.txt" 2>/dev/null

    # Check for outdated technologies (findings)
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if echo "$line" | grep -qiE "apache/2\.[0-3]|nginx/1\.[0-17]|php/[5-7]\.[0-3]"; then
            write_finding "{\"type\":\"outdated_tech\",\"severity\":\"medium\",\"description\":\"Potentially outdated technology detected\",\"details\":\"$(echo "$line" | head -c 200)\",\"phase\":\"tech\"}" \
                "$tech_dir/findings.jsonl" 2>/dev/null || true
        fi
    done < "$tech_dir/whatweb.txt" 2>/dev/null

    echo "$tech_count" > "$tech_dir/count.txt"

    py_log "INFO" "tech_phase" "Completed for $domain"
}