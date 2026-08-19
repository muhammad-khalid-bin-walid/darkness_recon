#!/bin/bash
# Combined Phase 3: Technology Fingerprinting
# Encompasses: Wappalyzer, WhatWeb, BuiltWith, WPScan, JoomScan, framework/library identification
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

tech_fingerprint_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local live_file="$output_dir/live/live_subdomains.json"
    local tech_dir="$output_dir/tech"

    mkdir -p "$tech_dir"

    log "INFO" "Starting technology fingerprinting for $domain"

    # WhatWeb fingerprinting
    if tool_available "whatweb"; then
        log "INFO" "Running WhatWeb fingerprinting..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            whatweb "$host" 2>>"$LOGS_DIR/whatweb.log" >> "$tech_dir/whatweb.txt" || true
        done < <(jq -r '.[].value' "$live_file" 2>/dev/null | head -20)
    fi

    # Wappalyzer detection
    if tool_available "wappalyzer"; then
        log "INFO" "Running Wappalyzer detection..."
        # Wappalyzer CLI or API integration
        wappalyzer "$domain" 2>>"$LOGS_DIR/wappalyzer.log" >> "$tech_dir/wappalyzer.txt" || true
    fi

    # WPScan for WordPress fingerprinting
    if tool_available "wpscan"; then
        log "INFO" "Running WPScan for WordPress..."
        wpscan --url "$domain" --enumerate u 2>>"$LOGS_DIR/wpscan.log" >> "$tech_dir/wpscan.txt" || true
    fi

    # JoomScan for Joomla fingerprinting
    if tool_available "joomscan"; then
        log "INFO" "Running Joomla fingerprinting..."
        joomscan -u "$domain" 2>>"$LOGS_DIR/joomscan.log" >> "$tech_dir/joomscan.txt" || true
    fi

    # BuiltWith alternative detection
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking HTTP headers for technology clues..."
        curl -sI "$domain" 2>>"$LOGS_DIR/header.log" | grep -E "X-Powered-By|Server|X-AspNet|X-Generator" >> "$tech_dir/headers.txt" || true
    fi

    # Deduplicate tech findings
    cat "$tech_dir"/*.txt 2>/dev/null | grep -v "^$" | sort -u > "$tech_dir/technologies.txt"

    local tech_count
    tech_count=$(wc -l < "$tech_dir/technologies.txt" 2>/dev/null || echo 0)

    phase_log "INFO" "Technology fingerprinting complete: $tech_count technologies detected" "tech_fingerprint" "$domain"

    # Write assets
    while IFS= read -r tech; do
        [ -z "$tech" ] && continue
        write_asset "{\"type\":\"technology\",\"value\":\"$tech\",\"source\":\"tech_fingerprint\",\"phase\":\"tech_fingerprinting\"}" \
            "$tech_dir/assets.jsonl" 2>/dev/null || true
    done < "$tech_dir/technologies.txt"

    echo "$tech_count" > "$tech_dir/count.txt"

    py_log "INFO" "tech_fingerprint_phase" "Completed for $domain"
}