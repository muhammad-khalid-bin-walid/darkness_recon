#!/bin/bash
# Service enumeration phase

service_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local service_dir="$output_dir/service"
    local live_file="$output_dir/live/live_subdomains.txt"

    mkdir -p "$service_dir"

    log "INFO" "Starting service enumeration for $domain"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, skipping service enumeration"
        return 1
    fi

    if tool_available "whatweb"; then
        log "INFO" "Running WhatWeb for service detection..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            whatweb "$url" 2>>"$LOGS_DIR/whatweb.log" >> "$service_dir/whatweb_results.txt" || true
        done < <(head -20 "$live_file")
    fi

    if tool_available "wpscan" && command -v wp >/dev/null 2>&1; then
        log "INFO" "Running WPScan for WordPress enumeration..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            wpscan --url "$url" --enumerate u,vt,vp,tt,cb,dbe --api-token "${WPSCAN_API_TOKEN:-}" \
                --format json --output "$service_dir/wpscan_$(echo "$url" | sed 's|https\?://||g' | sed 's|/|_|g').json" 2>>"$LOGS_DIR/wpscan.log" || true
        done < <(head -5 "$live_file")
    fi

    if tool_available "joomscan" && command -v joomla >/dev/null 2>&1; then
        log "INFO" "Running JoomScan for Joomla enumeration..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            joomscan -u "$url" --enumerate-components --enumerate-modules --enumerate-templates \
                -o "$service_dir/joomscan_$(echo "$url" | sed 's|https\?://||g' | sed 's|/|_|g').txt" 2>>"$LOGS_DIR/joomscan.log" || true
        done < <(head -5 "$live_file")
    fi

    if tool_available "retire"; then
        log "INFO" "Running Retire.js for JavaScript library scanning..."
        if [ -f "$output_dir/crawl/js_files.txt" ]; then
            while IFS= read -r js_url; do
                [ -z "$js_url" ] && continue
                retire --path "$js_url" --outputformat json --outputpath "$service_dir/retire_$(echo "$js_url" | sed 's|https\?://||g' | sed 's|/|_|g').json" 2>>"$LOGS_DIR/retire.log" || true
            done < <(head -10 "$output_dir/crawl/js_files.txt")
        fi
    fi

    if tool_available "cmseek"; then
        log "INFO" "Running CMSeeK for CMS detection..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            cmseek -u "$url" --batch -o "$service_dir/cmseek_$(echo "$url" | sed 's|https\?://||g' | sed 's|/|_|g')" 2>>"$LOGS_DIR/cmseek.log" || true
        done < <(head -10 "$live_file")
    fi

    local service_count
    service_count=$(wc -l < "$service_dir/whatweb_results.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "Service enumeration complete: $service_count results" "service" "$domain"

    # Write assets for discovered services
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local service_name=$(echo "$line" | grep -oE '\[[^]]+\]' | head -1 | tr -d '[]')
        local url=$(echo "$line" | awk '{print $1}')
        
        if [ -n "$service_name" ] && [ -n "$url" ]; then
            write_asset "{\"type\":\"service\",\"name\":\"$service_name\",\"url\":\"$url\",\"phase\":\"service\"}" \
                "$service_dir/assets.jsonl" 2>/dev/null || true
        fi
    done < "$service_dir/whatweb_results.txt" 2>/dev/null

    # Write findings for WordPress/Joomla detections
    for cms_file in "$service_dir"/wpscan_*.json "$service_dir"/joomscan_*.txt; do
        [ -f "$cms_file" ] || continue
        local cms_type=$(basename "$cms_file" | cut -d'_' -f1)
        write_finding "{\"type\":\"cms_detected\",\"severity\":\"info\",\"cms\":\"$cms_type\",\"phase\":\"service\"}" \
            "$service_dir/findings.jsonl" 2>/dev/null || true
    done

    echo "$service_count" > "$service_dir/count.txt"

    py_log "INFO" "service_phase" "Completed for $domain"
}