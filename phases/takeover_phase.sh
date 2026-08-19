#!/bin/bash
# Subdomain takeover detection phase

takeover_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local takeover_dir="$output_dir/takeovers"
    local subdomains_file="$output_dir/subdomains/subdomains.txt"

    mkdir -p "$takeover_dir"

    log "INFO" "Starting subdomain takeover detection for $domain"

    if [ ! -f "$subdomains_file" ]; then
        log "WARN" "No subdomains file found, skipping takeover detection"
        return 1
    fi

    if tool_available "subjack"; then
        log "INFO" "Running subjack for takeover detection..."
        subjack -w "$subdomains_file" -t "$THREADS" -timeout 10 \
            -o "$takeover_dir/subjack_results.txt" 2>>"$LOGS_DIR/subjack.log" || true
    fi

    if tool_available "subzy"; then
        log "INFO" "Running subzy for takeover detection..."
        subzy run --targets "$subdomains_file" --timeout 15 --concurrency "$THREADS" \
            --hide_fails --verify_ssl 2>>"$LOGS_DIR/subzy.log" >> "$takeover_dir/subzy_results.txt" || true
    fi

    if tool_available "nuclei"; then
        log "INFO" "Running nuclei takeover templates..."
        nuclei -l "$subdomains_file" -t takeovers -timeout 30 \
            -o "$takeover_dir/nuclei_takeovers.txt" 2>>"$LOGS_DIR/nuclei.log" || true
    fi

    if [ -f "$takeover_dir/subjack_results.txt" ]; then
        grep -i "likely" "$takeover_dir/subjack_results.txt" 2>/dev/null >> "$takeover_dir/potential_takeovers.txt" || true
    fi

    if [ -f "$takeover_dir/subzy_results.txt" ]; then
        grep -i "possible" "$takeover_dir/subzy_results.txt" 2>/dev/null >> "$takeover_dir/potential_takeovers.txt" || true
    fi

    if [ -f "$takeover_dir/nuclei_takeovers.txt" ]; then
        cat "$takeover_dir/nuclei_takeovers.txt" 2>/dev/null >> "$takeover_dir/potential_takeovers.txt" || true
    fi

    sort -u "$takeover_dir/potential_takeovers.txt" -o "$takeover_dir/potential_takeovers.txt" 2>/dev/null || true

    local takeover_count
    takeover_count=$(wc -l < "$takeover_dir/potential_takeovers.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "Subdomain takeover detection complete: $takeover_count potential takeovers found" "takeovers" "$domain"

    # Write findings for potential takeovers
    while IFS= read -r takeover; do
        [ -z "$takeover" ] && continue
        write_finding "{\"type\":\"subdomain_takeover\",\"severity\":\"high\",\"details\":\"$takeover\",\"phase\":\"takeovers\"}" \
            "$takeover_dir/findings.jsonl" 2>/dev/null || true
    done < "$takeover_dir/potential_takeovers.txt" 2>/dev/null

    echo "$takeover_count" > "$takeover_dir/count.txt"

    py_log "INFO" "takeover_phase" "Completed for $domain"
}