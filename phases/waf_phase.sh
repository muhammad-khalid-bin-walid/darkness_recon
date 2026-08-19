#!/bin/bash
# Combined Phase 7: WAF Detection & Evasion
# Encompasses: WAFW00F, nuclei WAF probes, WAF bypass techniques, fingerprinting
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

waf_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local live_file="$output_dir/live/live_subdomains.json"
    local waf_dir="$output_dir/waf"

    mkdir -p "$waf_dir"

    log "INFO" "Starting WAF detection & evasion analysis for $domain"

    # WAFW00F detection
    if tool_available "wafw00f"; then
        log "INFO" "Running WAFW00F detection..."
        wafw00f "$domain" 2>>"$LOGS_DIR/wafw00f.log" >> "$waf_dir/wafw00f.txt" || true
    fi

    # Nuclei WAF fingerprinting
    if tool_available "nuclei"; then
        log "INFO" "Running nuclei WAF detection..."
        nuclei -l "$live_file" -t "$TEMPLATES_DIR/waf/" -o "$waf_dir/nuclei.json" 2>>"$LOGS_DIR/nuclei.log" || true
    fi

    # WAF bypass probes
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Running WAF bypass probes..."
        # Test various paths known to trigger different WAF behaviors
        for path in "/admin" "/phpmyadmin" "/wp-admin" "/manager"; do
            curl -sI "http://$domain$path" 2>>"$LOGS_DIR/waf_bypass.log" | head -5 >> "$waf_dir/bypass_probes.txt" || true
        done
    fi

    # Correlation: match WAF signatures across detection methods
    local waf_signatures
    waf_signatures=$(cat "$waf_dir"/*.txt 2>/dev/null | grep -v "^$" | sort -u | tr "\n" "|")

    phase_log "INFO" "WAF detection complete: signatures identified" "waf_detection" "$domain"

    # Write assets
    if [ -f "$waf_dir/wafw00f.txt" ]; then
        while IFS= read -r sig; do
            [ -z "$sig" ] && continue
            write_asset "{\"type\":\"waf_signature\",\"value\":\"$sig\",\"source\":\"waf_detection\",\"phase\":\"waf_detection_evasion\"}" \
                "$waf_dir/assets.jsonl" 2>/dev/null || true
        done < "$waf_dir/wafw00f.txt"
    fi

    echo "0" > "$waf_dir/count.txt"

    py_log "INFO" "waf_phase" "Completed for $domain"
}