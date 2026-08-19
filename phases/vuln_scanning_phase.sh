#!/bin/bash
# Combined Phase 8: Vulnerability Scanning
# Encompasses: nuclei, dalfox, XSStrike, XSS/SQLi pattern matching phases
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

vuln_scanning_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local subdomains_file="$output_dir/subdomains/subdomains.txt"
    local vuln_dir="$output_dir/vuln"

    mkdir -p "$vuln_dir"

    log "INFO" "Starting vulnerability scanning for $domain"

    # Nuclei vulnerability scanning
    if tool_available "nuclei"; then
        log "INFO" "Running nuclei vulnerability scans..."
        nuclei -l "$subdomains_file" -t "$TEMPLATES_DIR/vuln/" -o "$vuln_dir/nuclei.json" -silent 2>>"$LOGS_DIR/nuclei.log" || true
    fi

    # Dalfox XSS scanning
    if tool_available "dalfox"; then
        log "INFO" "Running dalfox XSS scanning..."
        dalfox pipe -o "$vuln_dir/dalfox.json" < "$subdomains_file" 2>>"$LOGS_DIR/dalfox.log" || true
    fi

    # XSStrike if available
    if tool_available "xsstrike"; then
        log "INFO" "Running XSStrike..."
        xsstrike -u "$domain" 2>>"$LOGS_DIR/xsstrike.log" >> "$vuln_dir/xsstrike.txt" || true
    fi

    # correlation: merge findings from all scanners
    cat "$vuln_dir"/*.json 2>/dev/null | jq -s 'add // []' > "$vuln_dir/merged_findings.json" 2>/dev/null || true

    local vuln_count
    vuln_count=$(jq 'length' "$vuln_dir/merged_findings.json" 2>/dev/null || echo 0)

    phase_log "INFO" "Vulnerability scanning complete: $vuln_count findings identified" "vulnerability_scanning" "$domain"

    # Write assets for each vulnerability finding
    if [ -f "$vuln_dir/merged_findings.json" ]; then
        jq -r '.[] | "\(.type): \(.value)"' "$vuln_dir/merged_findings.json" 2>/dev/null | while IFS= read -r finding; do
            [ -z "$finding" ] && continue
            write_asset "{\"type\":\"vulnerability\",\"value\":$finding,\"source\":\"vuln_scanning\",\"phase\":\"vulnerability_scanning\"}" \
                "$vuln_dir/assets.jsonl" 2>/dev/null || true
        done
    fi

    echo "$vuln_count" > "$vuln_dir/count.txt"

    write_finding "{\"type\":\"vulnerability_scan\",\"severity\":\"info\",\"count\":$vuln_count,\"phase\":\"vulnerability_scanning\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "vuln_scanning_phase" "Completed for $domain"
}