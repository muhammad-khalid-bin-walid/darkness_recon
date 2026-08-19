#!/bin/bash
# Nuclei vulnerability scanning phase

nuclei_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local nuclei_dir="$output_dir/nuclei"
    local live_file="$output_dir/live/live_subdomains.txt"

    mkdir -p "$nuclei_dir"

    log "INFO" "Starting Nuclei vulnerability scanning for $domain"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, skipping Nuclei scanning"
        return 1
    fi

    if tool_available "nuclei"; then
        log "INFO" "Running nuclei with all templates..."
        nuclei -l "$live_file" -timeout 30 -retries 2 \
            -o "$nuclei_dir/all_results.txt" 2>>"$LOGS_DIR/nuclei.log" || true

        log "INFO" "Running nuclei critical severity templates..."
        nuclei -l "$live_file" -severity critical -timeout 30 \
            -o "$nuclei_dir/critical_results.txt" 2>>"$LOGS_DIR/nuclei.log" || true

        log "INFO" "Running nuclei high severity templates..."
        nuclei -l "$live_file" -severity high -timeout 30 \
            -o "$nuclei_dir/high_results.txt" 2>>"$LOGS_DIR/nuclei.log" || true

        log "INFO" "Running nuclei CVE templates..."
        nuclei -l "$live_file" -tags cve -timeout 30 \
            -o "$nuclei_dir/cve_results.txt" 2>>"$LOGS_DIR/nuclei.log" || true

        log "INFO" "Running nuclei vulnerability templates..."
        nuclei -l "$live_file" -tags vulnerability -timeout 30 \
            -o "$nuclei_dir/vuln_templates.txt" 2>>"$LOGS_DIR/nuclei.log" || true

        cat "$nuclei_dir/"*.txt 2>/dev/null | sort -u > "$nuclei_dir/all_vulnerabilities.txt" 2>/dev/null || true
    fi

    local vuln_count
    vuln_count=$(wc -l < "$nuclei_dir/all_vulnerabilities.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "Nuclei scanning complete: $vuln_count vulnerabilities found" "nuclei" "$domain"

    # Write findings for each vulnerability
    while IFS= read -r vuln; do
        [ -z "$vuln" ] && continue
        local severity="unknown"
        if echo "$vuln" | grep -qiE "critical"; then
            severity="critical"
        elif echo "$vuln" | grep -qiE "high"; then
            severity="high"
        elif echo "$vuln" | grep -qiE "medium"; then
            severity="medium"
        elif echo "$vuln" | grep -qiE "low"; then
            severity="low"
        fi
        
        write_finding "{\"type\":\"nuclei_vuln\",\"severity\":\"$severity\",\"details\":\"$(echo "$vuln" | head -c 500)\",\"phase\":\"nuclei\"}" \
            "$nuclei_dir/findings.jsonl" 2>/dev/null || true
    done < "$nuclei_dir/all_vulnerabilities.txt" 2>/dev/null

    echo "$vuln_count" > "$nuclei_dir/count.txt"

    py_log "INFO" "nuclei_phase" "Completed for $domain"
}