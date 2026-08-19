#!/bin/bash
# SSL/TLS analysis phase

ssl_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local ssl_dir="$output_dir/ssl"
    local live_file="$output_dir/live/live_subdomains.txt"

    mkdir -p "$ssl_dir"

    log "INFO" "Starting SSL/TLS analysis for $domain"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, skipping SSL analysis"
        return 1
    fi

    if tool_available "sslyze"; then
        log "INFO" "Running sslyze for SSL/TLS analysis..."
        while IFS= read -r sub; do
            [ -z "$sub" ] && continue
            sslyze --fast --jsonfile "$ssl_dir/sslyze_$(echo "$sub" | sed 's|https\?://||g' | sed 's|/|_|g').json" "$sub" 2>>"$LOGS_DIR/sslyze.log" || true
        done < <(head -10 "$live_file")
    fi

    if tool_available "testssl"; then
        log "INFO" "Running testssl for SSL/TLS analysis..."
        while IFS= read -r sub; do
            [ -z "$sub" ] && continue
            testssl --fast --jsonfile "$ssl_dir/testssl_$(echo "$sub" | sed 's|https\?://||g' | sed 's|/|_|g').json" "$sub" 2>>"$LOGS_DIR/testssl.log" || true
        done < <(head -10 "$live_file")
    fi

    if command -v openssl >/dev/null 2>&1; then
        log "INFO" "Running OpenSSL certificate checks..."
        while IFS= read -r sub; do
            [ -z "$sub" ] && continue
            echo "=== $sub ===" >> "$ssl_dir/openssl_cert.txt"
            echo | openssl s_client -servername "$sub" -connect "$sub:443" 2>/dev/null | \
                openssl x509 -noout -text 2>/dev/null >> "$ssl_dir/openssl_cert.txt" || true
        done < <(head -10 "$live_file")
    fi

    local ssl_count
    ssl_count=$(wc -l < "$ssl_dir/sslyze_results.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "SSL/TLS analysis complete: $ssl_count results" "ssl" "$domain"

    # Write findings for SSL/TLS issues
    for json_file in "$ssl_dir"/sslyze_*.json; do
        [ -f "$json_file" ] || continue
        local host=$(basename "$json_file" | sed 's/sslyze_//;s/\.json//;s/_/\//g')
        
        # Check for SSL/TLS vulnerabilities
        if grep -q "SSL vulnerabilities" "$json_file" 2>/dev/null; then
            write_finding "{\"type\":\"ssl_vulnerability\",\"severity\":\"high\",\"host\":\"$host\",\"details\":\"SSL vulnerability detected\",\"phase\":\"ssl\"}" \
                "$ssl_dir/findings.jsonl" 2>/dev/null || true
        fi
        
        # Check for weak cipher suites
        if grep -q "weak_cipher" "$json_file" 2>/dev/null; then
            write_finding "{\"type\":\"weak_cipher\",\"severity\":\"medium\",\"host\":\"$host\",\"details\":\"Weak cipher suite detected\",\"phase\":\"ssl\"}" \
                "$ssl_dir/findings.jsonl" 2>/dev/null || true
        fi
    done

    # Write assets for certificates
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if echo "$line" | grep -q "subject:"; then
            local subject=$(echo "$line" | sed 's/.*subject: //')
            write_asset "{\"type\":\"certificate\",\"subject\":\"$subject\",\"phase\":\"ssl\"}" \
                "$ssl_dir/assets.jsonl" 2>/dev/null || true
        fi
    done < "$ssl_dir/openssl_cert.txt" 2>/dev/null

    echo "$ssl_count" > "$ssl_dir/count.txt"

    py_log "INFO" "ssl_phase" "Completed for $domain"
}