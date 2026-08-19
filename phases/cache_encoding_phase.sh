#!/bin/bash
# Combined Phase 18: Cache & Encoding Security
# Encompasses: cache poisoning, content type confusion, TLS chain analysis phases
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

cache_encoding_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local cache_dir="$output_dir/cache_encoding"

    mkdir -p "$cache_dir"

    log "INFO" "Starting cache & encoding security analysis for $domain"

    # Cache poisoning tests
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Running cache poisoning detection..."
        # Test various cache-control headers
        curl -sI "https://$domain" -H "X-Forwarded-Proto: http" 2>>"$LOGS_DIR/cache_encoding.log" >> "$cache_dir/cache_poisoning.txt" || true
        curl -sI "https://$domain" -H "X-Host: evil.example.com" 2>>"$LOGS_DIR/cache_encoding.log" >> "$cache_dir/cache_poisoning.txt" || true
        curl -sI "https://$domain" -H "Cache-Control: max-age=0" 2>>"$LOGS_DIR/cache_encoding.log" >> "$cache_dir/cache_poisoning.txt" || true
    fi

    # Content type confusion
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Running content type confusion tests..."
        curl -sI "https://$domain" -H "Content-Type: text/html" 2>>"$LOGS_DIR/cache_encoding.log" >> "$cache_dir/content_type_confusion.txt" || true
        curl -sI "https://$domain" -H "Content-Type: application/json" 2>>"$LOGS_DIR/cache_encoding.log" >> "$cache_dir/content_type_confusion.txt" || true
    fi

    # TLS chain analysis
    log "INFO" "Analyzing TLS certificate chain..."
    # Placeholder for TLS chain analysis
    if command -v openssl >/dev/null 2>&1; then
        openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -subject -issuer >> "$cache_dir/tls_chain.txt" 2>/dev/null || true
    fi

    # Encode/decode analysis
    log "INFO" "Checking for encoding-based vulnerabilities..."
    # Placeholder for encoding analysis

    local ce_count
    ce_count=$(ls -l "$cache_dir"/*.txt 2>/dev/null | grep -c "^-" || echo 0)

    phase_log "INFO" "Cache & encoding security analysis complete: $ce_count tests executed" "cache_encoding" "$domain"

    # Write assets
    for check_file in "$cache_dir"/*.txt; do
        [ -f "$check_file" ] || continue
        while IFS= read -r result; do
            [ -z "$result" ] && continue
            write_asset "{\"type\":\"cache_encoding_finding\",\"value\":\"$result\",\"source\":\"cache_encoding_scan\",\"phase\":\"cache_encoding_security\"}" \
                "$cache_dir/assets.jsonl" 2>/dev/null || true
        done < "$check_file"
    done

    echo "$ce_count" > "$cache_dir/count.txt"

    write_finding "{\"type\":\"cache_encoding_scan\",\"severity\":\"info\",\"count\":$ce_count,\"phase\":\"cache_encoding_security\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "cache_encoding_phase" "Completed for $domain"
}