#!/bin/bash
# Parameter discovery phase

params_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local params_dir="$output_dir/params"
    local crawl_file="$output_dir/crawl/endpoints.txt"

    mkdir -p "$params_dir"

    log "INFO" "Starting parameter discovery for $domain"

    if [ ! -f "$crawl_file" ]; then
        log "WARN" "No endpoints file found, skipping parameter discovery"
        return 1
    fi

    if tool_available "arjun"; then
        log "INFO" "Running Arjun for parameter discovery..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            arjun -u "$url" -o "$params_dir/arjun_$(echo "$url" | sed 's|https\?://||g' | sed 's|/|_|g').json" \
                -t "$THREADS" --timeout 30 2>>"$LOGS_DIR/arjun.log" || true
        done < <(head -30 "$crawl_file")
    fi

    if tool_available "unfurl"; then
        log "INFO" "Extracting parameters with unfurl..."
        cat "$crawl_file" | unfurl keys 2>>"$LOGS_DIR/unfurl.log" \
            >> "$params_dir/param_keys.txt" 2>/dev/null || true
    fi

    if command -v grep >/dev/null 2>&1; then
        log "INFO" "Extracting parameters from URLs..."
        grep -oP '\?[^#]*' "$crawl_file" 2>/dev/null | \
            sed 's/?//g' | tr '&' '\n' | cut -d'=' -f1 | sort -u \
            >> "$params_dir/param_keys.txt" 2>/dev/null || true
    fi

    sort -u "$params_dir/param_keys.txt" -o "$params_dir/param_keys.txt" 2>/dev/null || true

    local param_count
    param_count=$(wc -l < "$params_dir/param_keys.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "Parameter discovery complete: $param_count unique parameters found" "params" "$domain"

    # Write assets for discovered parameters
    while IFS= read -r param; do
        [ -z "$param" ] && continue
        write_asset "{\"type\":\"parameter\",\"name\":\"$param\",\"source\":\"param_discovery\",\"phase\":\"params\"}" \
            "$params_dir/assets.jsonl" 2>/dev/null || true
    done < "$params_dir/param_keys.txt" 2>/dev/null

    # Check for sensitive parameters (findings)
    while IFS= read -r param; do
        [ -z "$param" ] && continue
        if echo "$param" | grep -qiE "^(token|key|secret|password|auth|session|admin|debug|test|callback|redirect|return|url|file|path|cmd|exec|eval|query|search|filter|sort|order|page|limit|offset|id|user|account|profile)"; then
            write_finding "{\"type\":\"sensitive_param\",\"severity\":\"info\",\"parameter\":\"$param\",\"description\":\"Potentially sensitive parameter discovered\",\"phase\":\"params\"}" \
                "$params_dir/findings.jsonl" 2>/dev/null || true
        fi
    done < "$params_dir/param_keys.txt" 2>/dev/null

    echo "$param_count" > "$params_dir/count.txt"

    py_log "INFO" "params_phase" "Completed for $domain"
}