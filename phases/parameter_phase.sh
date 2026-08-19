#!/bin/bash
# Combined Phase 5: Parameter & Form Analysis
# Encompasses: Arjun, JS AST analysis, form parameter discovery, unfurl
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

parameter_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local endpoints_file="$output_dir/crawl/endpoints.txt"
    local param_dir="$output_dir/crawl/params"

    mkdir -p "$param_dir"

    log "INFO" "Starting parameter & form analysis for $domain"

    # Arjun for parameter discovery
    if tool_available "arjun"; then
        log "INFO" "Running Arjun parameter discovery..."
        arjun -i "$output_dir/crawl/endpoints.txt" -o "$param_dir/arjun.txt" 2>>"$LOGS_DIR/arjun.log" || true
    fi

    # JS AST analysis for parameter extraction
    if tool_available "unfurl"; then
        log "INFO" "Running JS AST parameter analysis..."
        # Extract JS files and analyze for parameters
        jq -r '.[].value' "$output_dir/crawl/endpoints.txt" 2>/dev/null | grep "\.js$" | head -20 | while read -r jsfile; do
            [ -z "$jsfile" ] && continue
            # Try to fetch and analyze JS
            command -v curl >/dev/null 2>&1 && curl -s "https://$domain$jsfile" 2>/dev/null | \
                unfurl params >> "$param_dir/js_params.txt" 2>/dev/null || true
        done
    fi

    # Parameter correlation across endpoints
    if [ -f "$param_dir/arjun.txt" ]; then
        cat "$param_dir/arjun.txt" | grep -E "^[a-zA-Z_]+" | sort -u > "$param_dir/conc_params.txt"
    fi

    # Deduplicate all parameter keys
    cat "$param_dir"/*.txt 2>/dev/null | grep -v "^$" | sort -u > "$param_dir/all_param_keys.txt"

    local param_count
    param_count=$(wc -l < "$param_dir/all_param_keys.txt" 2>/dev/null || echo 0)

    phase_log "INFO" "Parameter & form analysis complete: $param_count unique parameters found" "parameter_analysis" "$domain"

    # Write assets
    while IFS= read -r param; do
        [ -z "$param" ] && continue
        write_asset "{\"type\":\"parameter\",\"value\":\"$param\",\"source\":\"param_analysis\",\"phase\":\"parameter_form_analysis\"}" \
            "$param_dir/assets.jsonl" 2>/dev/null || true
    done < "$param_dir/all_param_keys.txt"

    echo "$param_count" > "$param_dir/count.txt"

    write_finding "{\"type\":\"parameter_discovery\",\"severity\":\"info\",\"count\":$param_count,\"phase\":\"parameter_form_analysis\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "parameter_phase" "Completed for $domain"
}