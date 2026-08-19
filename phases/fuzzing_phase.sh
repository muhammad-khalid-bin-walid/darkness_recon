#!/bin/bash
# Combined Phase 6: Fuzzing & Path Discovery
# Encompasses: fuzz_phase, ffuf, commonspeak2, intelligent path discovery
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

fuzzing_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local subdomains_file="$output_dir/subdomains/subdomains.txt"
    local fuzz_dir="$output_dir/fuzz"

    mkdir -p "$fuzz_dir"

    log "INFO" "Starting fuzzing & path discovery for $domain"

    # ffuf for directory/file fuzzing
    if tool_available "ffuf"; then
        log "INFO" "Running ffuf fuzzing..."
        ffuf -w "$WORDLISTS_DIR/common_paths.txt" -u "$domain/FUZZ" -mc 200,301,302,401,403,404,500 2>>"$LOGS_DIR/ffuf.log" -o "$fuzz_dir/ffuf.json" || true
    fi

    # commonspeak2 fuzzing
    if tool_available "commonspeak2"; then
        log "INFO" "Running commonspeak2 fuzzing..."
        commonspeak2 -l "$subdomains_file" -t "$domain" 2>>"$LOGS_DIR/commonspeak2.log" >> "$fuzz_dir/commonspeak2.txt" || true
    fi

    # nuclei fuzzing with custom wordlist
    if tool_available "nuclei"; then
        log "INFO" "Running nuclei fuzzing..."
        nuclei -l "$subdomains_file" -t "$TEMPLATES_DIR/fuzzing/" -o "$fuzz_dir/nuclei.json" 2>>"$LOGS_DIR/nuclei.log" || true
    fi

    # Filter for interesting responses (non-404)
    local fuzz_count
    if [ -f "$fuzz_dir/ffuf.json" ]; then
        fuzz_count=$(jq '[.[] | .status] | map(select(. != 404)) | length' "$fuzz_dir/ffuf.json" 2>/dev/null || echo 0)
    else
        fuzz_count=0
    fi

    phase_log "INFO" "Fuzzing & path discovery complete: $fuzz_count interesting findings found" "fuzzing" "$domain"

    # Write assets for each fuzzing finding
    if [ -f "$fuzz_dir/ffuf.json" ]; then
        jq -r '.[] | select(.status >= 200 and .status < 300)' "$fuzz_dir/ffuf.json" 2>/dev/null | while IFS= read -r finding; do
            [ -z "$finding" ] && continue
            write_asset "{\"type\":\"fuzzing_finding\",\"value\":$finding,\"source\":\"fuzzing\",\"phase\":\"fuzzing_path_discovery\"}" \
                "$fuzz_dir/assets.jsonl" 2>/dev/null || true
        done
    fi

    echo "$fuzz_count" > "$fuzz_dir/count.txt"

    py_log "INFO" "fuzzing_phase" "Completed for $domain"
}