#!/bin/bash
# Visual reconnaissance phase

screenshots_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local screenshots_dir="$output_dir/screenshots"
    local live_file="$output_dir/live/live_subdomains.txt"

    mkdir -p "$screenshots_dir"

    log "INFO" "Starting visual reconnaissance for $domain"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, skipping screenshots"
        return 1
    fi

    if tool_available "aquatone"; then
        log "INFO" "Running aquatone for screenshots..."
        cat "$live_file" | aquatone -out "$screenshots_dir" -timeout 10 2>>"$LOGS_DIR/aquatone.log" || true
    fi

    if tool_available "eyewitness"; then
        log "INFO" "Running EyeWitness for visual reconnaissance..."
        eyewitness -f "$live_file" -d "$screenshots_dir/eyewitness" --no-prompt 2>>"$LOGS_DIR/eyewitness.log" || true
    fi

    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Taking screenshots with curl..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            local url_clean
            url_clean=$(echo "$url" | sed 's|https\?://||g' | sed 's|/|_|g')
            curl -s -o "$screenshots_dir/${url_clean}.html" \
                --max-time 15 "$url" 2>/dev/null || true
        done < <(head -10 "$live_file")
    fi

    local screenshot_count
    screenshot_count=$(find "$screenshots_dir" -name "*.png" -o -name "*.html" 2>/dev/null | wc -l)
    
    phase_log "INFO" "Visual reconnaissance complete: $screenshot_count screenshots captured" "screenshots" "$domain"

    # Write assets for captured screenshots
    find "$screenshots_dir" -name "*.png" -o -name "*.html" 2>/dev/null | while IFS= read -r screenshot; do
        [ -z "$screenshot" ] && continue
        write_asset "{\"type\":\"screenshot\",\"path\":\"$screenshot\",\"phase\":\"screenshots\"}" \
            "$screenshots_dir/assets.jsonl" 2>/dev/null || true
    done

    echo "$screenshot_count" > "$screenshots_dir/count.txt"

    write_finding "{\"type\":\"screenshots\",\"severity\":\"info\",\"count\":$screenshot_count,\"phase\":\"screenshots\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "screenshots_phase" "Completed for $domain"
}