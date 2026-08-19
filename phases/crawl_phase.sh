#!/bin/bash
# URL and endpoint discovery phase

crawl_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local crawl_dir="$output_dir/crawl"
    local live_file="$output_dir/live/httpx_results.txt"

    mkdir -p "$crawl_dir"

    log "INFO" "Starting URL and endpoint discovery for $domain"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, using domain for crawling"
        echo "https://$domain" > "$crawl_dir/seed_urls.txt"
    else
        head -50 "$live_file" | awk '{print $1}' > "$crawl_dir/seed_urls.txt"
    fi

    if tool_available "katana"; then
        log "INFO" "Running katana for URL discovery..."
        katana -l "$crawl_dir/seed_urls.txt" -d 3 -jc -mt -o "$crawl_dir/katana_results.txt" \
            -timeout 30 -concurrency "$THREADS" 2>>"$LOGS_DIR/katana.log" || true
    fi

    if tool_available "gospider"; then
        log "INFO" "Running gospider for spidering..."
        gospider -S "$crawl_dir/seed_urls.txt" -o "$crawl_dir/gospider" -t "$THREADS" \
            --robots --sitemap --timeout 15 --depth 6 --random-agent \
            --blacklist "\.(png|jpg|gif|css|woff|ttf)$" --include-subs 2>>"$LOGS_DIR/gospider.log" || true
        if [ -d "$crawl_dir/gospider" ]; then
            find "$crawl_dir/gospider" -name "*.txt" -exec cat {} \; 2>/dev/null >> "$crawl_dir/gospider_results.txt" || true
        fi
    fi

    if tool_available "waybackurls"; then
        log "INFO" "Querying Wayback Machine..."
        cat "$crawl_dir/seed_urls.txt" | waybackurls 2>>"$LOGS_DIR/waybackurls.log" \
            >> "$crawl_dir/wayback.txt" || true
    fi

    if tool_available "waymore"; then
        log "INFO" "Running waymore for comprehensive URL discovery..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            waymore -i "$url" -mode U -o "$crawl_dir/waymore.txt" 2>>"$LOGS_DIR/waymore.log" || true
        done < <(head -10 "$crawl_dir/seed_urls.txt")
    fi

    if tool_available "gauplus"; then
        log "INFO" "Running gauplus for URL discovery..."
        cat "$crawl_dir/seed_urls.txt" | gauplus 2>>"$LOGS_DIR/gauplus.log" \
            >> "$crawl_dir/gauplus.txt" || true
    fi

    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Fetching robots.txt and sitemap.xml..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            curl -s "${url}/robots.txt" 2>/dev/null >> "$crawl_dir/robots.txt" || true
            curl -s "${url}/sitemap.xml" 2>/dev/null >> "$crawl_dir/sitemap.xml" || true
        done < <(head -10 "$crawl_dir/seed_urls.txt")
    fi

    if [ -f "$crawl_dir/wayback.txt" ]; then
        grep -E '\.js(\?.*)?$' "$crawl_dir/wayback.txt" | sort -u > "$crawl_dir/js_files.txt" 2>/dev/null || true
        grep -E '\?.*=' "$crawl_dir/wayback.txt" | sort -u > "$crawl_dir/urls_with_params.txt" 2>/dev/null || true
    fi

    if [ -f "$crawl_dir/gospider_results.txt" ]; then
        grep -oP 'U:\K[^ ]+' "$crawl_dir/gospider_results.txt" 2>/dev/null | sort -u >> "$crawl_dir/endpoints.txt" 2>/dev/null || true
    fi

    if [ -f "$crawl_dir/katana_results.txt" ]; then
        grep -oP 'https?://[^"'\''<>]+' "$crawl_dir/katana_results.txt" 2>/dev/null | sort -u >> "$crawl_dir/endpoints.txt" 2>/dev/null || true
    fi

    sort -u "$crawl_dir/endpoints.txt" -o "$crawl_dir/endpoints.txt" 2>/dev/null || true

    # Extract parameter keys
    if [ -f "$crawl_dir/urls_with_params.txt" ]; then
        grep -oP '[?&]\K[^=]+(?==)' "$crawl_dir/urls_with_params.txt" | sort -u > "$crawl_dir/param_keys.txt" 2>/dev/null || true
    fi

    # Run JS file analysis if JS files found
    if [ -f "$crawl_dir/js_files.txt" ] && [ -s "$crawl_dir/js_files.txt" ]; then
        log "INFO" "Running JavaScript file analysis..."
        source "$SCRIPT_DIR/../scripts/analyze_js.sh"
        analyze_js_files "$domain"
    fi

    local crawl_count
    crawl_count=$(wc -l < "$crawl_dir/endpoints.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "URL and endpoint discovery complete: $crawl_count endpoints found" "crawl" "$domain"

    # Write endpoints for discovered URLs
    while IFS= read -r endpoint; do
        [ -z "$endpoint" ] && continue
        write_endpoint "{\"url\":\"$endpoint\",\"method\":\"GET\",\"phase\":\"crawl\"}" \
            "$crawl_dir/endpoints.jsonl" 2>/dev/null || true
    done < "$crawl_dir/endpoints.txt" 2>/dev/null

    # Write assets for JavaScript files
    if [ -f "$crawl_dir/js_files.txt" ]; then
        while IFS= read -r js_file; do
            [ -z "$js_file" ] && continue
            write_asset "{\"type\":\"javascript\",\"url\":\"$js_file\",\"source\":\"crawl\",\"phase\":\"crawl\"}" \
                "$crawl_dir/assets.jsonl" 2>/dev/null || true
        done < "$crawl_dir/js_files.txt"
    fi

    # Findings for URLs with parameters (potential injection points)
    if [ -f "$crawl_dir/urls_with_params.txt" ]; then
        local param_count
        param_count=$(wc -l < "$crawl_dir/urls_with_params.txt" 2>/dev/null || echo 0)
        if [ "$param_count" -gt 0 ]; then
            write_finding "{\"type\":\"parameterized_urls\",\"severity\":\"info\",\"count\":$param_count,\"description\":\"Found $param_count URLs with parameters\",\"phase\":\"crawl\"}" \
                "$crawl_dir/findings.jsonl" 2>/dev/null || true
        fi
    fi

    echo "$crawl_count" > "$crawl_dir/count.txt"

    py_log "INFO" "crawl_phase" "Completed for $domain"
}