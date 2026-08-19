#!/bin/bash
# Pattern matching phase (gf patterns)

patterns_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local patterns_dir="$output_dir/patterns"
    local crawl_file="$output_dir/crawl/endpoints.txt"

    mkdir -p "$patterns_dir"

    log "INFO" "Starting pattern matching for $domain"

    if [ ! -f "$crawl_file" ]; then
        log "WARN" "No endpoints file found, skipping pattern matching"
        return 1
    fi

    if tool_available "gf"; then
        log "INFO" "Running gf pattern matching..."
        gf xss "$crawl_file" 2>/dev/null > "$patterns_dir/xss_patterns.txt" || true
        gf ssrf "$crawl_file" 2>/dev/null > "$patterns_dir/ssrf_patterns.txt" || true
        gf sqli "$crawl_file" 2>/dev/null > "$patterns_dir/sqli_patterns.txt" || true
        gf lfi "$crawl_file" 2>/dev/null > "$patterns_dir/lfi_patterns.txt" || true
        gf rce "$crawl_file" 2>/dev/null > "$patterns_dir/rce_patterns.txt" || true
        gf redirect "$crawl_file" 2>/dev/null > "$patterns_dir/redirect_patterns.txt" || true
        gf cors "$crawl_file" 2>/dev/null > "$patterns_dir/cors_patterns.txt" || true
        gf idor "$crawl_file" 2>/dev/null > "$patterns_dir/idor_patterns.txt" || true
        gf jwt "$crawl_file" 2>/dev/null > "$patterns_dir/jwt_patterns.txt" || true
        gf graphql "$crawl_file" 2>/dev/null > "$patterns_dir/graphql_patterns.txt" || true
    fi

    if command -v grep >/dev/null 2>&1; then
        log "INFO" "Running custom pattern matching..."
        grep -iE "(<script|javascript:|onerror|onload)" "$crawl_file" 2>/dev/null | \
            sort -u > "$patterns_dir/xss_custom.txt" || true
        grep -iE "('|\").*OR.*=.*('--|#)" "$crawl_file" 2>/dev/null | \
            sort -u > "$patterns_dir/sqli_custom.txt" || true
        grep -iE "(file|path|include|require).*=.*(/|\\.\.)" "$crawl_file" 2>/dev/null | \
            sort -u > "$patterns_dir/lfi_custom.txt" || true
    fi

    local pattern_count
    pattern_count=$(find "$patterns_dir" -name "*.txt" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')
    
    phase_log "INFO" "Pattern matching complete: $pattern_count patterns found" "patterns" "$domain"

    # Write findings for each pattern type
    for pattern_file in "$patterns_dir"/*.txt; do
        [ -f "$pattern_file" ] || continue
        local count
        count=$(wc -l < "$pattern_file" 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            local pattern_type=$(basename "$pattern_file" .txt)
            local severity="info"
            if echo "$pattern_type" | grep -qiE "(xss|sqli|ssrf|lfi|rce)"; then
                severity="medium"
            fi
            write_finding "{\"type\":\"pattern_match\",\"severity\":\"$severity\",\"pattern\":\"$pattern_type\",\"count\":$count,\"phase\":\"patterns\"}" \
                "$patterns_dir/findings.jsonl" 2>/dev/null || true
        fi
    done

    echo "$pattern_count" > "$patterns_dir/count.txt"

    py_log "INFO" "patterns_phase" "Completed for $domain"
}