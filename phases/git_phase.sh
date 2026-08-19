#!/bin/bash
# Git repository scanning phase

git_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local git_dir="$output_dir/git"

    mkdir -p "$git_dir"

    log "INFO" "Starting Git repository scanning for $domain"

    if tool_available "gitrob"; then
        log "INFO" "Running gitrob for Git intelligence..."
        gitrob -d "$domain" -o "$git_dir/gitrob_results.txt" 2>>"$LOGS_DIR/gitrob.log" || true
    fi

    if tool_available "trufflehog"; then
        log "INFO" "Running trufflehog for secret scanning in Git..."
        trufflehog git https://github.com --regex --entropy=False \
            -o "$git_dir/trufflehog_results.txt" 2>>"$LOGS_DIR/trufflehog.log" || true
    fi

    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying GitHub for repository information..."
        curl -s "https://api.github.com/search/repositories?q=$domain" 2>/dev/null | \
            jq -r '.items[] | .full_name + " " + .html_url' 2>/dev/null >> "$git_dir/github_repos.txt" || true
    fi

    if command -v grep >/dev/null 2>&1; then
        log "INFO" "Searching for exposed .git directories..."
        if [ -f "$output_dir/crawl/endpoints.txt" ]; then
            grep -iE "\.git/" "$output_dir/crawl/endpoints.txt" 2>/dev/null | \
                sort -u > "$git_dir/git_exposures.txt" || true
        fi
    fi

    local git_count
    git_count=$(wc -l < "$git_dir/gitrob_results.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "Git repository scanning complete: $git_count results" "git" "$domain"

    # Write assets for discovered repositories
    while IFS= read -r repo; do
        [ -z "$repo" ] && continue
        write_asset "{\"type\":\"git_repository\",\"value\":\"$repo\",\"source\":\"github\",\"phase\":\"git\"}" \
            "$git_dir/assets.jsonl" 2>/dev/null || true
    done < "$git_dir/github_repos.txt" 2>/dev/null

    # Write findings for exposed .git directories
    if [ -f "$git_dir/git_exposures.txt" ]; then
        local exposure_count
        exposure_count=$(wc -l < "$git_dir/git_exposures.txt" 2>/dev/null || echo 0)
        if [ "$exposure_count" -gt 0 ]; then
            write_finding "{\"type\":\"git_exposure\",\"severity\":\"high\",\"count\":$exposure_count,\"phase\":\"git\"}" \
                "$git_dir/findings.jsonl" 2>/dev/null || true
        fi
    fi

    echo "$git_count" > "$git_dir/count.txt"

    py_log "INFO" "git_phase" "Completed for $domain"
}