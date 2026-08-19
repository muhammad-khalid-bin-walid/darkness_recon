#!/bin/bash
# Secret scanning phase

secrets_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local secrets_dir="$output_dir/secrets"
    local crawl_file="$output_dir/crawl/endpoints.txt"
    local js_files="$output_dir/crawl/js_files.txt"

    mkdir -p "$secrets_dir"

    log "INFO" "Starting secret scanning for $domain"

    if tool_available "trufflehog"; then
        log "INFO" "Running trufflehog for secret scanning..."
        trufflehog filesystem "$output_dir" --regex --entropy=False \
            -o "$secrets_dir/trufflehog_results.txt" 2>>"$LOGS_DIR/trufflehog.log" || true
    fi

    if command -v grep >/dev/null 2>&1; then
        log "INFO" "Scanning for API keys..."
        if [ -f "$js_files" ]; then
            grep -oE 'AIza[0-9A-Za-z_-]{35}' "$js_files" 2>/dev/null | sort -u > "$secrets_dir/google_api_keys.txt" || true
            grep -oE 'sk-[a-zA-Z0-9]{48,}' "$js_files" 2>/dev/null | sort -u > "$secrets_dir/openai_keys.txt" || true
            grep -oE 'ghp_[a-zA-Z0-9]{36}' "$js_files" 2>/dev/null | sort -u > "$secrets_dir/github_tokens.txt" || true
            grep -oE 'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}' "$js_files" 2>/dev/null | sort -u > "$secrets_dir/sendgrid_keys.txt" || true
            grep -oE 'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' "$js_files" 2>/dev/null | sort -u > "$secrets_dir/jwt_tokens.txt" || true
        fi
    fi

    if [ -f "$crawl_file" ]; then
        log "INFO" "Scanning endpoints for sensitive data..."
        grep -iE "(api.key|apikey|secret|token|password|passwd|credential)" "$crawl_file" 2>/dev/null | \
            sort -u > "$secrets_dir/sensitive_endpoints.txt" || true
    fi

    local secrets_count
    secrets_count=$(wc -l < "$secrets_dir/trufflehog_results.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "Secret scanning complete: $secrets_count secrets found" "secrets" "$domain"

    # Write findings for discovered secrets
    while IFS= read -r secret; do
        [ -z "$secret" ] && continue
        write_finding "{\"type\":\"secret_exposure\",\"severity\":\"critical\",\"details\":\"$(echo "$secret" | head -c 200)\",\"phase\":\"secrets\"}" \
            "$secrets_dir/findings.jsonl" 2>/dev/null || true
    done < "$secrets_dir/trufflehog_results.txt" 2>/dev/null

    # Write findings for API keys
    for key_file in "$secrets_dir"/*_keys.txt "$secrets_dir"/*_tokens.txt; do
        [ -f "$key_file" ] || continue
        local key_count
        key_count=$(wc -l < "$key_file" 2>/dev/null || echo 0)
        if [ "$key_count" -gt 0 ]; then
            local key_type=$(basename "$key_file" | sed 's/_keys.txt//;s/_tokens.txt//')
            write_finding "{\"type\":\"api_key_exposure\",\"severity\":\"critical\",\"key_type\":\"$key_type\",\"count\":$key_count,\"phase\":\"secrets\"}" \
                "$secrets_dir/findings.jsonl" 2>/dev/null || true
        fi
    done

    echo "$secrets_count" > "$secrets_dir/count.txt"

    py_log "INFO" "secrets_phase" "Completed for $domain"
}