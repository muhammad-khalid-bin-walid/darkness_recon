#!/bin/bash
# Combined Phase 10: Git & Secret Scanning
# Encompasses: GitRob, trufflehog, gitleaks, secret finding, credential detection
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

git_secret_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local git_dir="$output_dir/git"
    local secret_dir="$output_dir/secrets"

    mkdir -p "$git_dir" "$secret_dir"

    log "INFO" "Starting Git & secret scanning for $domain"

    # GitRob for repository analysis
    if tool_available "gitrob"; then
        log "INFO" "Running GitRob..."
        gitrob -u "$domain" -f public 2>>"$LOGS_DIR/gitrob.log" >> "$git_dir/gitrob.txt" || true
    fi

    # trufflehog for secret scanning
    if tool_available "trufflehog"; then
        log "INFO" "Running trufflehog..."
        trufflehog filesystem "$output_dir" 2>>"$LOGS_DIR/trufflehog.log" >> "$secret_dir/trufflehog.txt" || true
        # Also try git history scan
        trufflehog git "$subdomains_file" 2>>"$LOGS_DIR/trufflehog.log" >> "$secret_dir/trufflehog_git.txt" || true
    fi

    # gitleaks for secret detection
    if tool_available "gitleaks"; then
        log "INFO" "Running gitleaks..."
        gitleaks detect --no-git --source "$output_dir" 2>>"$LOGS_DIR/gitleaks.log" >> "$secret_dir/gitleaks.txt" || true
    fi

    # Extract potential secrets from all discovered files
    if command -v grep >/dev/null 2>&1; then
        log "INFO" "Pattern-matching secret extraction..."
        # Common secret patterns
        grep -riE "(api[_-]?key|secret[_-]?key|access[_-]?token|password[_-]?=)" "$output_dir" --include="*.env" --include="*.cfg" --include="*.yml" --include="*.yaml" 2>>"$LOGS_DIR/secret_patterns.log" >> "$secret_dir/pattern_matches.txt" || true
    fi

    # Deduplicate and categorize findings
    cat "$secret_dir"/*.txt 2>/dev/null | grep -v "^$" | sort -u > "$secret_dir/all_secrets.txt"

    local secret_count
    secret_count=$(wc -l < "$secret_dir/all_secrets.txt" 2>/dev/null || echo 0)

    phase_log "INFO" "Git & secret scanning complete: $secret_count potential secrets found" "git_secret_scanning" "$domain"

    # Write assets
    while IFS= read -r secret; do
        [ -z "$secret" ] && continue
        # Mask secret value for security in assets
        masked_secret=$(echo "$secret" | sed 's/\(.\{4\}\).*/\1***/')
        write_asset "{\"type\":\"secret\",\"value\":\"$masked_secret\",\"source\":\"secret_scanning\",\"phase\":\"git_secret_scanning\"}" \
            "$secret_dir/assets.jsonl" 2>/dev/null || true
    done < "$secret_dir/all_secrets.txt"

    echo "$secret_count" > "$secret_dir/count.txt"

    write_finding "{\"type\":\"secret_discovery\",\"severity\":\"high\",\"count\":$secret_count,\"phase\":\"git_secret_scanning\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "git_secret_phase" "Completed for $domain"
}