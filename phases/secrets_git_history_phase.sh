#!/bin/bash
# Track 16 - Secrets Deep | Phase 243: Git History Secret Scanning
# Commit analysis, credential extraction

secrets_git_history_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "secrets_git_history_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/secrets_git_history"
    mkdir -p "$phase_dir"

    log "INFO" "Starting secrets_git_history_phase for $domain"

    local git_secrets="$phase_dir/git_secrets.txt"
    local commit_secrets="$phase_dir/credential_commits.txt"
    local count=0

    # --- Discover GitHub repositories ---
    local repos_file="$phase_dir/discovered_repos.txt"
    log "INFO" "Discovering GitHub repositories for $domain..."
    curl -s "https://api.github.com/search/repositories?q=domain:$domain+OR+org:$domain" 2>/dev/null | \
        jq -r '.items[]? | .full_name + " " + .clone_url + " " + (.private|tostring)' 2>/dev/null \
        > "$repos_file" || true

    # Also check GitHub dork for code
    curl -s "https://api.github.com/search/code?q=$domain+in:file+extension:env+extension:yml+extension:json" 2>/dev/null | \
        jq -r '.items[]? | .repository.full_name + " " + .path' 2>/dev/null \
        >> "$repos_file" || true

    local repo_count
    repo_count=$(wc -l < "$repos_file" 2>/dev/null || echo 0)
    log "INFO" "Found $repo_count repositories"

    # --- Run trufflehog on discovered repos ---
    if tool_available "trufflehog"; then
        log "INFO" "Running trufflehog on discovered repositories..."
        while IFS= read -r line; do
            local clone_url
            clone_url=$(echo "$line" | awk '{print $2}')
            [[ -z "$clone_url" ]] && continue

            local repo_name
            repo_name=$(echo "$clone_url" | sed 's|.*/||;s|\.git$||')
            log "INFO" "Scanning repo: $repo_name"

            trufflehog git "$clone_url" --only-verified \
                -o json >> "$git_secrets" 2>>"$LOGS_DIR/trufflehog_git.log" || true
            ((count++)) || true
        done < "$repos_file"
    fi

    # --- Manual git log scanning ---
    log "INFO" "Performing pattern-based commit analysis..."
    local secret_patterns=(
        'password\s*[=:]\s*["\x27]?[^\s"]+'
        'api[_-]?key\s*[=:]\s*["\x27]?[^\s"]+'
        'secret\s*[=:]\s*["\x27]?[^\s"]+'
        'token\s*[=:]\s*["\x27]?[^\s"]+'
        'AWS_SECRET_ACCESS_KEY\s*[=:]'
        'PRIVATE.KEY'
        'BEGIN.*RSA'
        'BEGIN.*OPENSSH'
        'BEGIN.*EC PRIVATE'
    )

    while IFS= read -r line; do
        local clone_url
        clone_url=$(echo "$line" | awk '{print $2}')
        [[ -z "$clone_url" ]] && continue

        local repo_name
        repo_name=$(echo "$clone_url" | sed 's|.*/||;s|\.git$||')
        local tmp_clone="/tmp/drf_git_${repo_name}_$$"

        git clone --depth 1 "$clone_url" "$tmp_clone" 2>/dev/null || true
        [[ -d "$tmp_clone" ]] || continue

        for pat in "${secret_patterns[@]}"; do
            grep -rlnE "$pat" "$tmp_clone" 2>/dev/null | while IFS= read -r matched_file; do
                grep -nE "$pat" "$matched_file" 2>/dev/null | while IFS= read -r match_line; do
                    echo "[GIT_SECRET] repo=$repo_name file=${matched_file#$tmp_clone/} match=$match_line" >> "$commit_secrets"
                    ((count++)) || true
                done
            done
        done

        rm -rf "$tmp_clone" 2>/dev/null || true
    done < "$repos_file"

    # --- Write structured findings ---
    if [[ -f "$git_secrets" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "git_secret" "" "" "" || true
        done < "$git_secrets"
    fi

    if [[ -f "$commit_secrets" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "credential_commit" "" "" "" || true
        done < "$commit_secrets"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "secrets_git_history_phase" "domain=$domain findings=$count repos=$repo_count"
    log "INFO" "secrets_git_history_phase complete: $count findings"
    return 0
}

secrets_git_history_phase "$@"
