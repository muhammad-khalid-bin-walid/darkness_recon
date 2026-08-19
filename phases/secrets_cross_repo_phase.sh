#!/bin/bash
# Track 16 - Secrets Deep | Phase 247: Cross-Repository Secret Scanning
# Shared credential detection

secrets_cross_repo_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "secrets_cross_repo_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/secrets_cross_repo"
    mkdir -p "$phase_dir"

    log "INFO" "Starting secrets_cross_repo_phase for $domain"

    local cross_repo_file="$phase_dir/cross_repo_secrets.txt"
    local shared_file="$phase_dir/shared_credentials.txt"
    local count=0

    # --- Discover all repos under domain organization ---
    log "INFO" "Discovering cross-repository secret sharing..."
    local all_repos="$phase_dir/all_repos.txt"
    curl -s "https://api.github.com/search/repositories?q=org:$domain" 2>/dev/null | \
        jq -r '.items[]? | .full_name' 2>/dev/null > "$all_repos" || true

    local org_repos
    org_repos=$(wc -l < "$all_repos" 2>/dev/null || echo 0)
    log "INFO" "Found $org_repos repositories under organization"

    # --- Collect secrets from each repo ---
    local secrets_by_repo="$phase_dir/secrets_by_repo.json"
    echo "[]" > "$secrets_by_repo"

    while IFS= read -r repo_name; do
        [[ -z "$repo_name" ]] && continue
        local clone_url="https://github.com/${repo_name}.git"
        local tmp_clone="/tmp/drf_crossrepo_${repo_name//\//_}_$$"

        log "INFO" "Cloning and scanning: $repo_name"
        git clone --depth 1 "$clone_url" "$tmp_clone" 2>/dev/null || true
        [[ -d "$tmp_clone" ]] || continue

        local repo_secrets=()
        # Scan for secret patterns
        while IFS= read -r match; do
            [[ -z "$match" ]] && continue
            repo_secrets+=("$match")
            local hash
            hash=$(echo -n "$match" | md5sum 2>/dev/null | awk '{print $1}') || continue
            echo "$repo_name|$match|$hash" >> "$phase_dir/all_secrets_raw.txt"
        done < <(
            grep -rohE '(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{48}|xox[bpsar]-[a-zA-Z0-9-]+|AIza[0-9A-Za-z_-]{35}|SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}|sk_live_[0-9a-zA-Z]{24,}|sk_test_[0-9a-zA-Z]{24,}|key-[0-9a-zA-Z]{32})' "$tmp_clone" 2>/dev/null || true
        )

        rm -rf "$tmp_clone" 2>/dev/null || true
    done < "$all_repos"

    # --- Find shared credentials across repos ---
    log "INFO" "Identifying shared credentials across repositories..."
    if [[ -f "$phase_dir/all_secrets_raw.txt" ]]; then
        sort "$phase_dir/all_secrets_raw.txt" | cut -d'|' -f2,3 | sort | uniq -c | sort -rn | while read -r count_line secret_hash; do
            local secret_val
            secret_val=$(echo "$secret_hash" | cut -d'|' -f1)
            local secret_hash_val
            secret_hash_val=$(echo "$secret_hash" | cut -d'|' -f2)
            local repo_count
            repo_count=$(echo "$count_line" | tr -d ' ')

            if (( repo_count > 1 )); then
                # Find which repos share this secret
                local sharing_repos
                sharing_repos=$(grep "|$secret_hash_val$" "$phase_dir/all_secrets_raw.txt" 2>/dev/null | cut -d'|' -f1 | sort -u | tr '\n' ',' | sed 's/,$//')
                echo "[SHARED_SECRET] secret_prefix=${secret_val:0:8}... shared_across=$repo_count repos=[$sharing_repos]" >> "$shared_file"
                echo "[CROSS_REPO] secret_hash=$secret_hash_val repos=$sharing_repos" >> "$cross_repo_file"
                ((count++)) || true
            fi
        done
    fi

    # --- Check for shared environment variables across repos ---
    log "INFO" "Checking for shared environment configurations..."
    local env_hashes="$phase_dir/env_hashes.txt"
    while IFS= read -r repo_name; do
        [[ -z "$repo_name" ]] && continue
        local tmp_clone="/tmp/drf_envscan_${repo_name//\//_}_$$"
        git clone --depth 1 "https://github.com/${repo_name}.git" "$tmp_clone" 2>/dev/null || true
        [[ -d "$tmp_clone" ]] || continue

        while IFS= read -r envfile; do
            local env_hash
            env_hash=$(md5sum "$envfile" 2>/dev/null | awk '{print $1}') || continue
            echo "$repo_name|$envfile|$env_hash" >> "$env_hashes"
        done < <(find "$tmp_clone" -name '.env*' -o -name 'config.*' -o -name 'credentials*' 2>/dev/null)

        rm -rf "$tmp_clone" 2>/dev/null || true
    done < "$all_repos"

    if [[ -f "$env_hashes" ]]; then
        sort -t'|' -k3 "$env_hashes" | uniq -f2 -d | while IFS= read -r duplicate; do
            echo "[SHARED_CONFIG] $duplicate" >> "$cross_repo_file"
            ((count++)) || true
        done
    fi

    # --- Write structured findings ---
    if [[ -f "$cross_repo_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "cross_repo_secret" "" "" "" || true
        done < "$cross_repo_file"
    fi

    if [[ -f "$shared_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "shared_credential" "" "" "" || true
        done < "$shared_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "secrets_cross_repo_phase" "domain=$domain findings=$count repos_scanned=$org_repos"
    log "INFO" "secrets_cross_repo_phase complete: $count findings"
    return 0
}

secrets_cross_repo_phase "$@"
