#!/bin/bash
# Track 16 - Secrets Deep | Phase 249: Secret Scanning Coverage Analysis
# Unmonitored repositories, gap detection

secrets_coverage_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "secrets_coverage_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/secrets_coverage"
    mkdir -p "$phase_dir"

    log "INFO" "Starting secrets_coverage_phase for $domain"

    local coverage_file="$phase_dir/coverage_analysis.txt"
    local gaps_file="$phase_dir/scanning_gaps.txt"
    local count=0

    # --- Enumerate all repositories ---
    log "INFO" "Enumerating all repositories for coverage analysis..."
    local all_repos="$phase_dir/all_repos.txt"
    curl -s "https://api.github.com/search/repositories?q=org:$domain&per_page=100" 2>/dev/null | \
        jq -r '.items[]? | .full_name + "|" + .default_branch + "|" + (.private|tostring) + "|" + (.pushed_at // "unknown")' 2>/dev/null \
        > "$all_repos" || true

    # Also search by domain name
    curl -s "https://api.github.com/search/repositories?q=$domain+in:name&per_page=100" 2>/dev/null | \
        jq -r '.items[]? | .full_name + "|" + .default_branch + "|" + (.private|tostring) + "|" + (.pushed_at // "unknown")' 2>/dev/null \
        >> "$all_repos" || true

    sort -u "$all_repos" > "${all_repos}.tmp" && mv "${all_repos}.tmp" "$all_repos" 2>/dev/null || true
    local total_repos
    total_repos=$(wc -l < "$all_repos" 2>/dev/null || echo 0)
    log "INFO" "Found $total_repos total repositories"

    # --- Check which repos have secret scanning enabled ---
    log "INFO" "Checking secret scanning configuration per repository..."
    local scanned=0
    local unscanned=0
    local no_scanning_config=0

    while IFS='|' read -r repo_name default_branch is_private last_push; do
        [[ -z "$repo_name" ]] && continue

        # Check for secret scanning push protection (GitHub)
        local ss_resp
        ss_resp=$(curl -s "https://api.github.com/repos/$repo_name" 2>/dev/null) || true

        local has_secret_scanning="false"
        local has_push_protection="false"

        if echo "$ss_resp" | jq -e '.security_and_analysis.secret_scanning.status' 2>/dev/null | grep -q '"enabled"'; then
            has_secret_scanning="true"
        fi
        if echo "$ss_resp" | jq -e '.security_and_analysis.secret_scanning_push_protection.status' 2>/dev/null | grep -q '"enabled"'; then
            has_push_protection="true"
        fi

        # Check for .github/secret-scanning.yml or .gitleaks.toml
        local custom_config="false"
        local config_check
        config_check=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://api.github.com/repos/$repo_name/contents/.gitleaks.toml" 2>/dev/null) || true
        if [[ "$config_check" == "200" ]]; then
            custom_config="true"
        fi
        config_check=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://api.github.com/repos/$repo_name/contents/.github/secret-scanning.yml" 2>/dev/null) || true
        if [[ "$config_check" == "200" ]]; then
            custom_config="true"
        fi

        local status="unknown"
        if [[ "$has_secret_scanning" == "true" && "$has_push_protection" == "true" ]]; then
            status="fully_protected"
            ((scanned++)) || true
        elif [[ "$has_secret_scanning" == "true" ]]; then
            status="scanning_only"
            ((scanned++)) || true
        elif [[ "$custom_config" == "true" ]]; then
            status="custom_tooling"
            ((scanned++)) || true
        else
            status="no_scanning"
            ((unscanned++)) || true
            ((no_scanning_config++)) || true
        fi

        echo "$repo_name|$status|secret_scanning=$has_secret_scanning|push_protection=$has_push_protection|custom=$custom_config|last_push=$last_push" >> "$coverage_file"
        echo "[COVERAGE] repo=$repo_name status=$status" >> "$coverage_file"

        if [[ "$status" == "no_scanning" ]]; then
            echo "[UNMONITORED] repo=$repo_name branch=$default_branch private=$is_private last_push=$last_push" >> "$gaps_file"
            ((count++)) || true
        fi
    done < "$all_repos"

    # --- Check for leaked .env or secrets in recent commits of unmonitored repos ---
    log "INFO" "Checking unmonitored repos for recent secret leaks..."
    if [[ -f "$gaps_file" ]]; then
        while IFS= read -r gap_line; do
            local repo_name
            repo_name=$(echo "$gap_line" | grep -oP 'repo=\K[^ ]+')
            [[ -z "$repo_name" ]] && continue

            # Check recent commits for secret-like files
            local commits_resp
            commits_resp=$(curl -s "https://api.github.com/repos/$repo_name/commits?per_page=10" 2>/dev/null) || true
            echo "$commits_resp" | jq -r '.[]? | .sha' 2>/dev/null | while IFS= read -r sha; do
                [[ -z "$sha" ]] && continue
                local commit_detail
                commit_detail=$(curl -s "https://api.github.com/repos/$repo_name/commits/$sha" 2>/dev/null) || true
                echo "$commit_detail" | jq -r '.files[]? | .filename' 2>/dev/null | while IFS= read -r filename; do
                    if echo "$filename" | grep -qiE '\.env|secret|credential|\.key|\.pem|keyfile|service.account'; then
                        echo "[SECRET_IN_COMMIT] repo=$repo_name sha=$sha file=$filename" >> "$gaps_file"
                        ((count++)) || true
                    fi
                done
            done
        done
    fi

    # --- Generate coverage summary ---
    log "INFO" "Generating coverage summary..."
    {
        echo "=== SECRET SCANNING COVERAGE REPORT ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Total Repositories: $total_repos"
        echo "Scanned/Protected: $scanned"
        echo "Unmonitored/Gaps: $unscanned"
        echo "No Scanning Config: $no_scanning_config"
        echo "Coverage Rate: $(( total_repos > 0 ? scanned * 100 / total_repos : 0 ))%"
        echo "========================================="
    } > "$phase_dir/coverage_summary.txt"

    # --- Write structured findings ---
    if [[ -f "$gaps_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "scanning_gap" "" "" "" || true
        done < "$gaps_file"
    fi

    if [[ -f "$coverage_file" ]]; then
        while IFS= read -r asset; do
            write_asset "$phase_dir" "$domain" "repo_coverage" "$asset" "" "" || true
        done < "$coverage_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "secrets_coverage_phase" "domain=$domain findings=$count total_repos=$total_repos unmonitored=$unscanned"
    log "INFO" "secrets_coverage_phase complete: $count gaps found"
    return 0
}

secrets_coverage_phase "$@"
