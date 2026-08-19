#!/bin/bash
# Track 16 - Secrets Deep | Phase 250: False Positive Tuning
# Pattern refinement, whitelist management

secrets_fp_tuning_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "secrets_fp_tuning_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/secrets_fp_tuning"
    mkdir -p "$phase_dir"

    log "INFO" "Starting secrets_fp_tuning_phase for $domain"

    local fp_file="$phase_dir/fp_tuning_report.txt"
    local patterns_file="$phase_dir/refined_patterns.txt"
    local count=0

    # --- Aggregate all findings from secrets phases ---
    log "INFO" "Aggregating findings from all secrets phases..."
    local all_findings="$phase_dir/all_raw_findings.txt"
    : > "$all_findings"

    local secrets_dirs=(
        "$output_dir/secrets_entropy"
        "$output_dir/secrets_live_check"
        "$output_dir/secrets_git_history"
        "$output_dir/secrets_env_exposure"
        "$output_dir/secrets_api_key_detect"
        "$output_dir/secrets_rotation_age"
        "$output_dir/secrets_cross_repo"
        "$output_dir/secrets_cicd"
    )

    for sdir in "${secrets_dirs[@]}"; do
        [[ -d "$sdir" ]] || continue
        while IFS= read -r -d '' f; do
            cat "$f" >> "$all_findings" 2>/dev/null || true
        done < <(find "$sdir" -name '*.txt' -print0 2>/dev/null)
    done

    local total_findings
    total_findings=$(wc -l < "$all_findings" 2>/dev/null || echo 0)
    log "INFO" "Total raw findings to tune: $total_findings"

    if (( total_findings == 0 )); then
        echo "0" > "$phase_dir/count.txt"
        log "INFO" "No findings to tune"
        return 0
    fi

    # --- Known false positive patterns ---
    log "INFO" "Applying false positive filters..."
    declare -A FP_PATTERNS=(
        ["example_key"]="(example|test|sample|placeholder|dummy|fake|xxx|your[-_]key)"
        ["env_placeholder"]="(\$\{[A-Z_]+\}|<[A-Z_]+>|\{\{[A-Z_]+\}\}|__[A-Z_]+__)"
        ["uuid_not_key"]="^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        ["hash_not_key"]="^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$"
        ["timestamp"]="(1[3-9][0-9]{8,}|20[0-9]{11,})"
        ["version_number"]="v?[0-9]+\.[0-9]+\.[0-9]+(-[a-z]+)?"
        ["email_address"]="[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        ["ip_address"]="([0-9]{1,3}\.){3}[0-9]{1,3}"
        ["long_hex"]="^[0-9a-f]{20,}$"
        ["base64_not_secret"]="(iVBOR|UEsDB|H4sI|JVBER|QkFOD|R0lG|UklGR)"
    )

    local false_positives="$phase_dir/false_positives.txt"
    local confirmed_findings="$phase_dir/confirmed_findings.txt"
    : > "$false_positives"
    : > "$confirmed_findings"

    while IFS= read -r finding; do
        [[ -z "$finding" ]] && continue
        local is_fp=false

        for fp_name in "${!FP_PATTERNS[@]}"; do
            local fp_pat="${FP_PATTERNS[$fp_name]}"
            if echo "$finding" | grep -qiE "$fp_pat"; then
                echo "[FP] $finding (matched: $fp_name)" >> "$false_positives"
                is_fp=true
                ((count++)) || true
                break
            fi
        done

        if [[ "$is_fp" == "false" ]]; then
            echo "$finding" >> "$confirmed_findings"
        fi
    done < "$all_findings"

    local confirmed_count
    confirmed_count=$(wc -l < "$confirmed_findings" 2>/dev/null || echo 0)
    local fp_count
    fp_count=$(wc -l < "$false_positives" 2>/dev/null || echo 0)

    # --- Generate refined patterns ---
    log "INFO" "Generating refined detection patterns..."
    {
        echo "# Refined Secret Detection Patterns for $domain"
        echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# Total findings: $total_findings | Confirmed: $confirmed_count | False positives: $fp_count"
        echo ""
        echo "# --- Exclude these patterns (known FP) ---"
        for fp_name in "${!FP_PATTERNS[@]}"; do
            echo "# $fp_name: ${FP_PATTERNS[$fp_name]}"
        done
        echo ""
        echo "# --- High-confidence patterns to keep ---"
        echo "AKIA[0-9A-Z]{16}           # AWS Access Key"
        echo "ghp_[a-zA-Z0-9]{36}       # GitHub PAT"
        echo "sk-[a-zA-Z0-9]{48}        # OpenAI Key"
        echo "xox[bpsar]-[a-zA-Z0-9-]+  # Slack Token"
        echo "SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}  # SendGrid"
        echo "sk_live_[0-9a-zA-Z]{24,}  # Stripe Live Key"
        echo "AIza[0-9A-Za-z_-]{35}     # Google API Key"
    } > "$patterns_file"

    # --- Generate FP tuning report ---
    log "INFO" "Generating FP tuning report..."
    {
        echo "=== FALSE POSITIVE TUNING REPORT ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Total Raw Findings: $total_findings"
        echo "Confirmed Findings: $confirmed_count"
        echo "False Positives Filtered: $fp_count"
        if (( total_findings > 0 )); then
            echo "FP Rate: $(( fp_count * 100 / total_findings ))%"
        else
            echo "FP Rate: 0%"
        fi
        echo ""
        echo "--- Top FP Categories ---"
        if [[ -f "$false_positives" ]]; then
            grep -oP '\(matched: \K[^)]+' "$false_positives" 2>/dev/null | sort | uniq -c | sort -rn | head -10
        fi
        echo ""
        echo "--- Recommendations ---"
        echo "1. Update scanning tools to exclude matched FP patterns"
        echo "2. Add confirmed FPs to project-level whitelist"
        echo "3. Review patterns: $patterns_file"
        echo "======================================"
    } > "$fp_file"

    # --- Write structured findings ---
    if [[ -f "$confirmed_findings" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "confirmed_secret" "" "" "" || true
        done < "$confirmed_findings"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "secrets_fp_tuning_phase" "domain=$domain total=$total_findings confirmed=$confirmed_count false_positives=$fp_count"
    log "INFO" "secrets_fp_tuning_phase complete: $confirmed_count confirmed, $fp_count false positives filtered"
    return 0
}

secrets_fp_tuning_phase "$@"
