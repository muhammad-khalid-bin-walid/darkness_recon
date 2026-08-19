#!/usr/bin/env bash
# Manual Review Queue & Human Verification
# Generates queue for findings requiring human verification and confidence thresholds

manual_review_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "manual_review_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/manual_review"
    mkdir -p "$phase_dir"

    log "INFO" "Starting manual_review_phase for $domain"

    local manual_queue="$phase_dir/manual_queue.txt"
    local review_status="$phase_dir/review_status.txt"
    local count=0

    # --- Collect all findings for review triage ---
    log "INFO" "Collecting findings for manual review triage..."

    local all_findings_file="$phase_dir/all_findings_for_review.txt"
    find "$output_dir" -name "*_vulns.txt" -exec cat {} \; > "$all_findings_file" 2>/dev/null || true

    local total_findings
    total_findings=$(wc -l < "$all_findings_file" 2>/dev/null || echo "0") || true
    total_findings=$(echo "$total_findings" | tr -d ' ')

    echo "--- MANUAL REVIEW QUEUE ---" > "$manual_queue"
    echo "domain=$domain" >> "$manual_queue"
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$manual_queue"
    echo "total_findings=$total_findings" >> "$manual_queue"
    echo "" >> "$manual_queue"

    # --- Confidence-based triage ---
    log "INFO" "Triaging findings by confidence level..."

    local high_confidence=0
    local medium_confidence=0
    local low_confidence=0

    # High confidence patterns (definite vulnerabilities)
    local high_patterns=(
        "default credential"
        "default password"
        "open relay"
        "unauthenticated access"
        "SQL injection"
        "remote code execution"
        "RCE"
        "directory traversal"
        "file inclusion"
        "SSRF"
        "credentials leaked"
        "API key exposed"
        "private key exposed"
        "backup.*accessible"
        "directory listing"
    )

    # Medium confidence patterns (likely vulnerabilities)
    local medium_patterns=(
        "header leakage"
        "information disclosure"
        "missing.*header"
        "weak.*policy"
        "zone transfer"
        "server header"
        "debug.*enabled"
        "verbose.*error"
    )

    # Low confidence patterns (needs verification)
    local low_patterns=(
        "potential"
        "possible"
        "may indicate"
        "suspected"
        "could be"
    )

    while IFS= read -r finding; do
        [[ -z "$finding" ]] && continue
        local classified=false

        # Check high confidence
        for pattern in "${high_patterns[@]}"; do
            if echo "$finding" | grep -qiE "$pattern"; then
                echo "[HIGH] $finding" >> "$manual_queue"
                ((high_confidence++)) || true
                classified=true
                break
            fi
        done

        if ! $classified; then
            # Check medium confidence
            for pattern in "${medium_patterns[@]}"; do
                if echo "$finding" | grep -qiE "$pattern"; then
                    echo "[MEDIUM] $finding" >> "$manual_queue"
                    ((medium_confidence++)) || true
                    classified=true
                    break
                fi
            done
        fi

        if ! $classified; then
            # Check low confidence
            for pattern in "${low_patterns[@]}"; do
                if echo "$finding" | grep -qiE "$pattern"; then
                    echo "[LOW] $finding" >> "$manual_queue"
                    ((low_confidence++)) || true
                    classified=true
                    break
                fi
            done
        fi

        if ! $classified; then
            # Default to medium
            echo "[MEDIUM] $finding" >> "$manual_queue"
            ((medium_confidence++)) || true
        fi
    done < "$all_findings_file"

    # --- Generate review status ---
    echo "--- REVIEW STATUS ---" > "$review_status"
    echo "domain=$domain" >> "$review_status"
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$review_status"
    echo "total_findings=$total_findings" >> "$review_status"
    echo "high_confidence=$high_confidence" >> "$review_status"
    echo "medium_confidence=$medium_confidence" >> "$review_status"
    echo "low_confidence=$low_confidence" >> "$review_status"
    echo "review_status=QUEUED" >> "$review_status"

    # --- Priority queue ordering ---
    echo "" >> "$manual_queue"
    echo "--- PRIORITY ORDER ---" >> "$manual_queue"
    echo "1. HIGH confidence findings ($high_confidence) - immediate review" >> "$manual_queue"
    echo "2. MEDIUM confidence findings ($medium_confidence) - review within 24h" >> "$manual_queue"
    echo "3. LOW confidence findings ($low_confidence) - review when time permits" >> "$manual_queue"

    # --- Add human verification checklist ---
    echo "" >> "$manual_queue"
    echo "--- VERIFICATION CHECKLIST ---" >> "$manual_queue"
    echo "[ ] Verify each finding is not a false positive" >> "$manual_queue"
    echo "[ ] Confirm exploitation feasibility" >> "$manual_queue"
    echo "[ ] Assess business impact" >> "$manual_queue"
    echo "[ ] Determine remediation priority" >> "$manual_queue"
    echo "[ ] Assign to team member for deep-dive" >> "$manual_queue"

    count=$((high_confidence + medium_confidence + low_confidence))

    # --- Write structured findings ---
    write_finding "$phase_dir" "Manual review queue generated: $high_confidence high, $medium_confidence medium, $low_confidence low confidence findings" "manual_review" "" "" ""
    write_asset "$phase_dir" "$domain" "manual_review" "total=$total_findings queued=$count" "" ""

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "manual_review_phase" "domain=$domain total=$total_findings high=$high_confidence medium=$medium_confidence low=$low_confidence"

    log "INFO" "manual_review_phase complete: $count findings queued for review"
    return 0
}

manual_review_phase "$@"
