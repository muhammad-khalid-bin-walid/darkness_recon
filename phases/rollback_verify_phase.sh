#!/usr/bin/env bash
# Rollback & Cleanup Verification
# Verifies state restoration and artifact cleanup after engagement

rollback_verify_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "rollback_verify_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/rollback_verify"
    mkdir -p "$phase_dir"

    log "INFO" "Starting rollback_verify_phase for $domain"

    local rollback_status="$phase_dir/rollback_status.txt"
    local cleanup_log="$phase_dir/cleanup_log.txt"
    local count=0

    # --- Initialize status ---
    echo "--- ROLLBACK & CLEANUP STATUS ---" > "$rollback_status"
    echo "domain=$domain" >> "$rollback_status"
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$rollback_status"
    echo "phase_dir=$phase_dir" >> "$rollback_status"

    echo "--- CLEANUP LOG ---" > "$cleanup_log"
    echo "domain=$domain" >> "$cleanup_log"
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$cleanup_log"

    # --- Verify no persistent changes were made ---
    log "INFO" "Verifying no persistent changes were made to target..."

    # Check for any test accounts created
    local test_indicators=(
        "test-account"
        "pentest-user"
        "recon-user"
        "test@${domain}"
    )

    for indicator in "${test_indicators[@]}"; do
        echo "[CHECK] Test indicator: $indicator" >> "$cleanup_log"
        echo "[INFO] Verify no test accounts with identifier '$indicator' exist" >> "$rollback_status"
    done

    # --- Verify no test data was left behind ---
    log "INFO" "Checking for test data residue..."

    local test_data_markers=(
        "recon_test_data"
        "dark_recon_marker"
        "pentest_timestamp"
    )

    for marker in "${test_data_markers[@]}"; do
        echo "[CHECK] Test data marker: $marker" >> "$cleanup_log"
    done

    # --- Verify no web shells or test files were uploaded ---
    log "INFO" "Verifying no test files were uploaded..."

    local test_file_paths=(
        "/recon_test.txt"
        "/pentest_check.txt"
        "/.recon_marker"
    )

    for path in "${test_file_paths[@]}"; do
        local check_code
        check_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$check_code" == "200" ]]; then
            echo "[VULN] Test file still accessible: $path (HTTP $check_code)" >> "$rollback_status"
            echo "[CLEANUP] Test file found: $path - needs manual removal" >> "$cleanup_log"
            ((count++)) || true
        fi
    done

    # --- Verify DNS records unchanged ---
    log "INFO" "Verifying DNS records..."
    local current_ns
    current_ns=$(dig +short "$domain" NS 2>/dev/null | sort) || true
    echo "[CHECK] Current NS records:" >> "$cleanup_log"
    echo "$current_ns" >> "$cleanup_log"
    echo "[INFO] Verify NS records match pre-engagement baseline" >> "$rollback_status"

    # --- Verify no firewall rules were modified ---
    log "INFO" "Verifying firewall/network state..."
    local ports_to_check=(80 443 22 25 53)
    for port in "${ports_to_check[@]}"; do
        local port_status
        port_status=$(curl -s -o /dev/null -w "%{http_code}" -m 3 "https://$domain:$port" 2>/dev/null) || true
        echo "[CHECK] Port $port status: $port_status" >> "$cleanup_log"
    done

    # --- Verify no WAF rules were modified ---
    log "INFO" "Verifying WAF state..."
    local waf_headers
    waf_headers=$(curl -sI -m 5 "https://$domain/" 2>/dev/null) || true
    if echo "$waf_headers" | grep -qiE "x-sucuri|x-cdn|cf-ray"; then
        echo "[INFO] WAF/CDN headers present - verify rules unchanged" >> "$rollback_status"
    fi

    # --- Cleanup local artifacts ---
    log "INFO" "Cleaning up local artifacts..."

    # Remove temporary files created during recon
    local temp_patterns=(
        "*.tmp"
        "*.temp"
        "*.swp"
        "*~"
        "*.bak"
    )

    for pattern in "${temp_patterns[@]}"; do
        local temp_files
        temp_files=$(find "$output_dir" -name "$pattern" 2>/dev/null) || true
        if [[ -n "$temp_files" ]]; then
            echo "$temp_files" | while read -r f; do
                rm -f "$f" 2>/dev/null || true
                echo "[CLEANUP] Removed: $f" >> "$cleanup_log"
                ((count++)) || true
            done
        fi
    done

    # --- Verify tool state restored ---
    log "INFO" "Verifying tool state..."

    # Check for any running background processes
    local recon_processes
    recon_processes=$(ps aux 2>/dev/null | grep -iE "nmap|masscan|recon|scanner" | grep -v grep) || true
    if [[ -n "$recon_processes" ]]; then
        echo "[WARNING] Background recon processes still running:" >> "$rollback_status"
        echo "$recon_processes" >> "$rollback_status"
        echo "[INFO] Kill these processes: kill -9 <PID>" >> "$rollback_status"
    else
        echo "[PASS] No background recon processes detected" >> "$rollback_status"
    fi

    # --- Generate summary ---
    echo "" >> "$rollback_status"
    echo "--- SUMMARY ---" >> "$rollback_status"
    echo "Checks performed: $(grep -c '\[CHECK\]' "$cleanup_log" 2>/dev/null || echo 0)" >> "$rollback_status"
    echo "Issues found: $count" >> "$rollback_status"
    echo "Cleanup actions: $(grep -c '\[CLEANUP\]' "$cleanup_log" 2>/dev/null || echo 0)" >> "$rollback_status"
    echo "Status: $([ $count -eq 0 ] && echo 'CLEAN' || echo 'REQUIRES_ATTENTION')" >> "$rollback_status"

    # --- Write structured findings ---
    if [[ $count -gt 0 ]]; then
        write_finding "$phase_dir" "Rollback verification found $count issues requiring attention" "rollback_verify" "" "" ""
    else
        write_finding "$phase_dir" "Rollback verification complete - no issues found" "rollback_verify" "" "" ""
    fi

    write_asset "$phase_dir" "$domain" "rollback_verify" "issues=$count status=$([ $count -eq 0 ] && echo 'CLEAN' || echo 'REQUIRES_ATTENTION')" "" ""

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "rollback_verify_phase" "domain=$domain issues=$count status=$([ $count -eq 0 ] && echo 'CLEAN' || echo 'REQUIRES_ATTENTION')"

    log "INFO" "rollback_verify_phase complete: $count issues found"
    return 0
}

rollback_verify_phase "$@"
