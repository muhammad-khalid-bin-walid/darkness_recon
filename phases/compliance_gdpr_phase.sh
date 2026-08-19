#!/usr/bin/env bash
# Phase 264: GDPR Compliance Checking, Data Processing Audit, Consent Verification
# Track 18 - Compliance

compliance_gdpr() {
    local domain="${1:?Usage: compliance_gdpr <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/compliance_gdpr"
    mkdir -p "$phase_dir"

    log "INFO" "[GDPR] Starting GDPR compliance checking for $domain"

    local gdpr_compliance="$phase_dir/gdpr_compliance.txt"
    local data_processing="$phase_dir/data_processing.txt"

    : > "$gdpr_compliance"
    : > "$data_processing"

    local count=0

    if tool_available "curl"; then
        log "INFO" "[GDPR] Checking privacy policy and consent mechanisms"

        local privacy_page
        privacy_page=$(curl -sL --max-time 15 "https://$domain/privacy" 2>/dev/null | head -200 || true)
        local privacy_status
        privacy_status=$(curl -sI --max-time 10 "https://$domain/privacy" 2>/dev/null | head -1 || true)

        if echo "$privacy_status" | grep -q "200"; then
            echo "GDPR-Art.13: Privacy policy accessible - PASS" >> "$gdpr_compliance"
            echo "Evidence: /privacy returned 200" >> "$data_processing"
            write_finding "$phase_dir" "GDPR-Art.13" "Privacy policy found" "critical" "passed"
            count=$((count + 1))
        else
            echo "GDPR-Art.13: Privacy policy not found - FAIL" >> "$gdpr_compliance"
            write_finding "$phase_dir" "GDPR-Art.13" "Privacy policy missing" "critical" "failed"
            count=$((count + 1))
        fi

        local tos_page
        tos_page=$(curl -sI --max-time 10 "https://$domain/terms" 2>/dev/null | head -1 || true)
        if echo "$tos_page" | grep -q "200"; then
            echo "GDPR-Art.13: Terms of service accessible - PASS" >> "$gdpr_compliance"
            count=$((count + 1))
        else
            echo "GDPR-Art.13: Terms of service not found - FAIL" >> "$gdpr_compliance"
            count=$((count + 1))
        fi

        local cookie_page
        cookie_page=$(curl -sI --max-time 10 "https://$domain/cookie-policy" 2>/dev/null | head -1 || true)
        if echo "$cookie_page" | grep -q "200"; then
            echo "GDPR-Art.7: Cookie policy present - PASS" >> "$gdpr_compliance"
            echo "Evidence: /cookie-policy accessible" >> "$data_processing"
            count=$((count + 1))
        else
            echo "GDPR-Art.7: Cookie policy missing - FAIL" >> "$gdpr_compliance"
            count=$((count + 1))
        fi

        log "INFO" "[GDPR] Checking for cookie consent banner indicators"
        local body
        body=$(curl -sL --max-time 15 "https://$domain" 2>/dev/null || true)
        if echo "$body" | grep -qi "cookie-consent\|cookiebot\|onetrust\|osano\|cookie-consent-banner"; then
            echo "GDPR-Art.7: Cookie consent mechanism detected - PASS" >> "$gdpr_compliance"
            echo "Evidence: Cookie consent banner detected" >> "$data_processing"
            write_finding "$phase_dir" "GDPR-Art.7" "Cookie consent detected" "high" "passed"
            count=$((count + 1))
        else
            echo "GDPR-Art.7: Cookie consent mechanism not detected - FAIL" >> "$gdpr_compliance"
            write_finding "$phase_dir" "GDPR-Art.7" "No cookie consent" "high" "failed"
            count=$((count + 1))
        fi
    fi

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "gdpr_complete" "GDPR compliance check complete: $count items checked"
    log "INFO" "[GDPR] Completed: $count items checked"

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_endpoint "$phase_dir" "https://$domain" "GET" "GDPR compliance target"

    return 0
}
