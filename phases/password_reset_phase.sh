#!/usr/bin/env bash
# password_reset_phase.sh - Password reset flow methodology, token prediction,
# host header injection in reset flow.

password_reset_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "password_reset_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/password_reset"

    local results=0
    local vulns_file="$output_dir/password_reset/password_reset_vulns.txt"
    local flows_file="$output_dir/password_reset/reset_flows.txt"

    log "INFO" "Starting password reset analysis for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # Discover password reset endpoints
    local reset_endpoints=(
        "/api/password/reset"
        "/api/forgot-password"
        "/api/reset-password"
        "/api/auth/reset"
        "/api/auth/forgot"
        "/api/user/reset-password"
        "/api/account/reset"
        "/password/reset"
        "/forgot-password"
        "/reset-password"
        "/auth/forgot-password"
        "/auth/reset"
    )

    local found_reset_endpoint=""

    for ep in "${reset_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" != "404" && "$status" != "000" ]]; then
            echo "[RESET-ENDPOINT] $url - HTTP $status" >> "$flows_file"
            ((results++)) || true

            if [[ -z "$found_reset_endpoint" ]]; then
                found_reset_endpoint="$url"
            fi

            # Check response for token length hint
            local body
            body=$(curl -s -m 10 "$url" 2>/dev/null || true)
            local token_hint
            token_hint=$(echo "$body" | grep -ioE "(token|code|key|hash)[^a-z0-9]{0,10}[a-z0-9]{16,}" || true)
            if [[ -n "$token_hint" ]]; then
                echo "[TOKEN-HINT] $ep - Response contains potential token pattern: $token_hint" >> "$flows_file"
                ((results++)) || true
            fi
        fi
    done

    # Host header injection in password reset
    log "INFO" "Testing host header injection in password reset"

    if [[ -n "$found_reset_endpoint" ]]; then
        # Test with different host header values
        local malicious_hosts=(
            "evil.com"
            "attacker.com"
            "${domain}.evil.com"
            "evil-${domain}.com"
            "localhost"
            "127.0.0.1"
            "${domain}%0d%0aHost:evil.com"
            "${domain}%0d%0a%0d%0aHost:evil.com"
        )

        for mhost in "${malicious_hosts[@]}"; do
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -H "Host: $mhost" \
                -X POST -d "email=test@test.com" \
                "$found_reset_endpoint" 2>/dev/null || echo "000")

            if [[ "$status" == "200" || "$status" == "201" || "$status" == "202" ]]; then
                # Check if response body reflects the malicious host
                local body
                body=$(curl -s -m 10 \
                    -H "Host: $mhost" \
                    -X POST -d "email=test@test.com" \
                    "$found_reset_endpoint" 2>/dev/null || true)

                if echo "$body" | grep -qi "$mhost"; then
                    echo "[HOST-INJECT] $found_reset_endpoint - Host header injection: $mhost reflected in response" >> "$vulns_file"
                    ((results++)) || true
                fi
            fi
        done

        # Test with X-Forwarded-Host
        local xfwd_hosts=(
            "evil.com"
            "attacker.com"
            "${domain}.evil.com"
        )

        for xfwd in "${xfwd_hosts[@]}"; do
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -H "X-Forwarded-Host: $xfwd" \
                -X POST -d "email=test@test.com" \
                "$found_reset_endpoint" 2>/dev/null || echo "000")

            if [[ "$status" == "200" || "$status" == "201" || "$status" == "202" ]]; then
                local body
                body=$(curl -s -m 10 \
                    -H "X-Forwarded-Host: $xfwd" \
                    -X POST -d "email=test@test.com" \
                    "$found_reset_endpoint" 2>/dev/null || true)

                if echo "$body" | grep -qi "$xfwd"; then
                    echo "[XFORWARD-HOST-INJECT] $found_reset_endpoint - X-Forwarded-Host injection: $xfwd reflected" >> "$vulns_file"
                    ((results++)) || true
                fi
            fi
        done
    fi

    # Token analysis - check for predictable tokens
    log "INFO" "Analyzing reset token characteristics"

    # Check if reset tokens are in predictable locations
    local token_endpoints=(
        "/api/reset/verify"
        "/api/reset/confirm"
        "/api/password/confirm"
        "/api/auth/reset/confirm"
    )

    for ep in "${token_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        # Test with weak/sequential tokens
        local weak_tokens=(
            "1"
            "000000"
            "123456"
            "admin"
            "test"
            "token"
            "aaaaaa"
        )

        for token in "${weak_tokens[@]}"; do
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -X POST -d "token=$token&password=newpass123" \
                "$url" 2>/dev/null || echo "000")

            if [[ "$status" == "200" || "$status" == "201" ]]; then
                echo "[WEAK-TOKEN] $url - Accepted weak token: $token (HTTP $status)" >> "$vulns_file"
                ((results++)) || true
            fi
        done
    done

    # Test for token leakage in response headers/body
    log "INFO" "Checking for token leakage"

    if [[ -n "$found_reset_endpoint" ]]; then
        local full_response
        full_response=$(curl -sD - -m 10 \
            -X POST -d "email=test@test.com" \
            "$found_reset_endpoint" 2>/dev/null || true)

        # Check for token in response headers
        local token_headers
        token_headers=$(echo "$full_response" | grep -iE "(token|reset.*code|confirmation)" || true)
        if [[ -n "$token_headers" ]]; then
            echo "[TOKEN-IN-HEADERS] $found_reset_endpoint - Token/reference in response headers:" >> "$vulns_file"
            echo "$token_headers" >> "$vulns_file"
            echo "---" >> "$vulns_file"
            ((results++)) || true
        fi

        # Check for token in URL parameters
        local redirect_url
        redirect_url=$(echo "$full_response" | grep -iE "location:" | head -1 || true)
        if [[ -n "$redirect_url" ]] && echo "$redirect_url" | grep -qiE "(token|code|key)"; then
            echo "[TOKEN-IN-URL] $found_reset_endpoint - Token in redirect URL: $redirect_url" >> "$vulns_file"
            ((results++)) || true
        fi
    fi

    # Test for email enumeration via reset endpoint
    log "INFO" "Testing email enumeration"
    if [[ -n "$found_reset_endpoint" ]]; then
        local resp_valid
        resp_valid=$(curl -s -m 10 -X POST -d "email=admin@$domain" "$found_reset_endpoint" 2>/dev/null || true)
        local resp_invalid
        resp_invalid=$(curl -s -m 10 -X POST -d "email=nonexistent@invalid.test" "$found_reset_endpoint" 2>/dev/null || true)

        if [[ "$resp_valid" != "$resp_invalid" ]]; then
            echo "[EMAIL-ENUM] $found_reset_endpoint - Different responses for valid vs invalid email" >> "$vulns_file"
            ((results++)) || true
        fi
    fi

    # Test rate limiting on reset endpoint
    log "INFO" "Testing rate limiting on reset flow"
    if [[ -n "$found_reset_endpoint" ]]; then
        local rl_count=0
        for i in $(seq 1 10); do
            local rl_status
            rl_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
                -X POST -d "email=test@test.com" \
                "$found_reset_endpoint" 2>/dev/null || echo "000")
            if [[ "$rl_status" == "200" || "$rl_status" == "201" || "$rl_status" == "202" ]]; then
                ((rl_count++)) || true
            fi
        done

        if [[ "$rl_count" -ge 10 ]]; then
            echo "[NO-RL-RESET] $found_reset_endpoint - No rate limiting: $rl_count/10 requests succeeded" >> "$vulns_file"
            ((results++)) || true
        fi
    fi

    # Check for reset token inReferer/Origin headers
    log "INFO" "Testing reset token in HTTP headers"
    if [[ -n "$found_reset_endpoint" ]]; then
        local referrers=(
            "https://evil.com/reset?token=stolen"
            "https://evil.com/callback?code=123"
        )

        for ref in "${referrers[@]}"; do
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -H "Referer: $ref" \
                -X POST -d "email=test@test.com" \
                "$found_reset_endpoint" 2>/dev/null || echo "000")

            if [[ "$status" == "200" ]]; then
                echo "[REFERER-LEAK] $found_reset_endpoint - Referer header accepted: $ref" >> "$vulns_file"
                ((results++)) || true
            fi
        done
    fi

    # Write count
    echo "$results" > "$output_dir/password_reset/count.txt"

    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "password_reset" "HIGH" "$line" 2>/dev/null || true
        done < "$vulns_file" 2>/dev/null || true
    fi

    py_log "INFO" "password_reset_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Password reset phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    password_reset_phase "$@"
fi
