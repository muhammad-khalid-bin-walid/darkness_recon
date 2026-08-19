#!/usr/bin/env bash
# referral_abuse_phase.sh - Referral/invite-flow abuse testing, self-referral,
# code reuse, privilege escalation via referral.

referral_abuse_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "referral_abuse_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/referral_abuse"

    local results=0
    local abuse_file="$output_dir/referral_abuse/referral_abuse.txt"
    local invite_file="$output_dir/referral_abuse/invite_vulns.txt"
    local findings_file="$output_dir/referral_abuse/findings.json"

    log "INFO" "Starting referral abuse phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Discover referral/invite endpoints ---
    local referral_paths=(
        "/referral"
        "/invite"
        "/api/referral"
        "/api/invite"
        "/api/v1/referral"
        "/api/v1/invite"
        "/referrals"
        "/invites"
        "/refer"
        "/join"
        "/signup?ref="
        "/register?ref="
        "/api/referrals/claim"
        "/api/invites/accept"
        "/referral/claim"
        "/invite/accept"
        "/invite/claim"
        "/r/"
        "/i/"
    )

    local referral_tokens=("REFER" "INVITE" "PROMO" "GIFT" "SHARE")
    local test_codes=()
    for prefix in "${referral_tokens[@]}"; do
        for i in $(seq 1 5); do
            test_codes+=("${prefix}$(printf '%04d' $i)")
            test_codes+=("${prefix}-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 8)")
        done
    done

    for rpath in "${referral_paths[@]}"; do
        local url="https://${domain}${rpath}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" != "000" && "$status" != "404" ]]; then
            log "INFO" "Referral endpoint found: $url (HTTP $status)"

            echo "[REFERRAL-ENDPOINT] $url - HTTP $status" >> "$abuse_file"
            ((results++)) || true

            write_endpoint "{\"url\":\"$url\",\"method\":\"GET\",\"status\":$status,\"phase\":\"referral_abuse\"}" \
                "$findings_file" 2>/dev/null || true

            # --- Test for referral code reuse ---
            for code in "${test_codes[@]}"; do
                local resp_status resp_body
                resp_body=$(curl -s -m 10 -w "\n%{http_code}" "${url}?code=${code}" 2>/dev/null || true)
                resp_status=$(echo "$resp_body" | tail -1)

                if [[ "$resp_status" == "200" ]]; then
                    echo "[CODE-VALID] $url - Referral code accepted: $code" >> "$abuse_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"referral_code_accepted\",\"url\":\"$url\",\"code\":\"$code\",\"severity\":\"MEDIUM\",\"evidence\":\"Referral code accepted via GET parameter\"}" \
                        "$findings_file" 2>/dev/null || true
                fi
            done

            # --- Test self-referral via POST ---
            local self_ref_payloads=(
                '{"email":"self@test.com","referral_code":"SELF"}'
                '{"email":"self@test.com","referrer":"self@test.com"}'
                '{"invited_by":"self@test.com","email":"self@test.com"}'
                '{"referral":"same","email":"self@test.com"}'
            )

            for payload in "${self_ref_payloads[@]}"; do
                local post_resp post_status
                post_resp=$(curl -s -m 10 -w "\n%{http_code}" -X POST \
                    -H "Content-Type: application/json" \
                    -d "$payload" \
                    "$url" 2>/dev/null || true)
                post_status=$(echo "$post_resp" | tail -1)

                if [[ "$post_status" == "200" || "$post_status" == "201" ]]; then
                    echo "[SELF-REFERRAL] $url - Self-referral accepted: $payload" >> "$invite_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"self_referral\",\"url\":\"$url\",\"payload\":\"$payload\",\"severity\":\"HIGH\",\"evidence\":\"Self-referral accepted without validation\"}" \
                        "$findings_file" 2>/dev/null || true
                fi
            done

            # --- Test invite code brute-force ---
            local invite_code_paths=(
                "${url}/claim"
                "${url}/verify"
                "${url}/validate"
            )

            for icpath in "${invite_code_paths[@]}"; do
                for code in "${test_codes[@]}"; do
                    local ic_status
                    ic_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "${icpath}?code=${code}" 2>/dev/null || echo "000")

                    if [[ "$ic_status" == "200" || "$ic_status" == "201" ]]; then
                        echo "[INVITE-BRUTE] $icpath - Valid invite code found: $code" >> "$invite_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"invite_brute_force\",\"url\":\"$icpath\",\"code\":\"$code\",\"severity\":\"HIGH\",\"evidence\":\"Invite code guessable/brute-forceable\"}" \
                            "$findings_file" 2>/dev/null || true
                    fi
                done
            done

            # --- Test referral privilege escalation ---
            local priv_esc_payloads=(
                '{"referral_code":"admin","role":"admin"}'
                '{"referral":"admin","privilege":"admin"}'
                '{"code":"admin","upgrade":true}'
                '{"invite_code":"VIP","tier":"premium"}'
            )

            for payload in "${priv_esc_payloads[@]}"; do
                local pe_resp pe_status
                pe_resp=$(curl -s -m 10 -w "\n%{http_code}" -X POST \
                    -H "Content-Type: application/json" \
                    -d "$payload" \
                    "$url" 2>/dev/null || true)
                pe_status=$(echo "$pe_resp" | tail -1)

                if [[ "$pe_status" == "200" || "$pe_status" == "201" ]]; then
                    echo "[PRIV-ESC-REFERRAL] $url - Privilege escalation via referral: $payload" >> "$invite_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"referral_privilege_escalation\",\"url\":\"$url\",\"payload\":\"$payload\",\"severity\":\"CRITICAL\",\"evidence\":\"Referral endpoint accepts privilege escalation parameters\"}" \
                        "$findings_file" 2>/dev/null || true
                fi
            done

            # --- Test referral rate limiting ---
            local rl_success=0
            for i in $(seq 1 20); do
                local rl_status
                rl_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -X POST \
                    -H "Content-Type: application/json" \
                    -d "{\"email\":\"rate_test_${i}@test.com\",\"referral_code\":\"TEST\"}" \
                    "$url" 2>/dev/null || echo "000")

                if [[ "$rl_status" == "200" || "$rl_status" == "201" ]]; then
                    ((rl_success++)) || true
                fi
            done

            if [[ "$rl_success" -ge 15 ]]; then
                echo "[NO-RATE-LIMIT] $url - No rate limiting on referral endpoint ($rl_success/20 succeeded)" >> "$invite_file"
                ((results++)) || true

                write_finding "{\"type\":\"referral_no_rate_limit\",\"url\":\"$url\",\"success_count\":$rl_success,\"severity\":\"MEDIUM\",\"evidence\":\"Referral endpoint lacks rate limiting\"}" \
                    "$findings_file" 2>/dev/null || true
            fi
        fi
    done

    # Write count
    echo "$results" > "$output_dir/referral_abuse/count.txt"

    py_log "INFO" "referral_abuse_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Referral abuse phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    referral_abuse_phase "$@"
fi
