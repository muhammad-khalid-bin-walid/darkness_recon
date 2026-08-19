#!/usr/bin/env bash
# business_workflow_phase.sh - Business-workflow abuse detection,
# workflow state manipulation, step skipping, race conditions in workflows.

business_workflow_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "business_workflow_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/business_workflow"

    local results=0
    local abuse_file="$output_dir/business_workflow/workflow_abuse.txt"
    local states_file="$output_dir/business_workflow/workflow_states.txt"

    log "INFO" "Starting business workflow abuse testing for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    local temp_dir
    temp_dir=$(mktemp -d)

    # Phase 1: Discover multi-step workflows
    log "INFO" "Phase 1: Discovering multi-step workflows"

    local workflow_endpoints=(
        "/api/checkout"
        "/api/register"
        "/api/onboarding"
        "/api/order"
        "/api/payment"
        "/api/transfer"
        "/api/settings"
        "/api/profile"
        "/api/password/reset"
        "/api/verify"
        "/api/2fa/setup"
        "/api/subscription"
    )

    local discovered_workflows=()
    local workflow_types=()

    for endpoint in "${workflow_endpoints[@]}"; do
        local url="https://${domain}${endpoint}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" != "404" && "$status" != "000" ]]; then
            echo "[WORKFLOW-DISCOVERED] $endpoint (HTTP $status)" >> "$states_file"
            discovered_workflows+=("$endpoint")
            ((results++)) || true
        fi

        # Check POST variant
        local post_status
        post_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST -d "test=1" "$url" 2>/dev/null || echo "000")
        if [[ "$post_status" != "404" && "$post_status" != "000" ]]; then
            echo "[WORKFLOW-POST] $endpoint accepts POST (HTTP $post_status)" >> "$states_file"
        fi
    done

    # Phase 2: Workflow state manipulation - step skipping
    log "INFO" "Phase 2: Testing workflow step skipping"

    local checkout_steps=(
        "/api/checkout/init"
        "/api/checkout/cart"
        "/api/checkout/shipping"
        "/api/checkout/payment"
        "/api/checkout/confirm"
        "/api/checkout/complete"
    )

    for step in "${checkout_steps[@]}"; do
        local url="https://${domain}${step}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" != "404" ]]; then
            # Try accessing final step directly without prior steps
            echo "[STEP-SKIP] $step accessible directly (HTTP $status) without prior workflow state" >> "$abuse_file"
            ((results++)) || true

            # Try posting to later steps without initialization
            local post_status
            post_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
                -d "step=complete&bypass_init=true" "$url" 2>/dev/null || echo "000")
            if [[ "$post_status" != "404" && "$post_status" != "000" ]]; then
                echo "[STEP-SKIP-POST] $step accepts POST without workflow state (HTTP $post_status)" >> "$abuse_file"
                ((results++)) || true
            fi
        fi
    done

    # Phase 3: Password reset workflow abuse
    log "INFO" "Phase 3: Password reset workflow abuse"

    local reset_endpoints=(
        "/api/password/reset"
        "/api/password/forgot"
        "/api/reset"
        "/api/auth/reset"
        "/forgot-password"
        "/reset-password"
    )

    for ep in "${reset_endpoints[@]}"; do
        local url="https://${domain}${ep}"

        # Test step skipping - try to complete without requesting reset
        local complete_status
        complete_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
            -d "token=fake&password=newpass123" "${url}/complete" 2>/dev/null || echo "000")
        if [[ "$complete_status" != "404" && "$complete_status" != "000" ]]; then
            echo "[RESET-SKIP] ${ep}/complete accessible without valid reset token (HTTP $complete_status)" >> "$abuse_file"
            ((results++)) || true
        fi

        # Test token prediction/generation
        local token_resp
        token_resp=$(curl -s -m 10 -X POST -d "email=test@test.com" "$url" 2>/dev/null || true)
        if echo "$token_resp" | grep -qiE "(token|code|reset)" 2>/dev/null; then
            echo "[RESET-TOKEN-LEAK] $ep returns token in response body" >> "$abuse_file"
            ((results++)) || true
        fi

        # Test email parameter manipulation
        local email_status
        email_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
            -d "email=admin@${domain}" "$url" 2>/dev/null || echo "000")
        local user_status
        user_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
            -d "email=user@${domain}" "$url" 2>/dev/null || echo "000")
        if [[ "$email_status" == "$user_status" ]]; then
            echo "[RESET-USER-ENUM] $ep same response for valid/invalid emails (no user enumeration protection)" >> "$abuse_file"
            ((results++)) || true
        fi
    done

    # Phase 4: Registration workflow abuse
    log "INFO" "Phase 4: Registration workflow abuse"

    local reg_endpoints=(
        "/api/register"
        "/api/signup"
        "/api/user/create"
        "/register"
        "/signup"
    )

    for ep in "${reg_endpoints[@]}"; do
        local url="https://${domain}${ep}"

        # Test duplicate registration
        local dup_status
        dup_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
            -d "email=admin@${domain}&password=test123" "$url" 2>/dev/null || echo "000")

        if [[ "$dup_status" == "200" || "$dup_status" == "201" ]]; then
            # Try registering with same email again
            local dup2_status
            dup2_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
                -d "email=admin@${domain}&password=test456" "$url" 2>/dev/null || echo "000")
            if [[ "$dup2_status" == "200" || "$dup2_status" == "201" ]]; then
                echo "[REG-DUPLICATE] $ep allows duplicate registrations with same email" >> "$abuse_file"
                ((results++)) || true
            fi
        fi

        # Test role injection
        local role_status
        role_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
            -d "email=test@test.com&password=test123&role=admin" "$url" 2>/dev/null || echo "000")
        if [[ "$role_status" == "200" || "$role_status" == "201" ]]; then
            echo "[REG-PRIV-ESC] $ep accepts role parameter in registration (HTTP $role_status)" >> "$abuse_file"
            ((results++)) || true
        fi

        # Test email verification bypass
        local verify_endpoints=(
            "${ep}/verify"
            "${ep}/confirm"
            "/api/verify"
            "/api/email/verify"
        )
        for vep in "${verify_endpoints[@]}"; do
            local verify_url="https://${domain}${vep}"
            local verify_status
            verify_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                "$verify_url?token=fake&email=test@test.com" 2>/dev/null || echo "000")
            if [[ "$verify_status" != "404" && "$verify_status" != "000" ]]; then
                echo "[REG-VERIFY-BYPASS] $vep accepts arbitrary verification token (HTTP $verify_status)" >> "$abuse_file"
                ((results++)) || true
            fi
        done
    done

    # Phase 5: Payment/checkout workflow race conditions
    log "INFO" "Phase 5: Payment workflow race conditions"

    local payment_endpoints=(
        "/api/payment/process"
        "/api/checkout/submit"
        "/api/order/create"
        "/api/purchase/complete"
        "/api/transfer/send"
    )

    for ep in "${payment_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local base_status
        base_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
            -X POST -d "amount=100&item=test" "$url" 2>/dev/null || echo "000")

        if [[ "$base_status" != "404" && "$base_status" != "000" ]]; then
            # Race condition: concurrent payment submissions
            local race_pids=()
            local race_file="$temp_dir/race_${ep//\//_}.txt"

            for i in $(seq 1 10); do
                curl -s -o /dev/null -w "%{http_code}\n" -m 10 -X POST \
                    -d "amount=100&item=race_test_${i}" "$url" >> "$race_file" 2>/dev/null &
                race_pids+=($!)
            done

            for pid in "${race_pids[@]}"; do
                wait "$pid" 2>/dev/null || true
            done

            local success_count=0
            while IFS= read -r code; do
                if [[ "$code" == "200" || "$code" == "201" ]]; then
                    ((success_count++)) || true
                fi
            done < "$race_file" 2>/dev/null || true

            if [[ "$success_count" -gt 1 ]]; then
                echo "[PAYMENT-RACE] $ep - $success_count concurrent payments succeeded (double-spend risk)" >> "$abuse_file"
                ((results++)) || true
            fi
        fi
    done

    # Phase 6: Workflow state tampering via parameter manipulation
    log "INFO" "Phase 6: Workflow state tampering"

    local state_params=(
        "state=complete"
        "status=approved"
        "step=final"
        "phase=done"
        "completed=true"
        "verified=true"
        "paid=true"
        "approved=true"
    )

    for ep in "${discovered_workflows[@]}"; do
        local url="https://${domain}${ep}"
        for param in "${state_params[@]}"; do
            local tamper_status
            tamper_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -X POST -d "$param" "$url" 2>/dev/null || echo "000")
            if [[ "$tamper_status" == "200" || "$tamper_status" == "201" ]]; then
                echo "[STATE-TAMPER] $ep accepts state override: $param (HTTP $tamper_status)" >> "$abuse_file"
                ((results++)) || true
            fi
        done
    done

    # Phase 7: Authorization bypass in workflows
    log "INFO" "Phase 7: Authorization bypass in workflow transitions"

    local auth_workflows=(
        "/api/admin/settings"
        "/api/admin/users"
        "/api/admin/reports"
        "/api/internal/config"
        "/api/system/health"
    )

    for ep in "${auth_workflows[@]}"; do
        local url="https://${domain}${ep}"
        # Try without auth header
        local no_auth_status
        no_auth_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")
        if [[ "$no_auth_status" == "200" ]]; then
            echo "[AUTH-BYPASS] $ep accessible without authentication (HTTP $no_auth_status)" >> "$abuse_file"
            ((results++)) || true
        fi

        # Try with empty auth
        local empty_auth_status
        empty_auth_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
            -H "Authorization: Bearer " "$url" 2>/dev/null || echo "000")
        if [[ "$empty_auth_status" == "200" ]]; then
            echo "[AUTH-BYPASS] $ep accessible with empty Bearer token (HTTP $empty_auth_status)" >> "$abuse_file"
            ((results++)) || true
        fi
    done

    # Cleanup
    rm -rf "$temp_dir" 2>/dev/null || true

    # Write count
    echo "$results" > "$output_dir/business_workflow/count.txt"

    # Write structured findings via phase_bridge
    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "business_workflow" "HIGH" "$line" 2>/dev/null || true
        done < "$abuse_file" 2>/dev/null || true
        while IFS= read -r line; do
            write_endpoint "business_workflow" "$line" 2>/dev/null || true
        done < "$states_file" 2>/dev/null || true
    fi

    py_log "INFO" "business_workflow_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Business workflow phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    business_workflow_phase "$@"
fi
