#!/usr/bin/env bash
# workflow_bypass_phase.sh - Workflow state-bypass testing, step skipping,
# direct parameter manipulation.

workflow_bypass_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "workflow_bypass_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/workflow_bypass"

    local results=0
    local bypass_file="$output_dir/workflow_bypass/state_bypass.txt"
    local vulns_file="$output_dir/workflow_bypass/workflow_vulns.txt"
    local findings_file="$output_dir/workflow_bypass/findings.json"

    log "INFO" "Starting workflow bypass phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Discover workflow/state endpoints ---
    local workflow_paths=(
        "/checkout"
        "/api/checkout"
        "/api/v1/checkout"
        "/onboarding"
        "/api/onboarding"
        "/wizard"
        "/api/wizard"
        "/setup"
        "/api/setup"
        "/api/transfer"
        "/transfer"
        "/api/payment"
        "/payment"
        "/api/order"
        "/order"
        "/api/process"
        "/submit"
        "/api/submit"
    )

    for wpath in "${workflow_paths[@]}"; do
        local url="https://${domain}${wpath}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" != "000" && "$status" != "404" ]]; then
            log "INFO" "Workflow endpoint found: $url (HTTP $status)"

            echo "[WORKFLOW-ENDPOINT] $url - HTTP $status" >> "$bypass_file"
            ((results++)) || true

            write_endpoint "{\"url\":\"$url\",\"method\":\"GET\",\"status\":$status,\"phase\":\"workflow_bypass\"}" \
                "$findings_file" 2>/dev/null || true

            # --- Test step-skipping via state parameter manipulation ---
            local state_params=(
                "step=final"
                "step=complete"
                "state=complete"
                "state=finished"
                "step=4"
                "step=5"
                "step=10"
                "phase=done"
                "phase=complete"
                "current_step=99"
                "status=complete"
                "status=done"
                "skip=true"
                "skip_to=final"
                "workflow_step=complete"
            )

            for param in "${state_params[@]}"; do
                local bypass_resp bypass_status
                bypass_resp=$(curl -s -m 10 -w "\n%{http_code}" "${url}?${param}" 2>/dev/null || true)
                bypass_status=$(echo "$bypass_resp" | tail -1)

                if [[ "$bypass_status" == "200" ]]; then
                    local body
                    body=$(echo "$bypass_resp" | head -n -1)

                    # Check for sensitive content at skipped step
                    local has_sensitive=false
                    echo "$body" | grep -qiE '(password|credit.card|ssn|social.security|payment|admin|secret)' 2>/dev/null && has_sensitive=true

                    if [[ "$has_sensitive" == "true" ]]; then
                        echo "[STATE-BYPASS] $url?$param - Sensitive content at skipped step (HTTP $bypass_status)" >> "$bypass_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"workflow_step_skip\",\"url\":\"$url\",\"param\":\"$param\",\"severity\":\"HIGH\",\"evidence\":\"Workflow step skipping reveals sensitive content\"}" \
                            "$findings_file" 2>/dev/null || true
                    fi
                fi
            done

            # --- Test direct step access via POST ---
            local step_bodies=(
                '{"step":"final","complete":true}'
                '{"current_step":99,"bypass":true}'
                '{"workflow_state":"complete"}'
                '{"payment_confirmed":true,"order_id":"1"}'
                '{"verification_bypass":true}'
                '{"skip_validation":true}'
                '{"admin_override":true}'
            )

            for body in "${step_bodies[@]}"; do
                local post_resp post_status
                post_resp=$(curl -s -m 10 -w "\n%{http_code}" -X POST \
                    -H "Content-Type: application/json" \
                    -d "$body" \
                    "$url" 2>/dev/null || true)
                post_status=$(echo "$post_resp" | tail -1)

                if [[ "$post_status" == "200" || "$post_status" == "201" ]]; then
                    echo "[STEP-BYPASS-POST] $url - Direct step manipulation accepted: $body" >> "$bypass_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"workflow_step_bypass_post\",\"url\":\"$url\",\"payload\":\"$body\",\"severity\":\"HIGH\",\"evidence\":\"Direct POST manipulation bypasses workflow state\"}" \
                        "$findings_file" 2>/dev/null || true
                fi
            done

            # --- Test parameter injection to skip validation ---
            local inject_params=(
                "validated=true"
                "approved=true"
                "verified=true"
                "confirmed=true"
                "passed=true"
                "check_bypass=true"
                "skip_check=true"
                "force=true"
                "override=true"
                "admin=true"
                "debug=true"
                "internal=true"
            )

            for param in "${inject_params[@]}"; do
                local inject_resp inject_status
                inject_resp=$(curl -s -m 10 -w "\n%{http_code}" "${url}?${param}" 2>/dev/null || true)
                inject_status=$(echo "$inject_resp" | tail -1)

                if [[ "$inject_status" == "200" ]]; then
                    local inject_body
                    inject_body=$(echo "$inject_resp" | head -n -1)

                    local has_admin=false
                    echo "$inject_body" | grep -qiE '(admin|dashboard|settings|config|secret)' 2>/dev/null && has_admin=true

                    if [[ "$has_admin" == "true" ]]; then
                        echo "[PARAM-INJECT] $url?$param - Admin content revealed via parameter injection" >> "$vulns_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"workflow_param_injection\",\"url\":\"$url\",\"param\":\"$param\",\"severity\":\"CRITICAL\",\"evidence\":\"Parameter injection bypasses access controls\"}" \
                            "$findings_file" 2>/dev/null || true
                    fi
                fi
            done

            # --- Test referer-based state manipulation ---
            local referers=(
                "https://${domain}/admin"
                "https://${domain}/internal"
                "https://${domain}/debug"
                "https://evil.com"
            )

            for referer in "${referers[@]}"; do
                local ref_resp ref_status
                ref_resp=$(curl -s -m 10 -w "\n%{http_code}" -H "Referer: $referer" "$url" 2>/dev/null || true)
                ref_status=$(echo "$ref_resp" | tail -1)

                if [[ "$ref_status" == "200" ]]; then
                    local ref_body
                    ref_body=$(echo "$ref_resp" | head -n -1)

                    echo "$ref_body" | grep -qiE '(admin|internal|debug|bypass)' 2>/dev/null && {
                        echo "[REFERER-BYPASS] $url - Referer-based state change: $referer" >> "$vulns_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"workflow_referer_bypass\",\"url\":\"$url\",\"referer\":\"$referer\",\"severity\":\"MEDIUM\",\"evidence\":\"Referer header affects workflow state\"}" \
                            "$findings_file" 2>/dev/null || true
                    } || true
                fi
            done
        fi
    done

    # Write count
    echo "$results" > "$output_dir/workflow_bypass/count.txt"

    py_log "INFO" "workflow_bypass_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Workflow bypass phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    workflow_bypass_phase "$@"
fi
