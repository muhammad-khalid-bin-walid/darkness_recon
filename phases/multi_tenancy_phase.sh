#!/usr/bin/env bash
# multi_tenancy_phase.sh - Multi-tenancy isolation testing,
# data leakage between tenants, cross-tenant access.

multi_tenancy_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "multi_tenancy_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/multi_tenancy"

    local results=0
    local vulns_file="$output_dir/multi_tenancy/tenant_vulns.txt"
    local isolation_file="$output_dir/multi_tenancy/isolation_issues.txt"

    log "INFO" "Starting multi-tenancy isolation testing for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    local temp_dir
    temp_dir=$(mktemp -d)

    # Phase 1: Tenant identification and enumeration
    log "INFO" "Phase 1: Tenant identification and enumeration"

    local tenant_indicators=(
        "X-Tenant-ID"
        "X-Tenant"
        "X-Organization-ID"
        "X-Org-ID"
        "X-Account-ID"
        "X-Workspace-ID"
        "X-Company-ID"
    )

    local tenant_id_header=""
    local base_url="https://${domain}"

    # Try to discover tenant ID from response headers
    local base_headers
    base_headers=$(curl -sI -m 10 "$base_url" 2>/dev/null || true)

    for indicator in "${tenant_indicators[@]}"; do
        local found
        found=$(echo "$base_headers" | grep -i "^${indicator}:" || true)
        if [[ -n "$found" ]]; then
            tenant_id_header="$indicator"
            echo "[TENANT-HEADER] Found tenant identifier: $found" >> "$isolation_file"
            ((results++)) || true
            break
        fi
    done

    # Phase 2: Subdomain-based tenant isolation
    log "INFO" "Phase 2: Testing subdomain-based tenant isolation"

    local tenant_subdomains=(
        "tenant1" "tenant2" "customer1" "customer2"
        "org1" "org2" "company1" "company2"
        "client1" "client2" "account1" "account2"
        "t1" "t2" "c1" "c2"
        "acme" "globex" "initech" "umbrella"
    )

    local active_tenants=()

    for sub in "${tenant_subdomains[@]}"; do
        local tenant_url="https://${sub}.${domain}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$tenant_url" 2>/dev/null || echo "000")

        if [[ "$status" != "000" && "$status" != "502" && "$status" != "503" ]]; then
            echo "[TENANT-FOUND] ${sub}.${domain} (HTTP $status)" >> "$isolation_file"
            active_tenants+=("${sub}.${domain}")
            ((results++)) || true
        fi
    done

    # Phase 3: Cross-tenant API access
    log "INFO" "Phase 3: Testing cross-tenant API access"

    if [[ ${#active_tenants[@]} -ge 2 ]]; then
        local tenant_a="${active_tenants[0]}"
        local tenant_b="${active_tenants[1]}"

        # Try accessing tenant A's API from tenant B context
        local api_paths=(
            "/api/users"
            "/api/data"
            "/api/settings"
            "/api/admin"
            "/api/documents"
            "/api/invoices"
            "/api/projects"
            "/api/team"
        )

        for path in "${api_paths[@]}"; do
            # Request from tenant A
            local resp_a
            resp_a=$(curl -s -m 10 -H "Host: $tenant_a" "https://${domain}${path}" 2>/dev/null || true)

            # Request from tenant B
            local resp_b
            resp_b=$(curl -s -m 10 -H "Host: $tenant_b" "https://${domain}${path}" 2>/dev/null || true)

            # If responses contain different data, check for leakage
            if [[ -n "$resp_a" && -n "$resp_b" ]]; then
                local hash_a
                hash_a=$(echo "$resp_a" | md5sum 2>/dev/null | cut -d' ' -f1 || true)
                local hash_b
                hash_b=$(echo "$resp_b" | md5sum 2>/dev/null | cut -d' ' -f1 || true)

                if [[ "$hash_a" == "$hash_b" && ${#resp_a} -gt 50 ]]; then
                    echo "[CROSS-TENANT] $path returns identical data for different tenants" >> "$vulns_file"
                    ((results++)) || true
                fi
            fi

            # Test direct tenant ID parameter injection
            local cross_status
            cross_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -H "Host: $tenant_a" \
                -d "tenant_id=other_tenant" \
                "https://${domain}${path}" 2>/dev/null || echo "000")
            if [[ "$cross_status" == "200" ]]; then
                echo "[CROSS-TENANT-PARAM] $path accepts tenant_id parameter override (HTTP $cross_status)" >> "$vulns_file"
                ((results++)) || true
            fi
        done
    fi

    # Phase 4: JWT/Token tenant claim manipulation
    log "INFO" "Phase 4: Testing JWT/Token tenant claim manipulation"

    local auth_endpoints=(
        "/api/auth/login"
        "/api/login"
        "/api/token"
        "/auth/login"
        "/login"
    )

    for ep in "${auth_endpoints[@]}"; do
        local url="https://${domain}${ep}"

        # Try login with tenant manipulation
        local login_status
        login_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
            -d "email=test@test.com&password=test&tenant_id=admin" "$url" 2>/dev/null || echo "000")

        if [[ "$login_status" == "200" || "$login_status" == "201" ]]; then
            echo "[TENANT-LOGIN-INJECT] $ep accepts tenant_id in login request (HTTP $login_status)" >> "$vulns_file"
            ((results++)) || true
        fi
    done

    # Phase 5: Shared resource access
    log "INFO" "Phase 5: Testing shared resource access"

    local shared_paths=(
        "/api/shared"
        "/api/public"
        "/api/files"
        "/uploads"
        "/documents"
        "/media"
        "/static"
        "/assets"
        "/images"
        "/api/storage"
    )

    for path in "${shared_paths[@]}"; do
        local url="https://${domain}${path}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" == "200" ]]; then
            local resp
            resp=$(curl -s -m 10 "$url" 2>/dev/null || true)

            # Check for tenant-specific data in shared resources
            if echo "$resp" | grep -qiE "(tenant|org_id|company|account)" 2>/dev/null; then
                echo "[SHARED-RESOURCE-TENANT] $path exposes tenant-specific data in shared resource" >> "$vulns_file"
                ((results++)) || true
            fi

            # Check for path traversal in shared resources
            local traversal_status
            traversal_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                "${url}/../" 2>/dev/null || echo "000")
            if [[ "$traversal_status" == "200" ]]; then
                echo "[SHARED-TRAVERSAL] $path allows directory traversal (HTTP $traversal_status)" >> "$vulns_file"
                ((results++)) || true
            fi
        fi
    done

    # Phase 6: Database isolation via error messages
    log "INFO" "Phase 6: Testing database isolation via error messages"

    local error_endpoints=(
        "/api/search"
        "/api/query"
        "/api/data"
        "/api/list"
    )

    for ep in "${error_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        # Send malformed request to trigger error
        local error_resp
        error_resp=$(curl -s -m 10 -X POST -d "'" "$url" 2>/dev/null || true)

        if echo "$error_resp" | grep -qiE "(database|db|table|schema|tenant_id|org_id)" 2>/dev/null; then
            echo "[ERROR-TENANT-LEAK] $ep leaks tenant/database info in error messages" >> "$isolation_file"
            ((results++)) || true
        fi
    done

    # Phase 7: Tenant enumeration via timing
    log "INFO" "Phase 7: Testing tenant enumeration via timing"

    if [[ ${#active_tenants[@]} -ge 2 ]]; then
        local tenant_a="${active_tenants[0]}"

        # Measure response time for valid vs invalid tenant
        local valid_times=()
        local invalid_times=()

        for i in $(seq 1 5); do
            local start_time
            start_time=$(date +%s%N 2>/dev/null || echo "0")
            curl -s -o /dev/null -m 10 -H "Host: $tenant_a" "https://${domain}/api/status" 2>/dev/null || true
            local end_time
            end_time=$(date +%s%N 2>/dev/null || echo "0")
            valid_times+=($(( (end_time - start_time) / 1000000 )))

            start_time=$(date +%s%N 2>/dev/null || echo "0")
            curl -s -o /dev/null -m 10 -H "Host: nonexistent_tenant_xyz" "https://${domain}/api/status" 2>/dev/null || true
            end_time=$(date +%s%N 2>/dev/null || echo "0")
            invalid_times+=($(( (end_time - start_time) / 1000000 )))
        done

        # Compare average times
        local valid_avg=0
        local invalid_avg=0
        for t in "${valid_times[@]}"; do ((valid_avg += t)) || true; done
        for t in "${invalid_times[@]}"; do ((invalid_avg += t)) || true; done
        valid_avg=$((valid_avg / ${#valid_times[@]}))
        invalid_avg=$((invalid_avg / ${#invalid_times[@]}))

        local time_diff=$((valid_avg - invalid_avg))
        if [[ $time_diff -lt -100 || $time_diff -gt 100 ]]; then
            echo "[TENANT-TIMING] Response time difference: valid=${valid_avg}ms invalid=${invalid_avg}ms (diff=${time_diff}ms)" >> "$vulns_file"
            echo "  Potential tenant enumeration via timing side-channel" >> "$vulns_file"
            ((results++)) || true
        fi
    fi

    # Phase 8: Header-based tenant bypass
    log "INFO" "Phase 8: Testing header-based tenant bypass"

    local bypass_headers=(
        "X-Tenant-ID: admin"
        "X-Tenant-ID: root"
        "X-Tenant-ID: 1"
        "X-Organization-ID: 1"
        "X-Org-ID: admin"
        "X-Account-ID: 0"
        "X-Workspace-ID: default"
        "X-Company-ID: 1"
        "X-Tenant-Override: admin"
        "X-Debug: true"
        "X-Internal: true"
        "X-Admin: true"
    )

    local sensitive_endpoints=(
        "/api/admin/users"
        "/api/admin/settings"
        "/api/users"
        "/api/data"
        "/api/documents"
    )

    for ep in "${sensitive_endpoints[@]}"; do
        local url="https://${domain}${ep}"

        for hdr in "${bypass_headers[@]}"; do
            local hdr_status
            hdr_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -H "$hdr" "$url" 2>/dev/null || echo "000")
            if [[ "$hdr_status" == "200" ]]; then
                echo "[TENANT-BYPASS] $ep accepts $hdr (HTTP $hdr_status)" >> "$vulns_file"
                ((results++)) || true
            fi
        done
    done

    # Cleanup
    rm -rf "$temp_dir" 2>/dev/null || true

    # Write count
    echo "$results" > "$output_dir/multi_tenancy/count.txt"

    # Write structured findings via phase_bridge
    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "multi_tenancy" "CRITICAL" "$line" 2>/dev/null || true
        done < "$vulns_file" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "multi_tenancy" "MEDIUM" "$line" 2>/dev/null || true
        done < "$isolation_file" 2>/dev/null || true
    fi

    py_log "INFO" "multi_tenancy_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Multi-tenancy phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    multi_tenancy_phase "$@"
fi
