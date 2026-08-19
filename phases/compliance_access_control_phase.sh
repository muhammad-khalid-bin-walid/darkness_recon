#!/usr/bin/env bash
# Phase 269: Access Control Compliance, RBAC Review, Privilege Escalation Paths
# Track 18 - Compliance

compliance_access_control() {
    local domain="${1:?Usage: compliance_access_control <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/compliance_access_control"
    mkdir -p "$phase_dir"

    log "INFO" "[ACCESS_CTRL] Starting access control compliance for $domain"

    local access_control_compliance="$phase_dir/access_control_compliance.txt"
    local rbac_review="$phase_dir/rbac_review.txt"

    : > "$access_control_compliance"
    : > "$rbac_review"

    local count=0

    if tool_available "curl"; then
        log "INFO" "[ACCESS_CTRL] Checking admin and privileged paths"

        local admin_paths=("/admin" "/admin/" "/api/admin" "/dashboard" "/management" "/console" "/wp-admin" "/manager")
        for path in "${admin_paths[@]}"; do
            local status
            status=$(curl -sI --max-time 10 "https://$domain$path" 2>/dev/null | head -1 || true)
            if echo "$status" | grep -qE "200|301|302"; then
                echo "ADMIN_PATH: $path - $status" >> "$access_control_compliance"
                echo "PRIV_PATH: $path accessible without auth" >> "$rbac_review"
                write_finding "$phase_dir" "AC-ADMIN" "Admin path accessible: $path" "critical" "warning"
                count=$((count + 1))
            elif echo "$status" | grep -q "403"; then
                echo "ADMIN_PATH: $path - 403 Forbidden (protected)" >> "$access_control_compliance"
                echo "PRIV_PATH: $path properly restricted" >> "$rbac_review"
                count=$((count + 1))
            fi
        done

        log "INFO" "[ACCESS_CTRL] Checking API endpoint access control"
        local api_paths=("/api/v1/users" "/api/v1/admin" "/api/users" "/api/health" "/api/config")
        for path in "${api_paths[@]}"; do
            local status
            status=$(curl -sI --max-time 10 "https://$domain$path" 2>/dev/null | head -1 || true)
            if [ -n "$status" ]; then
                echo "API_ACCESS: $path - $status" >> "$access_control_compliance"
                count=$((count + 1))
            fi
        done

        log "INFO" "[ACCESS_CTRL] Checking role-related pages"
        local role_paths=("/roles" "/permissions" "/users/roles" "/access-control" "/rbac")
        for path in "${role_paths[@]}"; do
            local status
            status=$(curl -sI --max-time 10 "https://$domain$path" 2>/dev/null | head -1 || true)
            if echo "$status" | grep -qE "200|301|302"; then
                echo "ROLE_PAGE: $path - $status" >> "$rbac_review"
                write_finding "$phase_dir" "AC-RBAC" "Role management page: $path" "medium" "info"
                count=$((count + 1))
            fi
        done
    fi

    if tool_available "nmap"; then
        log "INFO" "[ACCESS_CTRL] Scanning management ports"
        nmap -p 22,3389,5900,8443,9090 "$domain" 2>/dev/null > "$phase_dir/mgmt_ports.txt" || true
        local mgmt_open
        mgmt_open=$(grep -c "open" "$phase_dir/mgmt_ports.txt" 2>/dev/null || echo "0")
        echo "MGMT_PORTS: $mgmt_open management ports exposed" >> "$access_control_compliance"
        echo "Management ports: $mgmt_open" >> "$rbac_review"
        count=$((count + 1))
    fi

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "access_control_complete" "Access control compliance complete: $count items checked"
    log "INFO" "[ACCESS_CTRL] Completed: $count items checked"

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_endpoint "$phase_dir" "https://$domain" "GET" "Access control compliance target"

    return 0
}
