#!/usr/bin/env bash
# Phase 267: Authentication Tracking, Access Control Audit, Session Management Review
# Track 18 - Compliance

compliance_auth_tracking() {
    local domain="${1:?Usage: compliance_auth_tracking <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/compliance_auth_tracking"
    mkdir -p "$phase_dir"

    log "INFO" "[AUTH_TRACK] Starting authentication tracking for $domain"

    local auth_tracking="$phase_dir/auth_tracking.txt"
    local access_control_audit="$phase_dir/access_control_audit.txt"

    : > "$auth_tracking"
    : > "$access_control_audit"

    local count=0

    if tool_available "curl"; then
        log "INFO" "[AUTH_TRACK] Checking login endpoints and session handling"

        local login_paths=("/login" "/signin" "/auth" "/admin/login" "/wp-login.php" "/user/login")
        for path in "${login_paths[@]}"; do
            local status
            status=$(curl -sI --max-time 10 "https://$domain$path" 2>/dev/null | head -1 || true)
            if echo "$status" | grep -qE "200|301|302|403"; then
                echo "AUTH_ENDPOINT: $path - $status" >> "$auth_tracking"
                write_finding "$phase_dir" "AUTH-EP" "Login endpoint: $path" "info" "info"
                count=$((count + 1))
            fi
        done

        log "INFO" "[AUTH_TRACK] Checking session cookie attributes"
        local cookies
        cookies=$(curl -sI --max-time 10 -c - "https://$domain" 2>/dev/null || true)
        if [ -n "$cookies" ]; then
            local has_secure
            has_secure=$(echo "$cookies" | grep -ci "secure" || true)
            local has_httponly
            has_httponly=$(echo "$cookies" | grep -ci "httponly" || true)

            if [ "$has_secure" -gt 0 ]; then
                echo "SESSION: Secure flag present" >> "$auth_tracking"
                echo "Secure flag: PRESENT" >> "$access_control_audit"
                count=$((count + 1))
            else
                echo "SESSION: Secure flag missing" >> "$auth_tracking"
                echo "Secure flag: MISSING" >> "$access_control_audit"
                write_finding "$phase_dir" "AUTH-SESS" "Session secure flag missing" "high" "failed"
                count=$((count + 1))
            fi

            if [ "$has_httponly" -gt 0 ]; then
                echo "SESSION: HttpOnly flag present" >> "$auth_tracking"
                echo "HttpOnly flag: PRESENT" >> "$access_control_audit"
                count=$((count + 1))
            else
                echo "SESSION: HttpOnly flag missing" >> "$auth_tracking"
                echo "HttpOnly flag: MISSING" >> "$access_control_audit"
                write_finding "$phase_dir" "AUTH-SESS" "Session HttpOnly flag missing" "high" "failed"
                count=$((count + 1))
            fi
        fi
    fi

    if tool_available "nmap"; then
        log "INFO" "[AUTH_TRACK] Checking auth service ports"
        nmap -p 389,636,88,8080,8443 "$domain" 2>/dev/null > "$phase_dir/auth_ports.txt" || true
        local auth_open
        auth_open=$(grep -c "open" "$phase_dir/auth_ports.txt" 2>/dev/null || echo "0")
        echo "AUTH_PORTS: $auth_open auth-related ports open" >> "$auth_tracking"
        echo "Auth port scan: $auth_open open ports" >> "$access_control_audit"
        count=$((count + 1))
    fi

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "auth_tracking_complete" "Auth tracking complete: $count items checked"
    log "INFO" "[AUTH_TRACK] Completed: $count items tracked"

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_endpoint "$phase_dir" "https://$domain" "GET" "Auth tracking target"

    return 0
}
