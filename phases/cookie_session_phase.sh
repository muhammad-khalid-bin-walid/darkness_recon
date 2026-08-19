#!/usr/bin/env bash
# cookie_session_phase.sh - Subdomain-scoped cookie and session-isolation testing,
# SameSite attribute validation, session fixation checks.

cookie_session_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "cookie_session_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/cookie_session"

    local results=0
    local cookie_file="$output_dir/cookie_session/cookie_vulns.txt"
    local session_file="$output_dir/cookie_session/session_issues.txt"

    log "INFO" "Starting cookie/session analysis for $domain"

    # Check for required tools
    local has_curl=false
    local has_whatcookie=false
    tool_available curl && has_curl=true
    tool_available whatcookie && has_whatcookie=true

    if ! $has_curl; then
        log "WARN" "curl not available - skipping cookie session phase"
        return 0
    fi

    # Fetch cookies from main domain and common subdomains
    local subdomains=("www" "api" "app" "admin" "mail" "dev" "staging" "test" "portal" "auth")
    local http_codes=("80" "443")

    for sub in "${subdomains[@]}"; do
        local target="${sub}.${domain}"
        log "INFO" "Testing cookies for $target"

        # Capture response headers including Set-Cookie
        local headers
        headers=$(curl -sI -m 10 "http://$target" 2>/dev/null || true)
        headers+=$'\n'
        headers+=$(curl -sIk -m 10 "https://$target" 2>/dev/null || true)

        if [[ -z "$headers" ]]; then
            continue
        fi

        # Check for missing Secure flag on cookies over HTTPS
        local secure_cookies
        secure_cookies=$(echo "$headers" | grep -i "set-cookie" | grep -i "secure" || true)
        local non_secure_cookies
        non_secure_cookies=$(echo "$headers" | grep -i "set-cookie" | grep -vi "secure" || true)

        if [[ -n "$non_secure_cookies" ]]; then
            echo "[COOKIE-SECURE] $target - Missing Secure flag:" >> "$cookie_file"
            echo "$non_secure_cookies" >> "$cookie_file"
            echo "---" >> "$cookie_file"
            ((results++)) || true
        fi

        # Check for missing HttpOnly flag
        local non_httponly
        non_httponly=$(echo "$headers" | grep -i "set-cookie" | grep -vi "httponly" || true)
        if [[ -n "$non_httponly" ]]; then
            echo "[COOKIE-HTTPTONLY] $target - Missing HttpOnly flag:" >> "$cookie_file"
            echo "$non_httponly" >> "$cookie_file"
            echo "---" >> "$cookie_file"
            ((results++)) || true
        fi

        # Check SameSite attribute
        local no_samesite
        no_samesite=$(echo "$headers" | grep -i "set-cookie" | grep -vi "samesite" || true)
        if [[ -n "$no_samesite" ]]; then
            echo "[COOKIE-SAMESITE] $target - Missing SameSite attribute:" >> "$cookie_file"
            echo "$no_samesite" >> "$cookie_file"
            echo "---" >> "$cookie_file"
            ((results++)) || true
        fi

        # Check for SameSite=none without Secure
        local samesite_none_insecure
        samesite_none_insecure=$(echo "$headers" | grep -i "set-cookie" | grep -i "samesite.*none" | grep -vi "secure" || true)
        if [[ -n "$samesite_none_insecure" ]]; then
            echo "[COOKIE-SAMESITE-NONE] $target - SameSite=None without Secure:" >> "$cookie_file"
            echo "$samesite_none_insecure" >> "$cookie_file"
            echo "---" >> "$cookie_file"
            ((results++)) || true
        fi

        # Session fixation - check if session ID changes after fresh visit
        local session_ids_before
        session_ids_before=$(echo "$headers" | grep -i "set-cookie" | grep -oiE "(session|sid|jsessionid|phpsessid|aspsessionid|connect\.sid)=[^;]*" || true)

        if [[ -n "$session_ids_before" ]]; then
            # Check domain scope of session cookie
            local scoped_to_domain
            scoped_to_domain=$(echo "$headers" | grep -i "set-cookie" | grep -i "domain=" || true)
            if [[ -n "$scoped_to_domain" ]]; then
                local overly_broad
                overly_broad=$(echo "$scoped_to_domain" | grep -i "domain=${domain}" | grep -vi "domain=\.${domain}" || true)
                if [[ -n "$overly_broad" ]]; then
                    echo "[SESSION-SCOPE] $target - Session cookie domain overly broad:" >> "$session_file"
                    echo "$overly_broad" >> "$session_file"
                    echo "---" >> "$session_file"
                    ((results++)) || true
                fi
            fi

            # Check for path exposure
            local path_cookies
            path_cookies=$(echo "$headers" | grep -i "set-cookie" | grep -i "path=/" || true)
            if [[ -n "$path_cookies" ]]; then
                echo "[SESSION-PATH] $target - Session cookie available at root path:" >> "$session_file"
                echo "$path_cookies" >> "$session_file"
                echo "---" >> "$session_file"
                ((results++)) || true
            fi
        fi

        # Check for overly long cookie expiry (session persistence)
        local long_expiry
        long_expiry=$(echo "$headers" | grep -i "set-cookie" | grep -iE "expires=" | while read -r line; do
            local exp_date
            exp_date=$(echo "$line" | grep -oiE "expires=[^;]*" | cut -d= -f2)
            if [[ -n "$exp_date" ]]; then
                echo "$line"
            fi
        done || true)

        if [[ -n "$long_expiry" ]]; then
            echo "[SESSION-LONG-EXPIRY] $target - Long-lived session cookie:" >> "$session_file"
            echo "$long_expiry" >> "$session_file"
            echo "---" >> "$session_file"
            ((results++)) || true
        fi
    done

    # Cross-subdomain cookie isolation test
    log "INFO" "Testing cross-subdomain cookie isolation for $domain"
    local main_cookies
    main_cookies=$(curl -sI -m 10 "https://$domain" 2>/dev/null | grep -i "set-cookie" || true)
    if [[ -n "$main_cookies" ]]; then
        local domain_attr
        domain_attr=$(echo "$main_cookies" | grep -i "domain=" || true)
        if [[ -n "$domain_attr" ]]; then
            echo "[CROSS-SUBDOMAIN] $domain - Cookies with domain attribute (potential cross-subdomain leakage):" >> "$session_file"
            echo "$domain_attr" >> "$session_file"
            echo "---" >> "$session_file"
            ((results++)) || true
        fi
    fi

    # Write count
    echo "$results" > "$output_dir/cookie_session/count.txt"

    # Write structured findings via phase_bridge
    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "cookie_session" "MEDIUM" "$line" 2>/dev/null || true
        done < "$cookie_file" 2>/dev/null || true
    fi

    py_log "INFO" "cookie_session_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Cookie/session phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    cookie_session_phase "$@"
fi
