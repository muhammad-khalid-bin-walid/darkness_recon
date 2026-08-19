#!/usr/bin/env bash
# session_fixation_phase.sh - Session fixation and session-invalidation-on-logout
# testing, session token predictability analysis.

session_fixation_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "session_fixation_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/session_fixation"

    local results=0
    local vulns_file="$output_dir/session_fixation/session_vulns.txt"
    local analysis_file="$output_dir/session_fixation/session_analysis.txt"

    log "INFO" "Starting session fixation testing for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    local temp_dir
    temp_dir=$(mktemp -d)

    # Phase 1: Session token collection and analysis
    log "INFO" "Phase 1: Collecting session tokens"

    local login_endpoints=(
        "/api/login"
        "/api/auth/login"
        "/api/signin"
        "/login"
        "/signin"
        "/auth/login"
    )

    local session_tokens=()
    local cookie_names=()

    for ep in "${login_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local cookie_jar
        cookie_jar=$(mktemp)

        curl -s -c "$cookie_jar" -m 10 "$url" 2>/dev/null || true

        if [[ -f "$cookie_jar" ]]; then
            local cookies
            cookies=$(cat "$cookie_jar" 2>/dev/null || true)

            while IFS= read -r cookie_line; do
                local cookie_name
                cookie_name=$(echo "$cookie_line" | awk '{print $NF}' | cut -d= -f1)
                local cookie_value
                cookie_value=$(echo "$cookie_line" | awk '{print $NF}' | cut -d= -f2)

                if [[ -n "$cookie_name" && -n "$cookie_value" ]]; then
                    session_tokens+=("$cookie_value")
                    cookie_names+=("$cookie_name")
                    echo "[COOKIE-CAPTURED] $ep: $cookie_name=$cookie_value" >> "$analysis_file"
                fi
            done < <(grep -i "session\|token\|sid\|auth\|jwt\|sess" "$cookie_jar" 2>/dev/null || true)

            ((results++)) || true
        fi
        rm -f "$cookie_jar" 2>/dev/null || true
    done

    # Phase 2: Session token predictability analysis
    log "INFO" "Phase 2: Analyzing session token predictability"

    if [[ ${#session_tokens[@]} -ge 2 ]]; then
        echo "[TOKEN-ANALYSIS] Collected ${#session_tokens[@]} session tokens" >> "$analysis_file"

        # Check token length consistency
        local lengths=()
        for token in "${session_tokens[@]}"; do
            lengths+=("${#token}")
        done

        local first_len="${lengths[0]}"
        local consistent=true
        for len in "${lengths[@]}"; do
            if [[ "$len" != "$first_len" ]]; then
                consistent=false
                break
            fi
        done

        if $consistent; then
            echo "[TOKEN-LENGTH] All tokens are $first_len characters (consistent)" >> "$analysis_file"
        else
            echo "[TOKEN-LENGTH] Token lengths vary: $(printf '%s ' "${lengths[@]}")" >> "$analysis_file"
            echo "  Inconsistent token length may indicate weak generation" >> "$vulns_file"
            ((results++)) || true
        fi

        # Check for sequential patterns
        local prev_numeric=""
        local sequential_found=false
        for token in "${session_tokens[@]}"; do
            local numeric_val
            numeric_val=$(echo "$token" | tr -dc '0-9' 2>/dev/null || true)
            if [[ -n "$numeric_val" && -n "$prev_numeric" ]]; then
                local diff=$((numeric_val - prev_numeric))
                if [[ "$diff" -eq 1 ]]; then
                    sequential_found=true
                    break
                fi
            fi
            prev_numeric="$numeric_val"
        done

        if $sequential_found; then
            echo "[TOKEN-SEQUENTIAL] Tokens appear to be sequential (predictable)" >> "$vulns_file"
            ((results++)) || true
        fi

        # Check for common patterns
        local charset_analysis=""
        for token in "${session_tokens[@]}"; do
            if echo "$token" | grep -qE '^[a-f0-9]+$' 2>/dev/null; then
                charset_analysis="hex"
            elif echo "$token" | grep -qE '^[A-Za-z0-9+/=]+$' 2>/dev/null; then
                charset_analysis="base64"
            elif echo "$token" | grep -qE '^[0-9]+$' 2>/dev/null; then
                charset_analysis="numeric"
            fi
        done

        echo "[TOKEN-CHARSET] Token charset: $charset_analysis" >> "$analysis_file"

        if [[ "$charset_analysis" == "numeric" ]]; then
            echo "[TOKEN-WEAK] Numeric-only tokens are easily brute-forced" >> "$vulns_file"
            ((results++)) || true
        fi
    fi

    # Phase 3: Session fixation - token reuse after auth state change
    log "INFO" "Phase 3: Testing session fixation"

    local session_endpoints=(
        "/api/user"
        "/api/me"
        "/api/profile"
        "/api/account"
        "/api/dashboard"
        "/api/settings"
    )

    for ep in "${session_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local cookie_jar_1
        cookie_jar_1=$(mktemp)
        local cookie_jar_2
        cookie_jar_2=$(mktemp)

        # Get initial session
        curl -s -c "$cookie_jar_1" -m 10 "$url" 2>/dev/null || true

        # Try to reuse session from different context
        curl -s -b "$cookie_jar_1" -c "$cookie_jar_2" -m 10 "$url" 2>/dev/null || true

        # Compare session tokens
        local token_1
        token_1=$(grep -oE '(session|sid|token|auth)=[^; ]+' "$cookie_jar_1" 2>/dev/null | head -1 || true)
        local token_2
        token_2=$(grep -oE '(session|sid|token|auth)=[^; ]+' "$cookie_jar_2" 2>/dev/null | head -1 || true)

        if [[ -n "$token_1" && "$token_1" == "$token_2" ]]; then
            echo "[SESSION-FIXATION] $ep - Session token unchanged after reuse" >> "$vulns_file"
            echo "  Token: $token_1" >> "$vulns_file"
            ((results++)) || true
        fi

        rm -f "$cookie_jar_1" "$cookie_jar_2" 2>/dev/null || true
    done

    # Phase 4: Session invalidation on logout testing
    log "INFO" "Phase 4: Testing session invalidation on logout"

    local logout_endpoints=(
        "/api/logout"
        "/api/auth/logout"
        "/api/signout"
        "/logout"
        "/signout"
        "/auth/logout"
    )

    for ep in "${logout_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local cookie_jar
        cookie_jar=$(mktemp)

        # Get a session
        local pre_session
        pre_session=$(curl -s -c "$cookie_jar" -m 10 "https://${domain}/api/user" 2>/dev/null || true)

        # Perform logout
        curl -s -b "$cookie_jar" -c "$cookie_jar" -m 10 "$url" 2>/dev/null || true

        # Try to use session after logout
        local post_status
        post_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
            -b "$cookie_jar" "https://${domain}/api/user" 2>/dev/null || echo "000")

        if [[ "$post_status" == "200" ]]; then
            echo "[INVALIDATION-FAIL] Session still valid after logout via $ep (HTTP $post_status)" >> "$vulns_file"
            echo "  Session not invalidated on logout" >> "$vulns_file"
            ((results++)) || true
        fi

        # Test if old token can be reused from different client
        local cookie_jar_reuse
        cookie_jar_reuse=$(mktemp)
        cp "$cookie_jar" "$cookie_jar_reuse" 2>/dev/null || true

        local reuse_status
        reuse_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
            -b "$cookie_jar_reuse" "https://${domain}/api/user" 2>/dev/null || echo "000")

        if [[ "$reuse_status" == "200" ]]; then
            echo "[SESSION-REUSE] Old session token still valid after logout (HTTP $reuse_status)" >> "$vulns_file"
            ((results++)) || true
        fi

        rm -f "$cookie_jar" "$cookie_jar_reuse" 2>/dev/null || true
    done

    # Phase 5: Session token in URL testing
    log "INFO" "Phase 5: Testing session token in URL"

    local url_endpoints=(
        "/api/login"
        "/api/auth/callback"
        "/api/sso/callback"
        "/api/oauth/callback"
        "/callback"
    )

    for ep in "${url_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local resp_headers
        resp_headers=$(curl -sI -m 10 "$url" 2>/dev/null || true)

        # Check for session token in URL parameters
        if echo "$resp_headers" | grep -qiE "(session|token|sid|auth)=[a-zA-Z0-9]" 2>/dev/null; then
            echo "[SESSION-IN-URL] $ep exposes session token in URL" >> "$vulns_file"
            ((results++)) || true
        fi

        # Check for session token in Location header
        local location
        location=$(echo "$resp_headers" | grep -i "^location:" || true)
        if echo "$location" | grep -qiE "(session|token|sid|auth)=[a-zA-Z0-9]" 2>/dev/null; then
            echo "[SESSION-IN-REDIRECT] $ep leaks session token in redirect URL" >> "$vulns_file"
            ((results++)) || true
        fi
    done

    # Phase 6: Session cookie security attributes
    log "INFO" "Phase 6: Analyzing session cookie security attributes"

    for ep in "${login_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local cookie_jar
        cookie_jar=$(mktemp)

        curl -s -c "$cookie_jar" -m 10 "$url" 2>/dev/null || true

        if [[ -f "$cookie_jar" ]]; then
            # Check Secure flag
            local no_secure
            no_secure=$(grep -v "^[#-]" "$cookie_jar" 2>/dev/null | grep -v "secure" || true)
            if [[ -n "$no_secure" ]]; then
                echo "[COOKIE-NO-SECURE] $ep - Session cookie missing Secure flag" >> "$vulns_file"
                ((results++)) || true
            fi

            # Check HttpOnly flag
            local no_httponly
            no_httponly=$(grep -v "^[#-]" "$cookie_jar" 2>/dev/null | grep -v "httponly" || true)
            if [[ -n "$no_httponly" ]]; then
                echo "[COOKIE-NO-HTTPTONLY] $ep - Session cookie missing HttpOnly flag" >> "$vulns_file"
                ((results++)) || true
            fi

            # Check SameSite attribute
            local no_samesite
            no_samesite=$(grep -v "^[#-]" "$cookie_jar" 2>/dev/null | grep -v "samesite" || true)
            if [[ -n "$no_samesite" ]]; then
                echo "[COOKIE-NO-SAMESITE] $ep - Session cookie missing SameSite attribute" >> "$vulns_file"
                ((results++)) || true
            fi
        fi
        rm -f "$cookie_jar" 2>/dev/null || true
    done

    # Phase 7: Concurrent session testing
    log "INFO" "Phase 7: Testing concurrent session behavior"

    local multi_session_tokens=()

    for i in $(seq 1 5); do
        local cookie_jar
        cookie_jar=$(mktemp)
        curl -s -c "$cookie_jar" -m 10 "https://${domain}/api/user" 2>/dev/null || true

        local token
        token=$(grep -oE '(session|sid|token|auth)=[^; ]+' "$cookie_jar" 2>/dev/null | head -1 || true)
        if [[ -n "$token" ]]; then
            multi_session_tokens+=("$token")
        fi
        rm -f "$cookie_jar" 2>/dev/null || true
    done

    local unique_tokens
    unique_tokens=$(printf '%s\n' "${multi_session_tokens[@]}" | sort -u | wc -l)
    local total_tokens=${#multi_session_tokens[@]}

    echo "[CONCURRENT-SESSIONS] Created $total_tokens sessions, $unique_tokens unique tokens" >> "$analysis_file"

    if [[ "$unique_tokens" -eq "$total_tokens" && "$total_tokens" -gt 1 ]]; then
        echo "[SESSION-PROLIFERATION] Server creates unique session per request (no session limit)" >> "$vulns_file"
        ((results++)) || true
    fi

    # Cleanup
    rm -rf "$temp_dir" 2>/dev/null || true

    # Write count
    echo "$results" > "$output_dir/session_fixation/count.txt"

    # Write structured findings via phase_bridge
    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "session_fixation" "HIGH" "$line" 2>/dev/null || true
        done < "$vulns_file" 2>/dev/null || true
        while IFS= read -r line; do
            write_asset "session_fixation" "session_analysis" "$line" 2>/dev/null || true
        done < "$analysis_file" 2>/dev/null || true
    fi

    py_log "INFO" "session_fixation_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Session fixation phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    session_fixation_phase "$@"
fi
