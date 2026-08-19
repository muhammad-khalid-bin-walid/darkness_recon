#!/usr/bin/env bash
# account_enum_phase.sh - Account enumeration via timing/response-difference,
# login error messages, registration flow analysis.

account_enum_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "account_enum_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/account_enum"

    local results=0
    local vectors_file="$output_dir/account_enum/enumeration_vectors.txt"
    local timing_file="$output_dir/account_enum/timing_differences.txt"
    local findings_file="$output_dir/account_enum/findings.json"

    log "INFO" "Starting account enumeration phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Timing-based enumeration on login endpoints ---
    local login_paths=(
        "/login"
        "/signin"
        "/api/login"
        "/api/v1/login"
        "/api/auth/login"
        "/wp-login.php"
        "/user/login"
        "/account/login"
        "/auth/login"
        "/session/login"
    )

    local test_users=("admin" "administrator" "root" "test" "user" "info" "support" "webmaster" "postmaster" "hostmaster")
    local timing_baseline_us=0

    for lpath in "${login_paths[@]}"; do
        local url="https://${domain}${lpath}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" != "000" && "$status" != "404" ]]; then
            log "INFO" "Login endpoint found: $url (HTTP $status)"

            echo "[LOGIN-ENDPOINT] $url - HTTP $status" >> "$vectors_file"
            ((results++)) || true

            write_endpoint "{\"url\":\"$url\",\"method\":\"POST\",\"status\":$status,\"phase\":\"account_enum\"}" \
                "$findings_file" 2>/dev/null || true

            # Timing-based enumeration: measure response times for different usernames
            for user in "${test_users[@]}"; do
                local start_ns end_ns elapsed_ms http_code body_size
                start_ns=$(date +%s%N 2>/dev/null || echo 0)

                local response
                response=$(curl -s -m 10 -w "\n%{http_code}\n%{size_download}" \
                    -X POST -d "username=${user}&password=invalidtest123" \
                    -H "Content-Type: application/x-www-form-urlencoded" \
                    "$url" 2>/dev/null || true)

                end_ns=$(date +%s%N 2>/dev/null || echo 0)

                http_code=$(echo "$response" | tail -n 2 | head -n 1)
                body_size=$(echo "$response" | tail -n 1)
                elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

                echo "[TIMING] $url user=$user http=$http_code size=${body_size}B time=${elapsed_ms}ms" >> "$timing_file"
            done

            # Compare timing deltas between valid and invalid users
            local timing_data
            timing_data=$(cat "$timing_file" 2>/dev/null || true)
            if [[ -n "$timing_data" ]]; then
                local avg_time
                avg_time=$(echo "$timing_data" | grep -oP 'time=\K[0-9]+' | awk '{sum+=$1; n++} END {if(n>0) print int(sum/n); else print 0}')
                local max_time min_time
                max_time=$(echo "$timing_data" | grep -oP 'time=\K[0-9]+' | sort -n | tail -1)
                min_time=$(echo "$timing_data" | grep -oP 'time=\K[0-9]+' | sort -n | head -1)

                if [[ -n "$max_time" && -n "$min_time" && "$max_time" -gt 0 ]]; then
                    local delta=$((max_time - min_time))
                    if [[ "$delta" -gt 100 ]]; then
                        echo "[TIMING-VULN] $url - Significant timing difference detected: ${delta}ms delta (min=${min_time}ms max=${max_time}ms avg=${avg_time}ms)" >> "$timing_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"timing_enumeration\",\"url\":\"$url\",\"delta_ms\":$delta,\"severity\":\"MEDIUM\",\"evidence\":\"Response time varies by ${delta}ms between usernames\"}" \
                            "$findings_file" 2>/dev/null || true
                    fi
                fi
            fi
        fi
    done

    # --- Login error message enumeration ---
    local error_indicators=(
        "invalid username"
        "invalid email"
        "user not found"
        "account not found"
        "no account"
        "unknown user"
        "incorrect password"
        "wrong password"
        "invalid password"
        "password incorrect"
        "login failed"
        "authentication failed"
        "does not exist"
        "not registered"
    )

    for lpath in "${login_paths[@]}"; do
        local url="https://${domain}${lpath}"

        for user in "nonexistent_user_xyz_$(date +%s)" "admin"; do
            local resp_body
            resp_body=$(curl -s -m 10 -X POST -d "username=${user}&password=invalidtest123" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                "$url" 2>/dev/null || true)

            if [[ -n "$resp_body" ]]; then
                for indicator in "${error_indicators[@]}"; do
                    local found
                    found=$(echo "$resp_body" | grep -ci "$indicator" 2>/dev/null || echo "0")
                    if [[ "$found" -gt 0 ]]; then
                        echo "[ERROR-MSG] $url - Login error reveals user existence: '$indicator' (user=$user)" >> "$vectors_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"login_error_enumeration\",\"url\":\"$url\",\"error_pattern\":\"$indicator\",\"severity\":\"MEDIUM\",\"evidence\":\"Different error messages for valid vs invalid users\"}" \
                            "$findings_file" 2>/dev/null || true
                    fi
                done
            fi
        done
    done

    # --- Registration flow enumeration ---
    local register_paths=(
        "/register"
        "/signup"
        "/api/register"
        "/api/v1/register"
        "/api/signup"
        "/user/register"
        "/account/register"
        "/join"
    )

    for rpath in "${register_paths[@]}"; do
        local url="https://${domain}${rpath}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" != "000" && "$status" != "404" ]]; then
            echo "[REGISTER-ENDPOINT] $url - HTTP $status" >> "$vectors_file"
            ((results++)) || true

            # Test if registration reveals existing accounts
            local test_email="test_enum_$(date +%s)@example.com"
            local reg_resp
            reg_resp=$(curl -s -m 10 -X POST -d "email=${test_email}&password=TestPass123!" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                "$url" 2>/dev/null || true)

            if [[ -n "$reg_resp" ]]; then
                local reg_indicators=("already registered" "already exists" "taken" "in use" "duplicate")
                for rind in "${reg_indicators[@]}"; do
                    local rfound
                    rfound=$(echo "$reg_resp" | grep -ci "$rind" 2>/dev/null || echo "0")
                    if [[ "$rfound" -gt 0 ]]; then
                        echo "[REGISTER-ENUM] $url - Registration error reveals account: '$rind'" >> "$vectors_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"registration_enumeration\",\"url\":\"$url\",\"pattern\":\"$rind\",\"severity\":\"LOW\",\"evidence\":\"Registration reveals existing account information\"}" \
                            "$findings_file" 2>/dev/null || true
                    fi
                done
            fi
        fi
    done

    # --- Password reset enumeration ---
    local reset_paths=(
        "/forgot-password"
        "/reset-password"
        "/password/reset"
        "/api/password/reset"
        "/recover"
    )

    for rpath in "${reset_paths[@]}"; do
        local url="https://${domain}${rpath}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" != "000" && "$status" != "404" ]]; then
            echo "[RESET-ENDPOINT] $url - HTTP $status" >> "$vectors_file"
            ((results++)) || true

            local reset_resp
            reset_resp=$(curl -s -m 10 -X POST -d "email=nonexistent_xyz_$(date +%s)@example.com" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                "$url" 2>/dev/null || true)

            if [[ -n "$reset_resp" ]]; then
                local reset_indicators=("no account" "not found" "not registered" "does not exist")
                for rind in "${reset_indicators[@]}"; do
                    local rfound
                    rfound=$(echo "$reset_resp" | grep -ci "$rind" 2>/dev/null || echo "0")
                    if [[ "$rfound" -gt 0 ]]; then
                        echo "[RESET-ENUM] $url - Password reset reveals account: '$rind'" >> "$vectors_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"reset_enumeration\",\"url\":\"$url\",\"pattern\":\"$rind\",\"severity\":\"MEDIUM\",\"evidence\":\"Password reset reveals whether email is registered\"}" \
                            "$findings_file" 2>/dev/null || true
                    fi
                done
            fi
        fi
    done

    # Write count
    echo "$results" > "$output_dir/account_enum/count.txt"

    py_log "INFO" "account_enum_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Account enumeration phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    account_enum_phase "$@"
fi
