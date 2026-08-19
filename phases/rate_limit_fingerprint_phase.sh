#!/usr/bin/env bash
# rate_limit_fingerprint_phase.sh - Rate-limit header and 429-behavior fingerprinting,
# rate-limit bypass vectors, token bucket analysis.

rate_limit_fingerprint_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "rate_limit_fingerprint_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/rate_limit"

    local results=0
    local map_file="$output_dir/rate_limit/rate_limit_map.txt"
    local bypass_file="$output_dir/rate_limit/bypass_vectors.txt"

    log "INFO" "Starting rate-limit fingerprinting for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    local endpoints=("/" "/api" "/api/health" "/api/login" "/api/register" "/api/search" "/api/users" "/api/data")

    # Fingerprint rate-limit headers from each endpoint
    for endpoint in "${endpoints[@]}"; do
        local url="https://${domain}${endpoint}"
        log "INFO" "Probing rate limits on $url"

        local headers
        headers=$(curl -sI -m 10 "$url" 2>/dev/null || true)

        if [[ -z "$headers" ]]; then
            continue
        fi

        # Extract rate-limit related headers
        local rl_headers
        rl_headers=$(echo "$headers" | grep -iE "(rate-limit|x-rate|ratelimit|retry-after|x-ratelimit|limit|remaining|reset|throttl)" || true)

        if [[ -n "$rl_headers" ]]; then
            echo "[RATE-LIMIT-HEADERS] $endpoint:" >> "$map_file"
            echo "$rl_headers" >> "$map_file"
            echo "---" >> "$map_file"
            ((results++)) || true

            # Parse specific values
            local remaining
            remaining=$(echo "$rl_headers" | grep -oiE "remaining[=: ]*[0-9]+" | head -1 || true)
            local limit_val
            limit_val=$(echo "$rl_headers" | grep -oiE "limit[=: ]*[0-9]+" | head -1 || true)
            local reset_val
            reset_val=$(echo "$rl_headers" | grep -oiE "reset[=: ]*[0-9]+" | head -1 || true)

            if [[ -n "$remaining" && -n "$limit_val" ]]; then
                echo "[TOKEN-BUCKET] $endpoint - Limit: $limit_val, Remaining: $remaining, Reset: $reset_val" >> "$map_file"
                ((results++)) || true
            fi
        fi
    done

    # Send rapid requests to detect 429 behavior
    log "INFO" "Testing 429 behavior with rapid requests"
    local test_url="https://${domain}/api/login"

    local batch_results=()
    for i in $(seq 1 20); do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -X POST -d "test=1" "$test_url" 2>/dev/null || echo "000")
        batch_results+=("$status")
    done

    # Analyze 429 pattern
    local count_429=0
    local count_200=0
    local first_429_index=-1
    for i in "${!batch_results[@]}"; do
        if [[ "${batch_results[$i]}" == "429" ]]; then
            ((count_429++)) || true
            if [[ $first_429_index -eq -1 ]]; then
                first_429_index=$((i + 1))
            fi
        elif [[ "${batch_results[$i]}" == "200" || "${batch_results[$i]}" == "401" || "${batch_results[$i]}" == "400" ]]; then
            ((count_200++)) || true
        fi
    done

    if [[ $count_429 -gt 0 ]]; then
        echo "[429-PATTERN] Endpoint: $test_url" >> "$map_file"
        echo "  Triggered after request #$first_429_index" >> "$map_file"
        echo "  Total 429s in batch: $count_429/20" >> "$map_file"
        echo "  Successful requests: $count_200/20" >> "$map_file"

        # Check for Retry-After header on 429
        local retry_after_headers
        retry_after_headers=$(curl -sI -m 5 -X POST -d "test=1" "$test_url" 2>/dev/null | grep -i "retry-after" || true)
        if [[ -n "$retry_after_headers" ]]; then
            echo "  Retry-After: $retry_after_headers" >> "$map_file"
        fi

        echo "---" >> "$map_file"
        ((results++)) || true

        # Test bypass vectors
        log "INFO" "Testing rate-limit bypass vectors"

        # Header manipulation bypass
        local bypass_headers=(
            "X-Forwarded-For: 127.0.0.$((RANDOM % 255))"
            "X-Real-IP: 10.0.$((RANDOM % 255)).$((RANDOM % 255))"
            "X-Originating-IP: 192.168.$((RANDOM % 255)).$((RANDOM % 255))"
            "X-Client-IP: 172.16.$((RANDOM % 255)).$((RANDOM % 255))"
            "Forwarded: for=127.0.0.$((RANDOM % 255))"
            "X-Forwarded-Host: $domain"
            "X-Forwarded-Proto: https"
        )

        for bh in "${bypass_headers[@]}"; do
            local bypass_status
            bypass_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -X POST -d "test=1" -H "$bh" "$test_url" 2>/dev/null || echo "000")
            if [[ "$bypass_status" != "429" && "$bypass_status" != "000" ]]; then
                echo "[BYPASS-FOUND] Header: $bh -> HTTP $bypass_status (expected 429)" >> "$bypass_file"
                ((results++)) || true
            fi
        done

        # Method variation bypass
        local methods=("GET" "POST" "PUT" "PATCH" "DELETE" "OPTIONS" "HEAD")
        for method in "${methods[@]}"; do
            local method_status
            method_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -X "$method" "$test_url" 2>/dev/null || echo "000")
            if [[ "$method_status" != "429" && "$method_status" != "000" ]]; then
                echo "[METHOD-BYPASS] $method $test_url -> HTTP $method_status (expected 429)" >> "$bypass_file"
                ((results++)) || true
            fi
        done

        # User-Agent rotation bypass
        local agents=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            "Googlebot/2.1 (+http://www.google.com/bot.html)"
            "curl/7.68.0"
        )
        for agent in "${agents[@]}"; do
            local agent_status
            agent_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -H "User-Agent: $agent" -X POST -d "test=1" "$test_url" 2>/dev/null || echo "000")
            if [[ "$agent_status" != "429" && "$agent_status" != "000" ]]; then
                echo "[UA-BYPASS] User-Agent: $agent -> HTTP $agent_status (expected 429)" >> "$bypass_file"
                ((results++)) || true
            fi
        done

        # Cookie/session based bypass
        local cookie_jar
        cookie_jar=$(mktemp)
        curl -s -c "$cookie_jar" -m 5 "$test_url" 2>/dev/null || true
        local cookie_status
        cookie_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -b "$cookie_jar" -X POST -d "test=1" "$test_url" 2>/dev/null || echo "000")
        rm -f "$cookie_jar" 2>/dev/null || true

        if [[ "$cookie_status" != "429" && "$cookie_status" != "000" ]]; then
            echo "[COOKIE-BYPASS] Session cookie bypass -> HTTP $cookie_status (expected 429)" >> "$bypass_file"
            ((results++)) || true
        fi
    else
        echo "[NO-RATE-LIMIT] No 429 responses detected in 20 rapid requests to $test_url" >> "$map_file"
        echo "---" >> "$map_file"
        ((results++)) || true
    fi

    # Write count
    echo "$results" > "$output_dir/rate_limit/count.txt"

    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "rate_limit" "MEDIUM" "$line" 2>/dev/null || true
        done < "$bypass_file" 2>/dev/null || true
    fi

    py_log "INFO" "rate_limit_fingerprint_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Rate-limit fingerprint phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    rate_limit_fingerprint_phase "$@"
fi
