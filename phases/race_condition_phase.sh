#!/usr/bin/env bash
# race_condition_phase.sh - Race condition test harness, concurrent request testing,
# TOCTOU vulnerability detection.

race_condition_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "race_condition_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/race_condition"

    local results=0
    local race_file="$output_dir/race_condition/race_vulns.txt"
    local toctou_file="$output_dir/race_condition/toctou_vectors.txt"

    log "INFO" "Starting race condition testing for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }
    tool_available xargs || true

    # Race-sensitive endpoints
    local race_endpoints=(
        "/api/transfer"
        "/api/payment"
        "/api/checkout"
        "/api/purchase"
        "/api/redeem"
        "/api/coupon/apply"
        "/api/wallet/withdraw"
        "/api/balance"
        "/api/points/redeem"
        "/api/ticket/purchase"
        "/api/seat/reserve"
        "/api/inventory/update"
        "/api/stock/purchase"
    )

    local concurrent_count=10
    local temp_dir
    temp_dir=$(mktemp -d)

    # Test 1: Concurrent balance/read-then-write
    log "INFO" "Testing concurrent balance operations"
    local balance_endpoints=("/api/balance" "/api/wallet" "/api/credits" "/api/account/balance")

    for ep in "${balance_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local base_status
        base_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$base_status" == "200" ]]; then
            log "INFO" "Sending $concurrent_count concurrent requests to $ep"

            # Send concurrent requests
            local pids=()
            for i in $(seq 1 "$concurrent_count"); do
                curl -s -m 10 "$url" > "$temp_dir/race_${ep//\//_}_$i.txt" 2>/dev/null &
                pids+=($!)
            done

            # Wait for all requests
            local all_success=true
            for pid in "${pids[@]}"; do
                wait "$pid" 2>/dev/null || all_success=false
            done

            # Analyze results - check for inconsistent responses
            local responses=()
            for i in $(seq 1 "$concurrent_count"); do
                local resp_file="$temp_dir/race_${ep//\//_}_$i.txt"
                if [[ -f "$resp_file" ]]; then
                    local resp_hash
                    resp_hash=$(md5sum "$resp_file" 2>/dev/null | cut -d' ' -f1 || true)
                    responses+=("$resp_hash")
                fi
            done

            # Check for unique responses (potential race condition)
            local unique_responses
            unique_responses=$(printf '%s\n' "${responses[@]}" | sort -u | wc -l)
            local total_responses=${#responses[@]}

            if [[ "$unique_responses" -gt 1 && "$total_responses" -gt 1 ]]; then
                echo "[RACE-BALANCE] $ep - $unique_responses unique responses out of $total_responses concurrent requests" >> "$race_file"
                echo "  Responses may indicate TOCTOU in balance check" >> "$race_file"
                echo "---" >> "$race_file"
                ((results++)) || true
            fi
        fi
    done

    # Test 2: Concurrent resource creation (double-spend)
    log "INFO" "Testing concurrent creation for double-spend"
    local create_endpoints=(
        "/api/orders/create"
        "/api/payment/process"
        "/api/transfer/send"
        "/api/purchase/complete"
        "/api/checkout/submit"
    )

    for ep in "${create_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local base_status
        base_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
            -d "test=1" "$url" 2>/dev/null || echo "000")

        if [[ "$base_status" != "404" && "$base_status" != "000" ]]; then
            log "INFO" "Testing double-spend on $ep with $concurrent_count concurrent requests"

            local pids=()
            for i in $(seq 1 "$concurrent_count"); do
                curl -s -o /dev/null -w "%{http_code}\n" -m 10 -X POST \
                    -d "amount=100&item=test_$i" "$url" > "$temp_dir/spend_${ep//\//_}_$i.txt" 2>/dev/null &
                pids+=($!)
            done

            for pid in "${pids[@]}"; do
                wait "$pid" 2>/dev/null || true
            done

            # Count successful responses
            local success_count=0
            for i in $(seq 1 "$concurrent_count"); do
                local spend_file="$temp_dir/spend_${ep//\//_}_$i.txt"
                if [[ -f "$spend_file" ]]; then
                    local code
                    code=$(cat "$spend_file" 2>/dev/null || true)
                    if [[ "$code" == "200" || "$code" == "201" ]]; then
                        ((success_count++)) || true
                    fi
                fi
            done

            if [[ "$success_count" -gt 1 ]]; then
                echo "[DOUBLE-SPEND] $ep - $success_count/$concurrent_count concurrent requests succeeded" >> "$race_file"
                echo "  Potential double-spend vulnerability" >> "$race_file"
                echo "---" >> "$race_file"
                ((results++)) || true
            fi
        fi
    done

    # Test 3: TOCTOU - Time-of-check to time-of-use
    log "INFO" "Testing TOCTOU vulnerabilities"

    # Check-then-act patterns
    local check_endpoints=(
        "/api/stock/check"
        "/api/inventory/check"
        "/api/availability/check"
        "/api/quota/check"
        "/api/limit/check"
    )

    for ep in "${check_endpoints[@]}"; do
        local check_url="https://${domain}${ep}"
        local act_url="https://${domain}${ep/\/check//\/use}"

        local check_status
        check_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$check_url" 2>/dev/null || echo "000")
        local act_status
        act_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST "$act_url" 2>/dev/null || echo "000")

        if [[ "$check_status" == "200" && "$act_status" != "404" ]]; then
            # Interleave check and act requests
            local toctou_pids=()
            for i in $(seq 1 5); do
                curl -s -m 10 "$check_url" > "$temp_dir/toctou_check_$i.txt" 2>/dev/null &
                toctou_pids+=($!)
                curl -s -o /dev/null -w "%{http_code}\n" -m 10 -X POST "$act_url" > "$temp_dir/toctou_act_$i.txt" 2>/dev/null &
                toctou_pids+=($!)
            done

            for pid in "${toctou_pids[@]}"; do
                wait "$pid" 2>/dev/null || true
            done

            local act_success=0
            for i in $(seq 1 5); do
                local act_code
                act_code=$(cat "$temp_dir/toctou_act_$i.txt" 2>/dev/null || true)
                if [[ "$act_code" == "200" || "$act_code" == "201" ]]; then
                    ((act_success++)) || true
                fi
            done

            if [[ "$act_success" -gt 0 ]]; then
                echo "[TOCTOU] $ep - Check-then-act pattern: $act_success successful acts during concurrent checks" >> "$toctou_file"
                ((results++)) || true
            fi
        fi
    done

    # Test 4: Race in token generation
    log "INFO" "Testing race in token/nonce generation"
    local token_endpoints=(
        "/api/token/generate"
        "/api/nonce"
        "/api/csrf-token"
        "/api/auth/challenge"
    )

    for ep in "${token_endpoints[@]}"; do
        local url="https://${domain}${ep}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

        if [[ "$status" == "200" ]]; then
            local tokens=()
            for i in $(seq 1 10); do
                local token_resp
                token_resp=$(curl -s -m 10 "$url" 2>/dev/null || true)
                local token_val
                token_val=$(echo "$token_resp" | grep -oE '"token"\s*:\s*"[^"]*"' | head -1 || true)
                tokens+=("$token_val")
            done

            local unique_tokens
            unique_tokens=$(printf '%s\n' "${tokens[@]}" | sort -u | wc -l)
            if [[ "$unique_tokens" -lt "${#tokens[@]}" ]]; then
                echo "[TOKEN-RACE] $ep - Duplicate tokens generated under concurrent requests" >> "$race_file"
                ((results++)) || true
            fi
        fi
    done

    # Test 5: Race in rate limiting (bypass via concurrency)
    log "INFO" "Testing rate-limit bypass via concurrency"
    local rl_test_url="https://${domain}/api/login"
    local rl_pids=()
    local rl_results_file="$temp_dir/rl_race_results.txt"

    for i in $(seq 1 20); do
        curl -s -o /dev/null -w "%{http_code}\n" -m 5 -X POST \
            -d "user=test&pass=test" "$rl_test_url" >> "$rl_results_file" 2>/dev/null &
        rl_pids+=($!)
    done

    for pid in "${rl_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    local rl_429_count=0
    local rl_success_count=0
    while IFS= read -r code; do
        if [[ "$code" == "429" ]]; then
            ((rl_429_count++)) || true
        elif [[ "$code" == "200" || "$code" == "401" || "$code" == "400" ]]; then
            ((rl_success_count++)) || true
        fi
    done < "$rl_results_file" 2>/dev/null || true

    if [[ "$rl_429_count" -eq 0 && "$rl_success_count" -gt 5 ]]; then
        echo "[RL-RACE-BYPASS] $rl_test_url - No 429s in $rl_success_count concurrent requests" >> "$toctou_file"
        ((results++)) || true
    fi

    # Cleanup
    rm -rf "$temp_dir" 2>/dev/null || true

    # Write count
    echo "$results" > "$output_dir/race_condition/count.txt"

    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "race_condition" "HIGH" "$line" 2>/dev/null || true
        done < "$race_file" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "race_condition" "MEDIUM" "$line" 2>/dev/null || true
        done < "$toctou_file" 2>/dev/null || true
    fi

    py_log "INFO" "race_condition_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Race condition phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    race_condition_phase "$@"
fi
