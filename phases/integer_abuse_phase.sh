#!/usr/bin/env bash
# integer_abuse_phase.sh - Negative-value and integer-boundary abuse testing,
# overflow/underflow, type confusion.

integer_abuse_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "integer_abuse_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/integer_abuse"

    local results=0
    local vulns_file="$output_dir/integer_abuse/integer_vulns.txt"
    local boundary_file="$output_dir/integer_abuse/boundary_cases.txt"
    local findings_file="$output_dir/integer_abuse/findings.json"

    log "INFO" "Starting integer abuse phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Discover API endpoints accepting numeric parameters ---
    local api_paths=(
        "/api"
        "/api/v1"
        "/api/v2"
        "/api/users"
        "/api/products"
        "/api/items"
        "/api/orders"
        "/api/transactions"
        "/api/payments"
        "/api/transfer"
        "/api/balance"
        "/api/account"
        "/api/cart"
    )

    local numeric_params=("id" "amount" "quantity" "count" "page" "limit" "offset" "price" "value" "total" "balance" "units" "num" "size" "index")

    # Integer boundary values for testing
    local boundary_values=(
        "0"
        "1"
        "-1"
        "2147483647"
        "2147483648"
        "-2147483648"
        "-2147483649"
        "4294967295"
        "4294967296"
        "-4294967296"
        "999999999999999999"
        "-999999999999999999"
        "18446744073709551615"
        "18446744073709551616"
        "NaN"
        "Infinity"
        "-Infinity"
        "null"
        "undefined"
        "''"
        "\"\""
        "true"
        "false"
        "0.0001"
        "-0.0001"
        "0x7FFFFFFF"
        "0x80000000"
        "0xFFFFFFFF"
        "0x100000000"
        "1e308"
        "-1e308"
        "1e309"
    )

    for api_path in "${api_paths[@]}"; do
        local base_url="https://${domain}${api_path}"

        # --- GET parameter abuse ---
        for param in "${numeric_params[@]}"; do
            for bval in "${boundary_values[@]}"; do
                local test_url="${base_url}?${param}=${bval}"
                local resp_status resp_body
                resp_body=$(curl -s -m 10 -w "\n%{http_code}" "$test_url" 2>/dev/null || true)
                resp_status=$(echo "$resp_body" | tail -1)

                if [[ "$resp_status" == "200" ]]; then
                    local body_content
                    body_content=$(echo "$resp_body" | head -n -1)

                    # Check for data leakage from boundary abuse
                    local has_leakage=false
                    echo "$body_content" | grep -qiE '(error|exception|stack|trace|internal|debug|admin|password|secret|key)' 2>/dev/null && has_leakage=true

                    if [[ "$has_leakage" == "true" ]]; then
                        echo "[BOUNDARY-LEAK] $test_url - Error/debug info leaked via boundary value" >> "$vulns_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"integer_boundary_leak\",\"url\":\"$test_url\",\"param\":\"$param\",\"value\":\"$bval\",\"severity\":\"MEDIUM\",\"evidence\":\"Boundary value triggers error information disclosure\"}" \
                            "$findings_file" 2>/dev/null || true
                    fi

                    # Check for negative value acceptance
                    if [[ "$bval" == -* && "$resp_status" == "200" ]]; then
                        local has_positive=false
                        echo "$body_content" | grep -qiE '(success|"status":\s*"ok"|data)' 2>/dev/null && has_positive=true

                        if [[ "$has_positive" == "true" ]]; then
                            echo "[NEGATIVE-VALUE] $test_url - Negative value accepted: param=$param" >> "$boundary_file"
                            ((results++)) || true

                            write_finding "{\"type\":\"negative_value_accepted\",\"url\":\"$test_url\",\"param\":\"$param\",\"value\":\"$bval\",\"severity\":\"MEDIUM\",\"evidence\":\"Negative numeric value accepted where positive expected\"}" \
                                "$findings_file" 2>/dev/null || true
                        fi
                    fi

                    echo "$body_content" | grep -qiE '(overflow|underflow|out.of.range|truncat)' 2>/dev/null && {
                        echo "[OVERFLOW-ERROR] $test_url - Overflow/underflow error exposed" >> "$vulns_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"integer_overflow_exposed\",\"url\":\"$test_url\",\"param\":\"$param\",\"value\":\"$bval\",\"severity\":\"LOW\",\"evidence\":\"Integer overflow error message exposed to user\"}" \
                            "$findings_file" 2>/dev/null || true
                    } || true
                fi
            done

            # --- POST body type confusion ---
            local type_confusion_payloads=(
                "{\"${param}\": \"abc123\"}"
                "{\"${param}\": true}"
                "{\"${param}\": []}"
                "{\"${param}\": {}}"
                "{\"${param}\": null}"
                "{\"${param}\": {\"nested\": \"value\"}}"
                "{\"${param}\": 1.5}"
                "{\"${param}\": \"\"}"
            )

            for payload in "${type_confusion_payloads[@]}"; do
                local post_resp post_status
                post_resp=$(curl -s -m 10 -w "\n%{http_code}" -X POST \
                    -H "Content-Type: application/json" \
                    -d "$payload" \
                    "$base_url" 2>/dev/null || true)
                post_status=$(echo "$post_resp" | tail -1)

                if [[ "$post_status" == "200" || "$post_status" == "201" ]]; then
                    local post_body
                    post_body=$(echo "$post_resp" | head -n -1)

                    echo "$post_body" | grep -qiE '(success|"status":\s*"ok")' 2>/dev/null && {
                        echo "[TYPE-CONFUSION] $base_url - Type confusion accepted: $payload" >> "$vulns_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"type_confusion\",\"url\":\"$base_url\",\"param\":\"$param\",\"payload\":\"$payload\",\"severity\":\"MEDIUM\",\"evidence\":\"Non-numeric type accepted for numeric parameter\"}" \
                            "$findings_file" 2>/dev/null || true
                    } || true
                fi
            done
        done

        # --- Test quantity/amount manipulation in order flows ---
        local order_payloads=(
            '{"quantity":-1,"id":1}'
            '{"amount":-100,"id":1}'
            '{"quantity":0,"id":1}'
            '{"amount":0.001,"id":1}'
            '{"quantity":999999999,"id":1}'
            '{"amount":999999999.99,"id":1}'
        )

        for payload in "${order_payloads[@]}"; do
            local order_resp order_status
            order_resp=$(curl -s -m 10 -w "\n%{http_code}" -X POST \
                -H "Content-Type: application/json" \
                -d "$payload" \
                "${base_url}/order" 2>/dev/null || true)
            order_status=$(echo "$order_resp" | tail -1)

            if [[ "$order_status" == "200" || "$order_status" == "201" ]]; then
                echo "[ORDER-MANIPULATION] ${base_url}/order - Integer abuse accepted: $payload" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"order_quantity_abuse\",\"url\":\"${base_url}/order\",\"payload\":\"$payload\",\"severity\":\"HIGH\",\"evidence\":\"Negative/zero/extreme quantity accepted in order flow\"}" \
                    "$findings_file" 2>/dev/null || true
            fi
        done
    done

    # Write count
    echo "$results" > "$output_dir/integer_abuse/count.txt"

    py_log "INFO" "integer_abuse_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Integer abuse phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    integer_abuse_phase "$@"
fi
