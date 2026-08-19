#!/bin/bash
# Server-Sent Events and long-poll endpoint security testing, event source validation

sse_polling_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local sse_dir="$output_dir/sse_polling"
    local crawl_file="$output_dir/crawl/endpoints.txt"
    local live_file="$output_dir/live/live_subdomains.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$sse_dir"

    log "INFO" "Starting SSE/Polling security testing for $domain"
    py_log "INFO" "sse_polling_phase started" --phase "sse_polling" --target "$domain" || true

    local sse_endpoints="$sse_dir/sse_endpoints.txt"
    local sse_vulns="$sse_dir/sse_vulns.txt"
    touch "$sse_endpoints" "$sse_vulns"

    # ------------------------------------------------------------------
    # 1. Discover SSE endpoints from crawl data
    # ------------------------------------------------------------------
    if [ -f "$crawl_file" ] && command -v grep >/dev/null 2>&1; then
        log "INFO" "Discovering SSE/long-poll endpoints from crawl data..."
        grep -iE "(text/event-stream|eventsource|/events|/sse|/stream|/subscribe|/listen|/feed|/live|/notifications|long.?poll)" "$crawl_file" 2>/dev/null \
            | sort -u > "$sse_endpoints" || true
    fi

    # ------------------------------------------------------------------
    # 2. Probe for SSE endpoints via Accept header
    # ------------------------------------------------------------------
    if [ -f "$live_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Probing for SSE endpoints..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            for sse_path in /events /sse /stream /subscribe /listen /feed /live /notifications /api/events /api/sse /api/stream /ws/events; do
                local resp_headers
                resp_headers=$(curl -s -D - -o "$sse_dir/_sse_body.tmp" --max-time 10 \
                    -H "Accept: text/event-stream" \
                    "${host%/}${sse_path}" 2>/dev/null) || true

                if echo "$resp_headers" | grep -qiE "text/event-stream"; then
                    echo "${host%/}${sse_path}" >> "$sse_endpoints"
                    write_endpoint "{\"type\":\"sse_endpoint\",\"url\":\"${host%/}${sse_path}\",\"domain\":\"$domain\"}" "$sse_dir/endpoints.json" || true
                fi
            done
        done < <(head -30 "$live_file")
        sort -u "$sse_endpoints" -o "$sse_endpoints" 2>/dev/null || true
    fi

    # ------------------------------------------------------------------
    # 3. Long-poll endpoint detection
    # ------------------------------------------------------------------
    if [ -f "$live_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Detecting long-polling endpoints..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            for poll_path in /poll /long-poll /api/poll /api/long-poll /wait /listen /subscribe; do
                local start_time end_time elapsed resp_code
                start_time=$(date +%s 2>/dev/null || echo 0)
                resp_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
                    "${host%/}${poll_path}?timeout=5000" 2>/dev/null) || true
                end_time=$(date +%s 2>/dev/null || echo 0)
                elapsed=$((end_time - start_time))

                if [ "$elapsed" -ge 5 ] && echo "$resp_code" | grep -qE "^(200|201)$"; then
                    echo "${host%/}${poll_path}" >> "$sse_endpoints"
                    echo "LONG_POLL: ${host%/}${poll_path} | Elapsed: ${elapsed}s | Status: $resp_code" >> "$sse_vulns"
                fi
            done
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 4. SSE authentication and authorization checks
    # ------------------------------------------------------------------
    if [ -f "$sse_endpoints" ] && [ -s "$sse_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing SSE authentication..."
        while IFS= read -r sse_url; do
            [ -z "$sse_url" ] && continue
            # Test without auth
            local no_auth_resp
            no_auth_resp=$(curl -s -D - -o /dev/null --max-time 10 \
                -H "Accept: text/event-stream" \
                "$sse_url" 2>/dev/null) || true
            if echo "$no_auth_resp" | grep -qiE "text/event-stream"; then
                echo "SSE_NO_AUTH: $sse_url | SSE stream accessible without authentication" >> "$sse_vulns"
                write_finding "{\"type\":\"sse_no_auth\",\"url\":\"$sse_url\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$sse_dir/findings.json" || true
            fi
            # Test with empty auth
            local empty_auth_resp
            empty_auth_resp=$(curl -s -D - -o /dev/null --max-time 10 \
                -H "Accept: text/event-stream" \
                -H "Authorization: " \
                "$sse_url" 2>/dev/null) || true
            if echo "$empty_auth_resp" | grep -qiE "text/event-stream"; then
                echo "SSE_EMPTY_AUTH: $sse_url | SSE accessible with empty auth" >> "$sse_vulns"
            fi
        done < "$sse_endpoints"
    fi

    # ------------------------------------------------------------------
    # 5. SSE event source origin validation
    # ------------------------------------------------------------------
    if [ -f "$sse_endpoints" ] && [ -s "$sse_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing SSE event source origin validation..."
        while IFS= read -r sse_url; do
            [ -z "$sse_url" ] && continue
            # Check CORS headers on SSE stream
            local cors_resp
            cors_resp=$(curl -s -D - -o /dev/null --max-time 10 \
                -H "Origin: https://evil.com" \
                -H "Accept: text/event-stream" \
                "$sse_url" 2>/dev/null) || true
            if echo "$cors_resp" | grep -qiE "access-control-allow-origin.*evil\.com"; then
                echo "SSE_CORS_BYPASS: $sse_url | Origin reflected in CORS" >> "$sse_vulns"
                write_finding "{\"type\":\"sse_cors_bypass\",\"url\":\"$sse_url\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$sse_dir/findings.json" || true
            fi
            # Check for Access-Control-Allow-Credentials
            if echo "$cors_resp" | grep -qiE "access-control-allow-credentials.*true"; then
                echo "SSE_CREDENTIALS_REFLECTED: $sse_url | Credentials allowed with reflected origin" >> "$sse_vulns"
            fi
        done < "$sse_endpoints"
    fi

    # ------------------------------------------------------------------
    # 6. SSE data injection via URL parameters
    # ------------------------------------------------------------------
    if [ -f "$sse_endpoints" ] && [ -s "$sse_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing SSE parameter injection..."
        while IFS= read -r sse_url; do
            [ -z "$sse_url" ] && continue
            for param in "channel=test&data=injected" "event=<script>alert(1)</script>" "data=${IFS}injected" "callback=alert(1)"; do
                local test_url="${sse_url}?${param}"
                local resp
                resp=$(curl -s --max-time 5 \
                    -H "Accept: text/event-stream" \
                    "$test_url" 2>/dev/null) || true
                if echo "$resp" | grep -qiE "(injected|alert|<script>)"; then
                    echo "SSE_INJECTION: $test_url | Parameter reflected in stream" >> "$sse_vulns"
                    write_finding "{\"type\":\"sse_parameter_injection\",\"url\":\"$test_url\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$sse_dir/findings.json" || true
                fi
            done
        done < "$sse_endpoints"
    fi

    # ------------------------------------------------------------------
    # 7. Summary count
    # ------------------------------------------------------------------
    local ep_count
    ep_count=$(wc -l < "$sse_endpoints" 2>/dev/null || echo 0)
    local vuln_count
    vuln_count=$(wc -l < "$sse_vulns" 2>/dev/null || echo 0)
    log "INFO" "SSE/Polling testing complete: $ep_count endpoints, $vuln_count issues found"

    py_log "INFO" "sse_polling_phase complete" --phase "sse_polling" --target "$domain" --extra "{\"endpoints\":$ep_count,\"vulns\":$vuln_count}" || true
    echo "$vuln_count" > "$sse_dir/count.txt"
}

export -f sse_polling_phase
