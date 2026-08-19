#!/bin/bash
# WebSocket protocol testing, authentication bypass, message injection, cross-site WebSocket hijacking

websocket_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local ws_dir="$output_dir/websocket"
    local crawl_file="$output_dir/crawl/endpoints.txt"
    local live_file="$output_dir/live/live_subdomains.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$ws_dir"

    log "INFO" "Starting WebSocket testing for $domain"
    py_log "INFO" "websocket_phase started" --phase "websocket" --target "$domain" || true

    local websocket_vulns="$ws_dir/websocket_vulns.txt"
    local ws_endpoints="$ws_dir/ws_endpoints.txt"
    touch "$websocket_vulns" "$ws_endpoints"

    # ------------------------------------------------------------------
    # 1. Discover WebSocket endpoints
    # ------------------------------------------------------------------
    if [ -f "$crawl_file" ] && command -v grep >/dev/null 2>&1; then
        log "INFO" "Discovering WebSocket endpoints from crawl data..."
        grep -iE "(wss?://|ws_endpoint|websocket|socket\.io|sockjs|signalr|/ws/|/socket|/realtime)" "$crawl_file" 2>/dev/null \
            | sort -u > "$ws_endpoints" || true
    fi

    # Probe common WebSocket paths
    if [ -f "$live_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Probing common WebSocket upgrade paths..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local ws_host
            ws_host=$(echo "$host" | sed 's|https://|wss://|; s|http://|ws://|')
            for ws_path in /ws /websocket /socket.io /sockjs /signalr /ws/v1 /ws/v2 /api/ws /realtime; do
                local upgrade_resp
                upgrade_resp=$(curl -s -D - -o /dev/null --max-time 10 \
                    -H "Upgrade: websocket" \
                    -H "Connection: Upgrade" \
                    -H "Sec-WebSocket-Version: 13" \
                    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
                    "${host%/}${ws_path}" 2>/dev/null) || true
                if echo "$upgrade_resp" | grep -qiE "^(101|upgrade)"; then
                    echo "${ws_host}${ws_path}" >> "$ws_endpoints"
                    write_endpoint "{\"type\":\"websocket_endpoint\",\"url\":\"${ws_host}${ws_path}\",\"domain\":\"$domain\"}" "$ws_dir/endpoints.json" || true
                fi
            done
        done < <(head -30 "$live_file")
        sort -u "$ws_endpoints" -o "$ws_endpoints" 2>/dev/null || true
    fi

    # ------------------------------------------------------------------
    # 2. WebSocket authentication bypass testing
    # ------------------------------------------------------------------
    if [ -f "$ws_endpoints" ] && [ -s "$ws_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing WebSocket authentication bypass..."
        while IFS= read -r ws_url; do
            [ -z "$ws_url" ] && continue
            # Test without auth
            local no_auth_resp
            no_auth_resp=$(curl -s -D - -o /dev/null --max-time 10 \
                -H "Upgrade: websocket" \
                -H "Connection: Upgrade" \
                -H "Sec-WebSocket-Version: 13" \
                -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
                "$ws_url" 2>/dev/null) || true
            if echo "$no_auth_resp" | grep -qiE "101|switching"; then
                echo "WS_NO_AUTH: $ws_url | WebSocket upgrade accepted without authentication" >> "$websocket_vulns"
                write_finding "{\"type\":\"ws_auth_bypass\",\"url\":\"$ws_url\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$ws_dir/findings.json" || true
            fi
            # Test with empty auth header
            local empty_auth_resp
            empty_auth_resp=$(curl -s -D - -o /dev/null --max-time 10 \
                -H "Upgrade: websocket" \
                -H "Connection: Upgrade" \
                -H "Sec-WebSocket-Version: 13" \
                -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
                -H "Authorization: " \
                "$ws_url" 2>/dev/null) || true
            if echo "$empty_auth_resp" | grep -qiE "101|switching"; then
                echo "WS_EMPTY_AUTH: $ws_url | WebSocket upgrade accepted with empty auth" >> "$websocket_vulns"
            fi
        done < "$ws_endpoints"
    fi

    # ------------------------------------------------------------------
    # 3. Cross-Site WebSocket Hijacking (CSWSH) check
    # ------------------------------------------------------------------
    if [ -f "$ws_endpoints" ] && [ -s "$ws_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing for Cross-Site WebSocket Hijacking..."
        while IFS= read -r ws_url; do
            [ -z "$ws_url" ] && continue
            # CSWSH: check if origin is validated
            local csesh_resp
            csesh_resp=$(curl -s -D - -o /dev/null --max-time 10 \
                -H "Upgrade: websocket" \
                -H "Connection: Upgrade" \
                -H "Sec-WebSocket-Version: 13" \
                -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
                -H "Origin: https://evil.com" \
                "$ws_url" 2>/dev/null) || true
            if echo "$csesh_resp" | grep -qiE "101|switching"; then
                echo "CSWSH_VULN: $ws_url | Origin not validated, cross-site hijacking possible" >> "$websocket_vulns"
                write_finding "{\"type\":\"cswsh\",\"url\":\"$ws_url\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$ws_dir/findings.json" || true
            fi
            # Check with null origin
            local null_origin_resp
            null_origin_resp=$(curl -s -D - -o /dev/null --max-time 10 \
                -H "Upgrade: websocket" \
                -H "Connection: Upgrade" \
                -H "Sec-WebSocket-Version: 13" \
                -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
                -H "Origin: null" \
                "$ws_url" 2>/dev/null) || true
            if echo "$null_origin_resp" | grep -qiE "101|switching"; then
                echo "CSWSH_NULL_ORIGIN: $ws_url | Null origin accepted" >> "$websocket_vulns"
            fi
        done < "$ws_endpoints"
    fi

    # ------------------------------------------------------------------
    # 4. WebSocket message injection via HTTP
    # ------------------------------------------------------------------
    if [ -f "$ws_endpoints" ] && [ -s "$ws_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing WebSocket message injection vectors..."
        while IFS= read -r ws_url; do
            [ -z "$ws_url" ] && continue
            # Try sending data to WebSocket via HTTP POST
            local http_url
            http_url=$(echo "$ws_url" | sed 's|wss://|https://|; s|ws://|http://|')
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                -X POST -H "Content-Type: application/json" \
                -d '{"type":"injection_test","data":"payload"}' \
                "$http_url" 2>/dev/null) || true
            if echo "$code" | grep -qE "^(200|201|101)$"; then
                echo "WS_HTTP_INJECTION: $http_url | POST accepted on WebSocket URL | Status: $code" >> "$websocket_vulns"
                write_finding "{\"type\":\"ws_http_injection\",\"url\":\"$http_url\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$ws_dir/findings.json" || true
            fi
        done < "$ws_endpoints"
    fi

    # ------------------------------------------------------------------
    # 5. WebSocket with wscat (if available)
    # ------------------------------------------------------------------
    if [ -f "$ws_endpoints" ] && [ -s "$ws_endpoints" ] && tool_available "wscat"; then
        log "INFO" "Testing WebSocket connections with wscat..."
        while IFS= read -r ws_url; do
            [ -z "$ws_url" ] && continue
            # Attempt connection with 5s timeout
            local ws_result
            ws_result=$(echo '{"type":"ping"}' | timeout 5 wscat -c "$ws_url" 2>&1) || true
            if echo "$ws_result" | grep -qiE "(connected|open)"; then
                echo "WSCAT_CONNECTED: $ws_url | WebSocket connection successful" >> "$websocket_vulns"
            fi
        done < "$ws_endpoints"
    fi

    # ------------------------------------------------------------------
    # 6. Summary count
    # ------------------------------------------------------------------
    local ws_count
    ws_count=$(wc -l < "$ws_endpoints" 2>/dev/null || echo 0)
    local vuln_count
    vuln_count=$(wc -l < "$websocket_vulns" 2>/dev/null || echo 0)
    log "INFO" "WebSocket testing complete: $ws_count endpoints, $vuln_count issues found"

    py_log "INFO" "websocket_phase complete" --phase "websocket" --target "$domain" --extra "{\"endpoints\":$ws_count,\"vulns\":$vuln_count}" || true
    echo "$vuln_count" > "$ws_dir/count.txt"
}

export -f websocket_phase
