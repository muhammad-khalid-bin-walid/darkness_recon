#!/bin/bash
# Caching layer poisoning test module, web cache deception, cache key manipulation

cache_poisoning_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local cache_dir="$output_dir/cache_poisoning"
    local live_file="$output_dir/live/live_subdomains.txt"
    local crawl_file="$output_dir/crawl/endpoints.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$cache_dir"

    log "INFO" "Starting cache poisoning testing for $domain"
    py_log "INFO" "cache_poisoning_phase started" --phase "cache_poisoning" --target "$domain" || true

    local cache_poison_vulns="$cache_dir/cache_poison_vulns.txt"
    local cache_layers="$cache_dir/cache_layers.txt"
    touch "$cache_poison_vulns" "$cache_layers"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, skipping cache poisoning testing"
        echo "0" > "$cache_dir/count.txt"
        return 0
    fi

    # ------------------------------------------------------------------
    # 1. Detect caching layers
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Detecting caching layers..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local headers
            headers=$(curl -s -D - -o /dev/null --max-time 10 "$host" 2>/dev/null) || true

            echo "$headers" | grep -qiE "x-cache|cf-cache|via|age|cdn-cache|fastly|x-varnish|akamai" && echo "$host | $(echo "$headers" | grep -iE 'x-cache|cf-cache|via|age|cdn-cache|fastly|x-varnish|akamai' | tr -d '\r\n')" >> "$cache_layers" || true
        done < <(head -30 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 2. Unkeyed header poisoning
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing unkeyed header poisoning..."
        local poison_marker="POISONED_$(date +%s)"

        while IFS= read -r host; do
            [ -z "$host" ] && continue
            # Send request with unkeyed header
            local first_resp
            first_resp=$(curl -s -D - -o "$cache_dir/_poison_body.tmp" --max-time 10 \
                -H "X-Forwarded-Host: ${poison_marker}.com" \
                "$host" 2>/dev/null) || true

            # Send second request without poison header to check if cached
            local second_resp
            second_resp=$(curl -s -D - -o "$cache_dir/_poison_body2.tmp" --max-time 10 \
                "$host" 2>/dev/null) || true

            if grep -qi "$poison_marker" "$cache_dir/_poison_body2.tmp" 2>/dev/null; then
                echo "UNKEYED_HEADER_POISON: $host | X-Forwarded-Host poisoned cached response" >> "$cache_poison_vulns"
                write_finding "{\"type\":\"cache_poison_unkeyed_header\",\"url\":\"$host\",\"severity\":\"critical\",\"domain\":\"$domain\"}" "$cache_dir/findings.json" || true
            fi
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 3. Cache key manipulation via parameter order
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing cache key manipulation..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local base_url="${host%/}"
            # Test with different parameter orderings
            local resp1 resp2
            resp1=$(curl -s -D - -o /dev/null --max-time 10 "${base_url}?a=1&b=2" 2>/dev/null) || true
            resp2=$(curl -s -D - -o /dev/null --max-time 10 "${base_url}?b=2&a=1" 2>/dev/null) || true

            local hit1 hit2
            hit1=$(echo "$resp1" | grep -iE "x-cache.*hit|cf-cache.*hit|age: [0-9]" | head -1)
            hit2=$(echo "$resp2" | grep -iE "x-cache.*hit|cf-cache.*hit|age: [0-9]" | head -1)
            if [ -n "$hit1" ] && [ -n "$hit2" ]; then
                echo "CACHE_KEY_PARAM_ORDER: $host | Different param order shares cache" >> "$cache_poison_vulns"
            fi
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 4. Web cache deception testing
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing web cache deception..."
        local deception_paths
        deception_paths="/admin.css /admin.js /profile.css /settings.js /account.js /user.css"

        while IFS= read -r host; do
            [ -z "$host" ] && continue
            for dpath in $deception_paths; do
                local resp
                resp=$(curl -s -D - --max-time 10 "${host%/}${dpath}" 2>/dev/null) || true
                if echo "$resp" | grep -qiE "x-cache.*hit|cf-cache.*hit|age: [0-9]"; then
                    local content_type
                    content_type=$(echo "$resp" | grep -i "^content-type:" | head -1 | tr -d '\r\n')
                    if echo "$content_type" | grep -qiE "text/html"; then
                        echo "WEB_CACHE_DECEPTION: ${host%/}${dpath} | HTML cached as static asset" >> "$cache_poison_vulns"
                        write_finding "{\"type\":\"web_cache_deception\",\"url\":\"${host%/}${dpath}\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$cache_dir/findings.json" || true
                    fi
                fi
            done
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 5. Vary header poisoning
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing Vary header poisoning..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local vary_resp
            vary_resp=$(curl -s -D - -o /dev/null --max-time 10 \
                -H "User-Agent: googlebot" \
                "$host" 2>/dev/null) || true

            local vary_header
            vary_header=$(echo "$vary_resp" | grep -i "^vary:" | tr -d '\r\n')
            if echo "$vary_header" | grep -qiE "user-agent"; then
                echo "VARY_USER_AGENT: $host | Vary: User-Agent set (cache key includes UA)" >> "$cache_poison_vulns"
            fi
            if [ -z "$vary_header" ]; then
                echo "NO_VARY_HEADER: $host | No Vary header (possible cache poisoning vector)" >> "$cache_poison_vulns"
            fi
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 6. Fat GET poisoning
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing fat GET poisoning..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local base_url="${host%/}"
            # Send a GET with body (fat GET)
            local fat_resp
            fat_resp=$(curl -s -D - -o /dev/null --max-time 10 \
                -X GET -d "poison=1" \
                "$base_url" 2>/dev/null) || true
            local http_code
            http_code=$(echo "$fat_resp" | head -1 | awk '{print $2}')
            if echo "$http_code" | grep -qE "^(200|201)$"; then
                echo "FAT_GET_ACCEPTED: $host | GET with body accepted (HTTP/1.1 compliant but unusual)" >> "$cache_poison_vulns"
            fi
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 7. Summary count
    # ------------------------------------------------------------------
    local vuln_count
    vuln_count=$(wc -l < "$cache_poison_vulns" 2>/dev/null || echo 0)
    log "INFO" "Cache poisoning testing complete: $vuln_count issues found"

    py_log "INFO" "cache_poisoning_phase complete" --phase "cache_poisoning" --target "$domain" --extra "{\"vulns\":$vuln_count}" || true
    echo "$vuln_count" > "$cache_dir/count.txt"
}

export -f cache_poisoning_phase
