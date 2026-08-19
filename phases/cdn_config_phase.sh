#!/usr/bin/env bash
# CDN Configuration Audit
# Detects cache poisoning, origin shield bypass, and CDN misconfigurations

cdn_config_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "cdn_config_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/cdn_config"
    mkdir -p "$phase_dir"

    log "INFO" "Starting cdn_config_phase for $domain"

    local cdn_vulns="$phase_dir/cdn_vulns.txt"
    local cdn_config="$phase_dir/cdn_config.txt"
    local count=0

    # --- Fetch response headers ---
    log "INFO" "Fetching response headers..."
    local headers_file="$phase_dir/response_headers.txt"
    curl -sI -m 10 "https://$domain/" > "$headers_file" 2>/dev/null || true

    # --- Detect CDN provider ---
    local cdn_provider="unknown"
    if grep -qi "cf-ray" "$headers_file" 2>/dev/null; then
        cdn_provider="cloudflare"
    elif grep -qi "x-amz-cf-id\|x-amz-cf-pop" "$headers_file" 2>/dev/null; then
        cdn_provider="cloudfront"
    elif grep -qi "x-fastly" "$headers_file" 2>/dev/null; then
        cdn_provider="fastly"
    elif grep -qi "x-akamai\|x-akamai-transformed" "$headers_file" 2>/dev/null; then
        cdn_provider="akamai"
    elif grep -qi "x-cdn\|x-served-by.*cache" "$headers_file" 2>/dev/null; then
        cdn_provider="other"
    fi
    echo "[CONFIG] CDN provider detected: $cdn_provider" >> "$cdn_config"

    # --- Check for origin IP leakage ---
    log "INFO" "Checking for origin IP leakage..."

    # Check DNS for direct origin IPs
    local dns_file="$phase_dir/dns_records.txt"
    dig +short "$domain" A > "$dns_file" 2>/dev/null || true
    dig +short "$domain" CNAME >> "$dns_file" 2>/dev/null || true

    # Check if origin responds directly
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        local origin_resp
        origin_resp=$(curl -sI -m 5 "http://$ip" -H "Host: $domain" 2>/dev/null) || true
        if echo "$origin_resp" | grep -qiE "server:.*apache|server:.*nginx|server:.*iis"; then
            echo "[VULN] Origin server accessible directly: $ip" >> "$cdn_vulns"
            echo "$ip responds directly without CDN" >> "$cdn_config"
            ((count++)) || true
        fi
    done < "$dns_file"

    # --- Check for cache poisoning vectors ---
    log "INFO" "Testing cache poisoning vectors..."

    # Test Host header injection
    local host_test
    host_test=$(curl -sI -m 5 -H "Host: evil.com" "https://$domain/" 2>/dev/null) || true
    if echo "$host_test" | grep -qiE "evil\.com|location:.*evil"; then
        echo "[VULN] Host header injection possible - cache poisoning vector" >> "$cdn_vulns"
        ((count++)) || true
    fi

    # Test X-Forwarded-Host injection
    local xfh_test
    xfh_test=$(curl -sI -m 5 -H "X-Forwarded-Host: evil.com" "https://$domain/" 2>/dev/null) || true
    if echo "$xfh_test" | grep -qiE "evil\.com"; then
        echo "[VULN] X-Forwarded-Host header influences response - cache poisoning vector" >> "$cdn_vulns"
        ((count++)) || true
    fi

    # --- Check cache headers ---
    log "INFO" "Analyzing cache configuration..."
    if grep -qiE "cache-control:.*no-store" "$headers_file" 2>/dev/null; then
        echo "[CONFIG] No-store cache directive present" >> "$cdn_config"
    fi
    if grep -qiE "cache-control:.*s-maxage" "$headers_file" 2>/dev/null; then
        local s_maxage
        s_maxage=$(grep -oiE "s-maxage=[0-9]+" "$headers_file" | head -1) || true
        echo "[CONFIG] CDN cache TTL: $s_maxage" >> "$cdn_config"
    fi
    if grep -qi "x-cache" "$headers_file" 2>/dev/null; then
        local cache_status
        cache_status=$(grep -i "^x-cache:" "$headers_file" | head -1) || true
        echo "[CONFIG] Cache status: $cache_status" >> "$cdn_config"
    fi

    # --- Check for origin shield bypass ---
    log "INFO" "Checking for origin shield bypass..."

    # Test range requests
    local range_test
    range_test=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -H "Range: bytes=0-0" "https://$domain/" 2>/dev/null) || true
    if [[ "$range_test" == "206" ]]; then
        echo "[CONFIG] Range requests supported - possible origin shield bypass" >> "$cdn_config"
    fi

    # --- Check for CDN-specific misconfigurations ---
    if [[ "$cdn_provider" == "cloudflare" ]]; then
        # Check for Cloudflare origin IP
        local cf_headers
        cf_headers=$(curl -sI -m 5 "https://$domain/" 2>/dev/null) || true
        if ! echo "$cf_headers" | grep -qi "cf-ray"; then
            echo "[VULN] Cloudflare not active - origin exposed" >> "$cdn_vulns"
            ((count++)) || true
        fi

        # Check for Cloudflare SPOA (Server Push)
        local spf_resp
        spf_resp=$(curl -sI -m 5 "https://$domain/__cf_spf_e.html" 2>/dev/null) || true
        if echo "$spf_resp" | grep -qi "200"; then
            echo "[CONFIG] Cloudflare SPF endpoint accessible" >> "$cdn_config"
        fi
    fi

    # --- Test for stale content serving ---
    log "INFO" "Testing for stale content serving..."
    local stale_test
    stale_test=$(curl -s -m 5 -H "Cache-Control: max-stale=999999" "https://$domain/" 2>/dev/null) || true
    if [[ -n "$stale_test" ]]; then
        echo "[CONFIG] Stale content serving may be enabled" >> "$cdn_config"
    fi

    # --- Write structured findings ---
    if [[ -f "$cdn_vulns" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "cdn_config" "" "" ""
        done < "$cdn_vulns"
    fi

    if [[ -f "$cdn_config" ]]; then
        while IFS= read -r config_line; do
            write_asset "$phase_dir" "$domain" "cdn_config" "$config_line" "" ""
        done < "$cdn_config"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "cdn_config_phase" "domain=$domain cdn=$cdn_provider findings=$count"

    log "INFO" "cdn_config_phase complete: $count findings (CDN: $cdn_provider)"
    return 0
}

cdn_config_phase "$@"
