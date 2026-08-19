#!/bin/bash
# Content-Type confusion and response-splitting checks, MIME sniffing, X-Content-Type-Options validation

content_type_confusion_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local ct_dir="$output_dir/content_type_confusion"
    local live_file="$output_dir/live/live_subdomains.txt"
    local crawl_file="$output_dir/crawl/endpoints.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$ct_dir"

    log "INFO" "Starting Content-Type confusion testing for $domain"
    py_log "INFO" "content_type_confusion_phase started" --phase "content_type_confusion" --target "$domain" || true

    local content_type_vulns="$ct_dir/content_type_vulns.txt"
    local response_splitting="$ct_dir/response_splitting.txt"
    touch "$content_type_vulns" "$response_splitting"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, skipping Content-Type confusion testing"
        echo "0" > "$ct_dir/count.txt"
        return 0
    fi

    # ------------------------------------------------------------------
    # 1. X-Content-Type-Options missing check
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking X-Content-Type-Options headers..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local headers
            headers=$(curl -s -D - -o /dev/null --max-time 10 "$host" 2>/dev/null) || true
            if echo "$headers" | grep -qiE "content-type:.*text/html"; then
                if ! echo "$headers" | grep -qiE "x-content-type-options"; then
                    echo "MISSING_XCTO: $host | HTML response without X-Content-Type-Options" >> "$content_type_vulns"
                    write_finding "{\"type\":\"missing_xcontent_type_options\",\"url\":\"$host\",\"severity\":\"low\",\"domain\":\"$domain\"}" "$ct_dir/findings.json" || true
                fi
            fi
        done < <(head -30 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 2. MIME sniffing detection - send JS as image
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing MIME sniffing vulnerabilities..."
        local js_payload="$ct_dir/sniff_test.js"
        echo 'alert(document.domain)' > "$js_payload" 2>/dev/null || true

        while IFS= read -r host; do
            [ -z "$host" ] && continue
            # Try to upload JS as image
            for upload_path in /upload /api/upload /file/upload /images/upload; do
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
                    -F "file=@${js_payload};filename=test.jpg;type=image/jpeg" \
                    "${host%/}${upload_path}" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|201)$"; then
                    echo "MIME_SNIFF_UPLOAD: ${host%/}${upload_path} | JS file uploaded as image" >> "$content_type_vulns"
                    write_finding "{\"type\":\"mime_sniff_vulnerability\",\"url\":\"${host%/}${upload_path}\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$ct_dir/findings.json" || true
                fi
            done
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 3. Content-Type response splitting via header injection
    # ------------------------------------------------------------------
    if [ -f "$crawl_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing response splitting via Content-Type..."
        local injectable_params
        injectable_params=$(grep -iE "(\?|&)(content.?type|ct|mime|format|type)=" "$crawl_file" 2>/dev/null | head -30) || true

        while IFS= read -r target; do
            [ -z "$target" ] && continue
            # Inject newline into Content-Type parameter
            local test_url
            test_url=$(echo "$target" | sed 's|\(content.?type\|ct\|mime\|format\|type\)=[^&]*|\1=text/html%0d%0aX-Injected:true|' 2>/dev/null) || continue
            if [ "$test_url" = "$target" ]; then
                continue
            fi
            local resp_headers
            resp_headers=$(curl -s -D - -o /dev/null --max-time 10 "$test_url" 2>/dev/null) || true
            if echo "$resp_headers" | grep -qiE "X-Injected"; then
                echo "RESPONSE_SPLITTING: $test_url | Header injection successful" >> "$response_splitting"
                write_finding "{\"type\":\"response_splitting\",\"url\":\"$test_url\",\"severity\":\"critical\",\"domain\":\"$domain\"}" "$ct_dir/findings.json" || true
            fi
        done < <(echo "$injectable_params")
    fi

    # ------------------------------------------------------------------
    # 4. Content-Type override via Accept header manipulation
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing Content-Type override via Accept header..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            for accept in "application/json" "text/xml" "application/xml" "*/*" "text/html,application/xhtml+xml"; do
                local resp_ct
                resp_ct=$(curl -s -D - -o /dev/null --max-time 10 \
                    -H "Accept: $accept" \
                    "$host" 2>/dev/null) || true
                local returned_ct
                returned_ct=$(echo "$resp_ct" | grep -i "^content-type:" | head -1 | tr -d '\r\n' | awk -F': ' '{print $2}')
                if [ -n "$returned_ct" ]; then
                    echo "CT_OVERRIDE: $host | Accept: $accept -> Returned: $returned_ct" >> "$content_type_vulns"
                fi
            done
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 5. JSON response Content-Type validation
    # ------------------------------------------------------------------
    if [ -f "$crawl_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Validating JSON endpoint Content-Type enforcement..."
        grep -iE "(/api/|/json)" "$crawl_file" 2>/dev/null | sort -u | head -30 > "$ct_dir/_json_endpoints.txt" 2>/dev/null || true

        if [ -s "$ct_dir/_json_endpoints.txt" ]; then
            while IFS= read -r json_url; do
                [ -z "$json_url" ] && continue
                # Send XML to JSON endpoint
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                    -X POST -H "Content-Type: application/xml" \
                    -d '<?xml version="1.0"?><test>injection</test>' \
                    "$json_url" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|201)$"; then
                    echo "JSON_ACCEPTS_XML: $json_url | XML accepted on JSON endpoint" >> "$content_type_vulns"
                    write_finding "{\"type\":\"json_accepts_xml\",\"url\":\"$json_url\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$ct_dir/findings.json" || true
                fi
            done < "$ct_dir/_json_endpoints.txt"
        fi
    fi

    # ------------------------------------------------------------------
    # 6. Summary count
    # ------------------------------------------------------------------
    local total_vulns
    total_vulns=$(( $(wc -l < "$content_type_vulns" 2>/dev/null || echo 0) \
                 + $(wc -l < "$response_splitting" 2>/dev/null || echo 0) ))
    log "INFO" "Content-Type confusion testing complete: $total_vulns issues found"

    py_log "INFO" "content_type_confusion_phase complete" --phase "content_type_confusion" --target "$domain" --extra "{\"vulns\":$total_vulns}" || true
    echo "$total_vulns" > "$ct_dir/count.txt"
}

export -f content_type_confusion_phase
