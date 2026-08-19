#!/usr/bin/env bash
# Response-Diff Evidence Capture & Anomaly Detection
# Captures baseline responses and detects anomalies via diff comparison

response_diff_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "response_diff_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/response_diff"
    mkdir -p "$phase_dir"

    log "INFO" "Starting response_diff_phase for $domain"

    local response_diffs="$phase_dir/response_diffs.txt"
    local baselines="$phase_dir/baselines.txt"
    local count=0

    # --- Capture baseline responses ---
    log "INFO" "Capturing baseline responses..."

    local test_urls=(
        "https://$domain/"
        "https://$domain/robots.txt"
        "https://$domain/sitemap.xml"
        "https://$domain/.well-known/security.txt"
        "http://$domain/"
    )

    for url in "${test_urls[@]}"; do
        local url_hash
        url_hash=$(echo "$url" | md5sum | awk '{print $1}') || true
        local baseline_file="$phase_dir/baseline_${url_hash}.txt"

        # Capture full response (headers + body)
        local response_file="$phase_dir/response_${url_hash}.txt"
        curl -s -D - -m 10 "$url" > "$response_file" 2>/dev/null || true

        if [[ -s "$response_file" ]]; then
            # Extract key metrics
            local status_code
            status_code=$(head -1 "$response_file" | awk '{print $2}') || true
            local content_length
            content_length=$(grep -i "^content-length:" "$response_file" | awk '{print $2}' | tr -d '\r') || true
            local content_type
            content_type=$(grep -i "^content-type:" "$response_file" | head -1 | awk '{print $2}' | tr -d '\r') || true

            echo "[BASELINE] $url" >> "$baselines"
            echo "  status=$status_code" >> "$baselines"
            echo "  content_length=$content_length" >> "$baselines"
            echo "  content_type=$content_type" >> "$baselines"
            echo "  file=$response_file" >> "$baselines"

            # Store response hash for diff
            local body
            body=$(sed '1,/^[\r]*$/d' "$response_file") || true
            local body_hash
            body_hash=$(echo "$body" | md5sum | awk '{print $1}') || true
            echo "$url $status_code $content_length $body_hash" >> "$phase_dir/baseline_hashes.txt"

            ((count++)) || true
        fi
    done

    # --- Detect anomalies in response patterns ---
    log "INFO" "Detecting response anomalies..."

    local anomaly_count=0

    # Check for inconsistent status codes
    local status_codes
    status_codes=$(awk '{print $2}' "$phase_dir/baseline_hashes.txt" 2>/dev/null | sort | uniq -c | sort -rn) || true
    local unique_statuses
    unique_statuses=$(echo "$status_codes" | wc -l) || true
    if [[ "$unique_statuses" -gt 2 ]]; then
        echo "[ANOMALY] Multiple status codes detected across endpoints:" >> "$response_diffs"
        echo "$status_codes" >> "$response_diffs"
        ((anomaly_count++)) || true
    fi

    # Check for information disclosure in error responses
    local error_paths=(
        "/nonexistent_page_$(date +%s)"
        "/%00"
        "/../etc/passwd"
        "/../../../etc/passwd"
        "/%2e%2e%2fetc/passwd"
    )

    for path in "${error_paths[@]}"; do
        local error_response
        error_response=$(curl -s -m 5 "https://$domain$path" 2>/dev/null) || true
        if echo "$error_response" | grep -qiE "root:x:0:0|stack trace|debug|exception|syntax error|mysql_|ORA-|postgresql"; then
            echo "[ANOMALY] Information disclosure in error response: $path" >> "$response_diffs"
            ((anomaly_count++)) || true
            ((count++)) || true
        fi
    done

    # --- HTTP vs HTTPS comparison ---
    log "INFO" "Comparing HTTP vs HTTPS responses..."
    local http_resp="$phase_dir/http_response.txt"
    local https_resp="$phase_dir/https_response.txt"

    curl -s -D - -m 10 "http://$domain/" > "$http_resp" 2>/dev/null || true
    curl -s -D - -m 10 "https://$domain/" > "$https_resp" 2>/dev/null || true

    if [[ -s "$http_resp" ]] && [[ -s "$https_resp" ]]; then
        local http_hash
        http_hash=$(sed '1,/^[\r]*$/d' "$http_resp" | md5sum | awk '{print $1}') || true
        local https_hash
        https_hash=$(sed '1,/^[\r]*$/d' "$https_resp" | md5sum | awk '{print $1}') || true

        if [[ "$http_hash" == "$https_hash" ]]; then
            echo "[ANOMALY] HTTP and HTTPS serve identical content - no redirect enforced" >> "$response_diffs"
            ((anomaly_count++)) || true
            ((count++)) || true
        else
            echo "[INFO] HTTP and HTTPS serve different content (expected)" >> "$baselines"
        fi
    fi

    # --- Check for WAF/CDN behavioral differences ---
    log "INFO" "Testing WAF behavioral differences..."
    local waf_test_urls=(
        "https://$domain/<script>alert(1)</script>"
        "https://$domain/?id=1' OR '1'='1"
        "https://$domain/?cmd=ls"
    )

    for url in "${waf_test_urls[@]}"; do
        local waf_code
        waf_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$url" 2>/dev/null) || true
        if [[ "$waf_code" == "403" ]] || [[ "$waf_code" == "406" ]] || [[ "$waf_code" == "418" ]]; then
            echo "[INFO] WAF blocking detected for: $url (HTTP $waf_code)" >> "$baselines"
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$response_diffs" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "response_diff" "" "" ""
        done < "$response_diffs"
    fi

    if [[ -f "$baselines" ]]; then
        while IFS= read -r baseline; do
            write_asset "$phase_dir" "$domain" "response_diff" "$baseline" "" ""
        done < "$baselines"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "response_diff_phase" "domain=$domain anomalies=$anomaly_count baselines=$count"

    log "INFO" "response_diff_phase complete: $count baselines, $anomaly_count anomalies"
    return 0
}

response_diff_phase "$@"
