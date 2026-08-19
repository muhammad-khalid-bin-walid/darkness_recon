#!/bin/bash
# Track 16 - Secrets Deep | Phase 245: API Key Detection Across Codebases
# Key format analysis, service identification

secrets_api_key_detect_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "secrets_api_key_detect_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/secrets_api_key_detect"
    mkdir -p "$phase_dir"

    log "INFO" "Starting secrets_api_key_detect_phase for $domain"

    local detection_file="$phase_dir/api_key_detections.txt"
    local service_file="$phase_dir/key_services.txt"
    local count=0

    # --- Service-specific API key patterns ---
    declare -A KEY_PATTERNS=(
        ["AWS Access Key"]="AKIA[0-9A-Z]{16}"
        ["AWS Secret Key"]="[0-9a-zA-Z/+]{40}"
        ["GitHub Token (ghp)"]="ghp_[a-zA-Z0-9]{36}"
        ["GitHub OAuth"]="gho_[a-zA-Z0-9]{36}"
        ["GitHub App Token"]="(ghu|ghs)_[a-zA-Z0-9]{36}"
        ["GitLab Token"]="glpat-[a-zA-Z0-9\-_]{20,}"
        ["Slack Bot Token"]="xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}"
        ["Slack User Token"]="xoxp-[0-9]{11}-[0-9]{11}-[0-9]{12}-[a-z0-9]{32}"
        ["Slack Webhook"]="https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"
        ["Google API Key"]="AIza[0-9A-Za-z_-]{35}"
        ["Google OAuth ID"]="[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com"
        ["Stripe Key (Live)"]="sk_live_[0-9a-zA-Z]{24,}"
        ["Stripe Key (Test)"]="sk_test_[0-9a-zA-Z]{24,}"
        ["Stripe Publishable"]="pk_(live|test)_[0-9a-zA-Z]{24,}"
        ["Twilio Account SID"]="AC[0-9a-f]{32}"
        ["Twilio API Key"]="SK[0-9a-fA-F]{32}"
        ["SendGrid Key"]="SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"
        ["Mailgun Key"]="key-[0-9a-zA-Z]{32}"
        ["Heroku API Key"]="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        ["Telegram Bot Token"]="[0-9]{9}:[a-zA-Z0-9_-]{35}"
        ["Square Access Token"]="sq0atp-[0-9A-Za-z_-]{22}"
        ["Square OAuth Secret"]="sq0csp-[0-9A-Za-z_-]{43}"
        ["npm Token"]="npm_[a-zA-Z0-9]{36}"
        ["PyPI Token"]="pypi-[a-zA-Z0-9]{16,}"
        ["Atlassian Token"]="ATATT[a-zA-Z0-9_-]{30,}"
        ["Shopify Token"]="shpat_[a-fA-F0-9]{32}"
        ["GitLab PAT"]="glpat-[a-zA-Z0-9\-_]{20,}"
    )

    # --- Scan web content for API key patterns ---
    log "INFO" "Scanning web content for API key patterns..."
    local crawl_dir="$output_dir/crawl"
    if [[ -d "$crawl_dir" ]]; then
        for f in "$crawl_dir"/*.txt; do
            [[ -f "$f" ]] || continue
            for service in "${!KEY_PATTERNS[@]}"; do
                local pattern="${KEY_PATTERNS[$service]}"
                grep -oE "$pattern" "$f" 2>/dev/null | while IFS= read -r match; do
                    echo "[API_KEY] service=$service key=$match source=$(basename "$f")" >> "$detection_file"
                    echo "$service|$match|$(basename "$f")" >> "$service_file"
                    ((count++)) || true
                done
            done
        done
    fi

    # --- Scan JavaScript files for key exposure ---
    log "INFO" "Scanning JavaScript for hardcoded API keys..."
    local js_dir="$output_dir/js_analysis"
    if [[ -d "$js_dir" ]]; then
        while IFS= read -r -d '' jsfile; do
            for service in "${!KEY_PATTERNS[@]}"; do
                local pattern="${KEY_PATTERNS[$service]}"
                grep -oE "(['\"]?)(${pattern})" "$jsfile" 2>/dev/null | while IFS= read -r match; do
                    echo "[JS_API_KEY] service=$service key=$match source=$(basename "$jsfile")" >> "$detection_file"
                    ((count++)) || true
                done
            done
        done < <(find "$js_dir" -name '*.js' -o -name '*.ts' -o -name '*.jsx' -o -name '*.tsx' 2>/dev/null | head -100 | tr '\n' '\0')
    fi

    # --- Scan response headers for leaked keys ---
    log "INFO" "Checking response headers for key leakage..."
    local endpoints_file="$output_dir/crawl/endpoints.txt"
    if [[ -f "$endpoints_file" ]]; then
        head -50 "$endpoints_file" | while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            local headers
            headers=$(curl -sI -m 5 "$url" 2>/dev/null) || true
            for service in "${!KEY_PATTERNS[@]}"; do
                local pattern="${KEY_PATTERNS[$service]}"
                echo "$headers" | grep -oiE "$pattern" 2>/dev/null | while IFS= read -r match; do
                    echo "[HEADER_KEY] service=$service key=$match url=$url" >> "$detection_file"
                    ((count++)) || true
                done
            done
        done
    fi

    # --- Write structured findings ---
    if [[ -f "$detection_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "api_key_detection" "" "" "" || true
        done < "$detection_file"
    fi

    if [[ -f "$service_file" ]]; then
        while IFS= read -r asset; do
            write_asset "$phase_dir" "$domain" "api_key_service" "$asset" "" "" || true
        done < "$service_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "secrets_api_key_detect_phase" "domain=$domain findings=$count"
    log "INFO" "secrets_api_key_detect_phase complete: $count findings"
    return 0
}

secrets_api_key_detect_phase "$@"
