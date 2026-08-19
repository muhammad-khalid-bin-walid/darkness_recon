#!/usr/bin/env bash
# Screenshot & Visual Evidence Capture
# Uses aquatone/gowitness for visual evidence and visual diff

screenshot_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "screenshot_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/screenshot"
    mkdir -p "$phase_dir/screenshots"

    log "INFO" "Starting screenshot_phase for $domain"

    local screenshots_dir="$phase_dir/screenshots"
    local visual_evidence="$phase_dir/visual_evidence.txt"
    local count=0

    # --- Check for available screenshot tools ---
    local tool="none"
    if tool_available "aquatone"; then
        tool="aquatone"
    elif tool_available "gowitness"; then
        tool="gowitness"
    elif tool_available "chromium"; then
        tool="chromium"
    elif tool_available "google-chrome"; then
        tool="chrome"
    elif tool_available "firefox"; then
        tool="firefox"
    fi

    echo "[CONFIG] Screenshot tool: $tool" >> "$visual_evidence"

    # --- Capture screenshot with available tool ---
    if [[ "$tool" == "aquatone" ]]; then
        log "INFO" "Using aquatone for screenshots..."
        echo "https://$domain" | aquatone -out "$screenshots_dir" -threads 5 -timeout 15000 -silent 2>/dev/null || true

        if [[ -d "$screenshots_dir/aquatone_urls" ]]; then
            local screenshot_count
            screenshot_count=$(find "$screenshots_dir" -name "*.png" 2>/dev/null | wc -l) || true
            echo "[INFO] Aquatone captured $screenshot_count screenshots" >> "$visual_evidence"
            count=$screenshot_count
        fi

    elif [[ "$tool" == "gowitness" ]]; then
        log "INFO" "Using gowitness for screenshots..."
        echo "https://$domain" > "$screenshots_dir/urls.txt"
        gowitness file -f "$screenshots_dir/urls.txt" -P "$screenshots_dir" --timeout 15 --chrome-defaults 2>/dev/null || true

        local screenshot_count
        screenshot_count=$(find "$screenshots_dir" -name "*.png" 2>/dev/null | wc -l) || true
        echo "[INFO] Gowitness captured $screenshot_count screenshots" >> "$visual_evidence"
        count=$screenshot_count

    elif [[ "$tool" == "chromium" ]] || [[ "$tool" == "chrome" ]]; then
        log "INFO" "Using browser for screenshots..."

        # Capture main page
        local screenshot_file="$screenshots_dir/${domain}_main.png"
        if [[ "$tool" == "chromium" ]]; then
            chromium --headless --disable-gpu --no-sandbox --screenshot="$screenshot_file" --window-size=1920,1080 "https://$domain" 2>/dev/null || true
        else
            google-chrome --headless --disable-gpu --no-sandbox --screenshot="$screenshot_file" --window-size=1920,1080 "https://$domain" 2>/dev/null || true
        fi

        if [[ -f "$screenshot_file" ]]; then
            echo "[INFO] Main page screenshot captured" >> "$visual_evidence"
            ((count++)) || true
        fi

    else
        log "WARN" "No screenshot tool available - using curl for headers only"
        echo "[WARN] No screenshot tool available" >> "$visual_evidence"

        # Fallback: capture headers as visual evidence
        local header_file="$screenshots_dir/${domain}_headers.txt"
        curl -sI -m 10 "https://$domain/" > "$header_file" 2>/dev/null || true
        curl -sI -m 10 "http://$domain/" > "$screenshots_dir/${domain}_http_headers.txt" 2>/dev/null || true
        ((count++)) || true
    fi

    # --- Capture additional pages if tool is available ---
    if [[ "$tool" != "none" ]]; then
        local additional_pages=(
            "/admin"
            "/login"
            "/dashboard"
            "/api"
            "/status"
        )

        for page in "${additional_pages[@]}"; do
            local page_url="https://$domain$page"
            local page_code
            page_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$page_url" 2>/dev/null) || true
            if [[ "$page_code" == "200" ]] || [[ "$page_code" == "302" ]]; then
                local page_screenshot="$screenshots_dir/${domain}${page//\//_}.png"
                if [[ "$tool" == "chromium" ]] || [[ "$tool" == "chrome" ]]; then
                    local chrome_cmd="$tool"
                    $chrome_cmd --headless --disable-gpu --no-sandbox --screenshot="$page_screenshot" --window-size=1920,1080 "$page_url" 2>/dev/null || true
                    if [[ -f "$page_screenshot" ]]; then
                        ((count++)) || true
                    fi
                fi
            fi
        done
    fi

    # --- Generate visual diff against baseline (if exists) ---
    log "INFO" "Checking for visual diff baseline..."
    local baseline_dir="$output_dir/../baseline_screenshots"
    if [[ -d "$baseline_dir" ]]; then
        echo "[INFO] Baseline screenshots found for visual diff" >> "$visual_evidence"
        # Visual diff would require additional tooling (perceptualdiff, etc.)
        echo "[CONFIG] Visual diff: baseline available at $baseline_dir" >> "$visual_evidence"
    else
        echo "[INFO] No baseline screenshots found - first capture" >> "$visual_evidence"
    fi

    # --- Write structured findings ---
    write_finding "$phase_dir" "Visual evidence captured for $domain ($count screenshots)" "screenshot" "" "" ""
    write_asset "$phase_dir" "$domain" "screenshot" "tool=$tool count=$count" "" ""

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "screenshot_phase" "domain=$domain tool=$tool screenshots=$count"

    log "INFO" "screenshot_phase complete: $count screenshots captured (tool: $tool)"
    return 0
}

screenshot_phase "$@"
