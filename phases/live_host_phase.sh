#!/bin/bash
# Combined Phase 2: Live Host & Service Detection
# Encompasses: live host detection, httpx, whatweb, nmap, masscan, naabu, port scanning
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

live_host_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local subdomains_file="$output_dir/subdomains/subdomains.txt"
    local live_dir="$output_dir/live"

    mkdir -p "$live_dir"

    log "INFO" "Starting live host detection for $domain"

    # httpx for HTTP/HTTPS live detection
    if tool_available "httpx"; then
        log "INFO" "Running httpx for live host detection..."
        httpx -l "$subdomains_file" -silent -json 2>>"$LOGS_DIR/httpx.log" >> "$live_dir/live_subdomains.json" || true
    fi

    # whatweb for technology fingerprinting on live hosts
    if tool_available "whatweb"; then
        log "INFO" "Running whatweb on live hosts..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            whatweb "$host" 2>>"$LOGS_DIR/whatweb.log" >> "$live_dir/whatweb.txt" || true
        done < <(jq -r '.[].value' "$live_dir/live_subdomains.json" 2>/dev/null | head -50)
    fi

    # nmap port scan on live hosts
    if tool_available "nmap"; then
        log "INFO" "Running nmap port scan..."
        nmap -iL "$subdomains_file" -T4 -p- 2>>"$LOGS_DIR/nmap.log" -oG "$live_dir/nmap.gnmap" || true
    fi

    # naabu for fast port scanning
    if tool_available "naabu"; then
        log "INFO" "Running naabu port scan..."
        naabu -l "$subdomains_file" -silent -port 80,443 2>>"$LOGS_DIR/naabu.log" >> "$live_dir/naabu_results.txt" || true
    fi

    # Correlation: match live hosts with subdomains
    local live_count
    live_count=$(jq 'length' "$live_dir/live_subdomains.json" 2>/dev/null || echo 0)

    phase_log "INFO" "Live host detection complete: $live_count live hosts found" "live_hosts" "$domain"

    # Write assets for live hosts
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        write_asset "{\"type\":\"live_host\",\"value\":\"$host\",\"source\":\"live_detection\",\"phase\":\"live_host_service_detection\"}" \
            "$live_dir/assets.jsonl" 2>/dev/null || true
    done < "$live_dir/live_subdomains.json" 2>/dev/null

    echo "$live_count" > "$live_dir/count.txt"

    py_log "INFO" "live_host_phase" "Completed for $domain"
}