#!/usr/bin/env bash
# Load Balancer / Reverse-Proxy Misconfiguration Detection
# Detects header leakage, backend routing, and LB config issues

load_balancer_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "load_balancer_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/load_balancer"
    mkdir -p "$phase_dir"

    log "INFO" "Starting load_balancer_phase for $domain"

    local lb_vulns="$phase_dir/lb_vulns.txt"
    local lb_config="$phase_dir/lb_config.txt"
    local count=0

    # --- Detect load balancer via response headers ---
    log "INFO" "Detecting load balancer type via headers..."
    local headers_file="$phase_dir/response_headers.txt"
    curl -sI -m 10 "http://$domain" > "$headers_file" 2>/dev/null || true
    curl -sI -m 10 "https://$domain" >> "$headers_file" 2>/dev/null || true

    # --- Check for common LB header leakage ---
    if grep -qiE "x-forwarded-host|x-real-ip|x-forwarded-for|x-original-forwarded-for" "$headers_file" 2>/dev/null; then
        echo "[VULN] Header leakage detected - internal IP/Host headers exposed" >> "$lb_vulns"
        grep -iE "x-forwarded-host|x-real-ip|x-forwarded-for|x-original-forwarded-for" "$headers_file" >> "$lb_vulns" 2>/dev/null
        ((count++)) || true
    fi

    # --- Check for Server header revealing LB software ---
    if grep -qiE "server:.*nginx|server:.*apache|server:.*cloudflare|server:.*awselb|server:.*haproxy|server:.*bigip|server:.*f5" "$headers_file" 2>/dev/null; then
        echo "[INFO] Server header reveals software:" >> "$lb_config"
        grep -i "^server:" "$headers_file" >> "$lb_config" 2>/dev/null
    fi

    # --- Check for Set-Cookie backend leakage ---
    if grep -qiE "x-backend|backend-server|x-upstream|x-cdn" "$headers_file" 2>/dev/null; then
        echo "[VULN] Backend routing information leaked via headers" >> "$lb_vulns"
        grep -iE "x-backend|backend-server|x-upstream|x-cdn" "$headers_file" >> "$lb_vulns" 2>/dev/null
        ((count++)) || true
    fi

    # --- Probe for IP-based virtual hosting bypass ---
    local ip_list="$phase_dir/resolved_ips.txt"
    dig +short "$domain" A 2>/dev/null > "$ip_list" || true
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        local ip_response
        ip_response=$(curl -sI -m 5 -H "Host: $domain" "http://$ip" 2>/dev/null) || true
        if [[ -n "$ip_response" ]]; then
            local code
            code=$(echo "$ip_response" | head -1 | awk '{print $2}')
            if [[ "$code" == "200" ]] || [[ "$code" == "301" ]] || [[ "$code" == "302" ]]; then
                echo "[VULN] Direct IP access bypasses LB: $ip (HTTP $code)" >> "$lb_vulns"
                ((count++)) || true
            fi
        fi
    done < "$ip_list"

    # --- Test HTTP method routing inconsistencies ---
    if tool_available "curl"; then
        for method in GET POST PUT DELETE OPTIONS TRACE; do
            local method_code
            method_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -X "$method" "https://$domain/" 2>/dev/null) || true
            if [[ "$method_code" != "000" ]]; then
                echo "[CONFIG] $method -> HTTP $method_code" >> "$lb_config"
            fi
        done
    fi

    # --- Check for HSTS and security headers on LB ---
    if ! grep -qi "strict-transport-security" "$headers_file" 2>/dev/null; then
        echo "[VULN] HSTS header missing - potential LB downgrade attack" >> "$lb_vulns"
        ((count++)) || true
    fi

    # --- Write structured findings ---
    if [[ -f "$lb_vulns" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "load_balancer" "" "" ""
        done < "$lb_vulns"
    fi

    if [[ -f "$lb_config" ]]; then
        while IFS= read -r config_line; do
            write_asset "$phase_dir" "$domain" "load_balancer" "$config_line" "" ""
        done < "$lb_config"
    fi

    # --- Write count ---
    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "load_balancer_phase" "domain=$domain findings=$count"

    log "INFO" "load_balancer_phase complete: $count findings"
    return 0
}

load_balancer_phase "$@"
