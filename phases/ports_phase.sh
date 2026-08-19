#!/bin/bash
# Port scanning phase

ports_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local ports_dir="$output_dir/ports"
    local live_file="$output_dir/live/live_subdomains.txt"

    mkdir -p "$ports_dir"

    log "INFO" "Starting port scanning for $domain"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, skipping port scanning"
        return 1
    fi

    if tool_available "nmap"; then
        log "INFO" "Running nmap top 1000 ports..."
        nmap -sV -T4 --top-ports 1000 -iL "$live_file" \
            -oN "$ports_dir/portscan_results.txt" 2>>"$LOGS_DIR/nmap.log" || true
    fi

    if tool_available "masscan"; then
        log "INFO" "Running masscan for fast port scanning..."
        masscan -iL "$live_file" -p1-65535 --rate=1000 \
            -oG "$ports_dir/masscan_results.txt" 2>>"$LOGS_DIR/masscan.log" || true
    fi

    if tool_available "naabu"; then
        log "INFO" "Running naabu for port scanning..."
        naabu -l "$live_file" -top-ports 1000 -timeout 10 \
            -o "$ports_dir/naabu_results.txt" 2>>"$LOGS_DIR/naabu.log" || true
    fi

    if [ -f "$ports_dir/portscan_results.txt" ]; then
        grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$ports_dir/portscan_results.txt" 2>/dev/null | sort -u > "$ports_dir/ips.txt" 2>/dev/null || true
    fi

    local port_count
    port_count=$(wc -l < "$ports_dir/portscan_results.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "Port scanning complete: $port_count results" "ports" "$domain"

    # Write assets for discovered IPs
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        write_asset "{\"type\":\"ip_address\",\"value\":\"$ip\",\"source\":\"port_scan\",\"phase\":\"ports\"}" \
            "$ports_dir/assets.jsonl" 2>/dev/null || true
    done < "$ports_dir/ips.txt" 2>/dev/null

    # Write findings for open ports
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if echo "$line" | grep -qE "open"; then
            local port=$(echo "$line" | grep -oE '[0-9]+/open' | cut -d'/' -f1)
            local service=$(echo "$line" | grep -oE 'open\s+\S+' | awk '{print $2}')
            local ip=$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
            
            if [ -n "$port" ] && [ -n "$ip" ]; then
                write_finding "{\"type\":\"open_port\",\"severity\":\"info\",\"ip\":\"$ip\",\"port\":$port,\"service\":\"${service:-unknown}\",\"phase\":\"ports\"}" \
                    "$ports_dir/findings.jsonl" 2>/dev/null || true
            fi
        fi
    done < "$ports_dir/portscan_results.txt" 2>/dev/null

    echo "$port_count" > "$ports_dir/count.txt"

    py_log "INFO" "ports_phase" "Completed for $domain"
}