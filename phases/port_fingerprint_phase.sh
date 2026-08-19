#!/usr/bin/env bash
# Port Fingerprint Phase - Passive port/service discovery and fingerprinting
set -euo pipefail

port_fingerprint_phase() {
    local domain="$1"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/port_fingerprint"
    mkdir -p "$phase_dir"

    log "INFO" "[port_fingerprint] Starting port fingerprinting for $domain"
    py_log "phase_start" "port_fingerprint" "$domain"

    local count=0

    # Resolve domain to IP
    local target_ip
    target_ip=$(dig +short "$domain" A 2>/dev/null | head -1)
    if [[ -z "$target_ip" ]]; then
        log "ERROR" "[port_fingerprint] Could not resolve $domain"
        echo "0" > "$phase_dir/count.txt"
        return 1
    fi
    log "INFO" "[port_fingerprint] Target IP: $target_ip"

    # naabu for port scanning
    if tool_available "naabu"; then
        log "INFO" "[port_fingerprint] Running naabu"
        echo "$target_ip" | naabu -silent -o "$phase_dir/naabu_raw.txt" 2>/dev/null || true
    else
        log "WARN" "[port_fingerprint] naabu not available"
    fi

    # masscan in passive mode (if available and permitted)
    if tool_available "masscan"; then
        log "INFO" "[port_fingerprint] Running masscan (passive)"
        masscan "$target_ip" -p0-65535 --rate=100 -oJ "$phase_dir/masscan_raw.json" 2>/dev/null || true
        # Parse masscan JSON
        python3 -c "
import json
try:
    data = json.load(open('$phase_dir/masscan_raw.json'))
    for item in data:
        for port in item.get('ports', []):
            print(f\"{item.get('ip', '')}:{port.get('port', '')}/{port.get('proto', 'tcp')}\")
except: pass
" > "$phase_dir/masscan_parsed.txt" 2>/dev/null || true
    fi

    # Shodan API query
    if [[ -n "${SHODAN_API_KEY:-}" ]]; then
        log "INFO" "[port_fingerprint] Querying Shodan API"
        curl -s "https://api.shodan.io/shodan/host/${target_ip}?key=${SHODAN_API_KEY}" \
            2>/dev/null > "$phase_dir/shodan_host.json" || true

        # Parse Shodan response for open ports and services
        python3 -c "
import json
try:
    data = json.load(open('$phase_dir/shodan_host.json'))
    for svc in data.get('data', []):
        port = svc.get('port', '')
        transport = svc.get('transport', 'tcp')
        product = svc.get('product', 'unknown')
        version = svc.get('version', '')
        banner = svc.get('data', '')[:200]
        print(f'{port}/{transport}: {product} {version}')
        if banner:
            print(f'  Banner: {banner}')
except: pass
" > "$phase_dir/shodan_services.txt" 2>/dev/null || true
    fi

    # Censys API query
    if [[ -n "${CENSYS_API_ID:-}" && -n "${CENSYS_API_SECRET:-}" ]]; then
        log "INFO" "[port_fingerprint] Querying Censys API"
        curl -s -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
            "https://search.censys.io/api/v2/hosts/${target_ip}" \
            2>/dev/null > "$phase_dir/censys_host.json" || true

        python3 -c "
import json
try:
    data = json.load(open('$phase_dir/censys_host.json'))
    services = data.get('result', {}).get('services', [])
    for svc in services:
        port = svc.get('port', '')
        service = svc.get('service_name', 'unknown')
        banner = svc.get('banner', '')[:200]
        print(f'{port}: {service}')
        if banner:
            print(f'  Banner: {banner}')
except: pass
" > "$phase_dir/censys_services.txt" 2>/dev/null || true
    fi

    # Combine all port data
    cat "$phase_dir/naabu_raw.txt" "$phase_dir/masscan_parsed.txt" 2>/dev/null \
        | grep -oP '\d+\.\d+\.\d+\.\d+:\d+|\d+/tcp|\d+/udp' \
        | sort -u > "$phase_dir/open_ports.txt" || true

    # If we have port lines from Shodan/Censys, add them
    grep -oP '^\d+/' "$phase_dir/shodan_services.txt" 2>/dev/null >> "$phase_dir/open_ports.txt" || true
    grep -oP '^\d+/' "$phase_dir/censys_services.txt" 2>/dev/null >> "$phase_dir/open_ports.txt" || true
    sort -u -o "$phase_dir/open_ports.txt" "$phase_dir/open_ports.txt" 2>/dev/null || true

    # Combine service banners
    cat "$phase_dir/shodan_services.txt" "$phase_dir/censys_services.txt" 2>/dev/null \
        | sort -u > "$phase_dir/service_banners.txt" || true

    count=$(wc -l < "$phase_dir/open_ports.txt" 2>/dev/null || echo 0)
    echo "$count" > "$phase_dir/count.txt"

    write_finding "$domain" "port_fingerprint" "info" \
        "Discovered $count open ports" || true
    write_asset "$domain" "ports" "$phase_dir/open_ports.txt" || true

    log "INFO" "[port_fingerprint] Complete: $count open ports found"
    py_log "phase_complete" "port_fingerprint" "$domain" "count=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    port_fingerprint_phase "${1:?Usage: port_fingerprint_phase <domain>}"
fi
