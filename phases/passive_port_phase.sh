#!/bin/bash
# Passive port discovery phase - Shodan/Censys, historical banners, service versions

passive_port_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local port_dir="$output_dir/passive_ports"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$port_dir"

    log "INFO" "Starting passive port discovery for $domain"
    py_log "INFO" "passive_port_phase" --phase "passive_ports" --target "$domain"

    # ===== SHODAN PASSIVE PORTS =====
    log "INFO" "Querying Shodan for passive port data..."
    if tool_available "curl" && [ -n "${SHODAN_API_KEY:-}" ]; then
        # Domain search
        curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=hostname:$domain" \
            -o "$port_dir/shodan_hosts.json" 2>/dev/null || true

        if [ -s "$port_dir/shodan_hosts.json" ]; then
            python3 -c "
import json, sys
try:
    with open('$port_dir/shodan_hosts.json') as f:
        data = json.load(f)
    ports = set()
    services = []
    for match in data.get('matches', []):
        ip = match.get('ip_str', '')
        port = match.get('port', '')
        transport = match.get('transport', 'tcp')
        product = match.get('product', '')
        version = match.get('version', '')
        banner = match.get('data', '')[:200]
        if ip and port:
            ports.add(f'{ip}:{port}')
            services.append({
                'ip': ip, 'port': port, 'transport': transport,
                'product': product, 'version': version, 'banner_preview': banner
            })
    with open('$port_dir/passive_ports.txt', 'w') as f:
        for p in sorted(ports):
            f.write(p + '\n')
    with open('$port_dir/shodan_services.json', 'w') as f:
        json.dump(services, f, indent=2)
    with open('$port_dir/service_versions.txt', 'w') as f:
        for s in services:
            if s['product']:
                f.write(f\"{s['ip']}:{s['port']} {s['product']} {s['version']}\n\")
except Exception as e:
    print(f'error={e}', file=sys.stderr)
" 2>/dev/null || true
        fi

        # IP-based lookups for known subdomains
        local subdomains_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/subdomains/all_subdomains.txt"
        if [ -f "$subdomains_file" ]; then
            log "INFO" "Running Shodan IP lookups for subdomains..."
            while IFS= read -r sub; do
                [ -z "$sub" ] && continue
                local ips
                ips=$(dig +short "$sub" 2>/dev/null | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
                [ -z "$ips" ] && continue
                curl -s "https://api.shodan.io/shodan/host/$ips?key=$SHODAN_API_KEY" \
                    -o "$port_dir/shodan_${sub}.json" 2>/dev/null || true
            done < <(head -20 "$subdomains_file")
        fi
    elif [ -z "${SHODAN_API_KEY:-}" ]; then
        log "WARN" "SHODAN_API_KEY not set, skipping Shodan queries"
    fi

    # ===== CENSYS PASSIVE PORTS =====
    log "INFO" "Querying Censys for passive port data..."
    if tool_available "curl" && [ -n "${CENSYS_API_ID:-}" ] && [ -n "${CENSYS_API_SECRET:-}" ]; then
        curl -s -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
            "https://search.censys.io/api/v2/hosts/search?q=$domain&per_page=100" \
            -o "$port_dir/censys_results.json" 2>/dev/null || true

        if [ -s "$port_dir/censys_results.json" ]; then
            python3 -c "
import json, sys
try:
    with open('$port_dir/censys_results.json') as f:
        data = json.load(f)
    hits = data.get('result', {}).get('hits', [])
    censys_ports = set()
    for hit in hits:
        ip = hit.get('ip', '')
        for svc in hit.get('services', []):
            port = svc.get('port', '')
            name = svc.get('service_name', '')
            if ip and port:
                censys_ports.add(f'{ip}:{port}')
    with open('$port_dir/censys_ports.txt', 'w') as f:
        for p in sorted(censys_ports):
            f.write(p + '\n')
except Exception as e:
    pass
" 2>/dev/null || true
        fi
    elif [ -z "${CENSYS_API_ID:-}" ]; then
        log "WARN" "CENSYS_API_ID not set, skipping Censys queries"
    fi

    # ===== HISTORICAL BANNER DATA =====
    log "INFO" "Collecting historical banner data..."
    if tool_available "curl"; then
        # Wayback Machine for banner/headers
        curl -s "https://web.archive.org/cdx/search/cdx?url=$domain&output=json&limit=50&fl=timestamp,statuscode,mimetype" \
            -o "$port_dir/wayback_headers.json" 2>/dev/null || true

        # SecurityTrails / VirusTotal passive DNS for port correlation
        if [ -n "${VT_API_KEY:-}" ]; then
            curl -s "https://www.virustotal.com/api/v3/domains/$domain/resolutions" \
                -H "x-apikey: $VT_API_KEY" 2>/dev/null \
                | jq -r '.data[]?.attributes.ip_address' 2>/dev/null \
                | sort -u > "$port_dir/vt_ips.txt" || true
        fi
    fi

    # ===== CONSOLIDATE PORT DATA =====
    log "INFO" "Consolidating passive port findings..."
    {
        cat "$port_dir/passive_ports.txt" 2>/dev/null
        cat "$port_dir/censys_ports.txt" 2>/dev/null
    } | sort -u > "$port_dir/all_passive_ports.txt" 2>/dev/null || true

    local port_count
    port_count=$(wc -l < "$port_dir/all_passive_ports.txt" 2>/dev/null || echo 0)

    if [ "$port_count" -gt 0 ]; then
        write_finding "{\"type\":\"passive_ports\",\"target\":\"$domain\",\"count\":$port_count,\"sources\":\"shodan,censys\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$port_dir/port_finding.json" || true
    fi

    # ===== SERVICE VERSION FINDINGS =====
    if [ -f "$port_dir/service_versions.txt" ] && [ -s "$port_dir/service_versions.txt" ]; then
        write_finding "{\"type\":\"service_versions\",\"target\":\"$domain\",\"file\":\"service_versions.txt\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$port_dir/version_finding.json" || true
    fi

    log "INFO" "Passive port discovery complete: $port_count unique ports found"
    echo "$port_count" > "$port_dir/count.txt"
}
