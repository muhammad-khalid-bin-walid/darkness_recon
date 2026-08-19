#!/bin/bash
# DNS historical phase - historical DNS records, changes over time, passive DNS databases

dns_historical_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local dns_hist_dir="$output_dir/dns_historical"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$dns_hist_dir"

    log "INFO" "Starting DNS historical mining for $domain"
    py_log "INFO" "dns_historical_phase" --phase "dns_historical" --target "$domain"

    # ===== CURRENT DNS SNAPSHOT =====
    log "INFO" "Capturing current DNS snapshot..."
    if command -v dig >/dev/null 2>&1; then
        local record_types=("A" "AAAA" "MX" "TXT" "NS" "CNAME" "SOA" "SRV" "CAA" "PTR")
        for rtype in "${record_types[@]}"; do
            dig +short "$rtype" "$domain" 2>/dev/null > "$dns_hist_dir/current_${rtype}.txt" || true
        done

        # Record current state for comparison
        {
            echo "=== CURRENT DNS STATE FOR $domain ==="
            for rtype in "${record_types[@]}"; do
                echo "--- $rtype ---"
                cat "$dns_hist_dir/current_${rtype}.txt" 2>/dev/null || echo "None"
            done
        } > "$dns_hist_dir/dns_current_snapshot.txt" 2>/dev/null || true
    fi

    # ===== SECURITYTRAILS DNS HISTORY =====
    log "INFO" "Querying SecurityTrails for DNS history..."
    if tool_available "curl" && [ -n "${SECURITYTRAILS_API_KEY:-}" ]; then
        curl -s "https://api.securitytrails.com/v1/domain/$domain/history/a" \
            -H "apikey: $SECURITYTRAILS_API_KEY" \
            -H "Accept: application/json" \
            -o "$dns_hist_dir/st_history_a.json" 2>/dev/null || true

        curl -s "https://api.securitytrails.com/v1/domain/$domain/history/mx" \
            -H "apikey: $SECURITYTRAILS_API_KEY" \
            -H "Accept: application/json" \
            -o "$dns_hist_dir/st_history_mx.json" 2>/dev/null || true

        curl -s "https://api.securitytrails.com/v1/domain/$domain/history/ns" \
            -H "apikey: $SECURITYTRAILS_API_KEY" \
            -H "Accept: application/json" \
            -o "$dns_hist_dir/st_history_ns.json" 2>/dev/null || true

        python3 -c "
import json, os, sys
records = []
for f in os.listdir('$dns_hist_dir'):
    if f.startswith('st_history_') and f.endswith('.json'):
        fpath = os.path.join('$dns_hist_dir', f)
        try:
            with open(fpath) as fh:
                data = json.load(fh)
                for rec in data.get('records', []):
                    records.append({
                        'type': f.replace('st_history_', '').replace('.json', ''),
                        'value': rec.get('value', ''),
                        'first_seen': rec.get('first_seen', ''),
                        'last_seen': rec.get('last_seen', ''),
                    })
        except:
            pass
with open('$dns_hist_dir/securitytrails_history.json', 'w') as f:
    json.dump(records, f, indent=2)
" 2>/dev/null || true
    elif [ -z "${SECURITYTRAILS_API_KEY:-}" ]; then
        log "WARN" "SECURITYTRAILS_API_KEY not set"
    fi

    # ===== PASSIVE DNS DATABASES =====
    log "INFO" "Querying passive DNS databases..."
    if tool_available "curl"; then
        # VirusTotal passive DNS
        if [ -n "${VT_API_KEY:-}" ]; then
            curl -s "https://www.virustotal.com/api/v3/domains/$domain/resolutions" \
                -H "x-apikey: $VT_API_KEY" 2>/dev/null \
                -o "$dns_hist_dir/vt_resolutions.json" 2>/dev/null || true

            python3 -c "
import json, sys
try:
    with open('$dns_hist_dir/vt_resolutions.json') as f:
        data = json.load(f)
    resolutions = []
    for item in data.get('data', []):
        attr = item.get('attributes', {})
        resolutions.append({
            'ip': attr.get('ip_address', ''),
            'date': attr.get('date', ''),
        })
    with open('$dns_hist_dir/vt_passive_dns.json', 'w') as f:
        json.dump(resolutions, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true
        fi

        # ThreatCrowd passive DNS
        curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" \
            -o "$dns_hist_dir/threatcrowd.json" 2>/dev/null || true
    fi

    # ===== DNS CHANGES OVER TIME =====
    log "INFO" "Analyzing DNS changes over time..."
    python3 -c "
import json, os, sys
from collections import defaultdict

dns_dir = '$dns_hist_dir'
changes = defaultdict(list)

# Parse SecurityTrails history
st_file = os.path.join(dns_dir, 'securitytrails_history.json')
if os.path.exists(st_file):
    with open(st_file) as f:
        records = json.load(f)
    for rec in records:
        rec_type = rec.get('type', 'unknown')
        changes[rec_type].append({
            'value': rec.get('value', ''),
            'first_seen': rec.get('first_seen', ''),
            'last_seen': rec.get('last_seen', '')
        })

# Parse VT passive DNS
vt_file = os.path.join(dns_dir, 'vt_passive_dns.json')
if os.path.exists(vt_file):
    with open(vt_file) as f:
        resolutions = json.load(f)
    for res in resolutions:
        if res.get('ip'):
            changes['A'].append({
                'value': res['ip'],
                'date': res.get('date', '')
            })

# Identify changes
dns_changes = {}
for rtype, entries in changes.items():
    unique_values = set(e.get('value', '') for e in entries)
    dns_changes[rtype] = {
        'unique_values': len(unique_values),
        'total_records': len(entries),
        'values': list(unique_values)[:50],
        'entries': entries[:100]
    }

with open(os.path.join(dns_dir, 'dns_changes.json'), 'w') as f:
    json.dump(dns_changes, f, indent=2)

# Write human-readable change summary
with open(os.path.join(dns_dir, 'dns_changes.txt'), 'w') as f:
    f.write('=== DNS CHANGE ANALYSIS ===\n\n')
    for rtype, info in dns_changes.items():
        f.write(f'--- {rtype} Records ---\n')
        f.write(f'Unique values: {info[\"unique_values\"]}\n')
        f.write(f'Total records: {info[\"total_records\"]}\n')
        for v in info['values']:
            f.write(f'  {v}\n')
        f.write('\n')
" 2>/dev/null || true

    # ===== CROSS-REFERENCE AND VALIDATE =====
    log "INFO" "Cross-referencing historical DNS findings..."
    {
        echo "=== DNS HISTORICAL REPORT FOR $domain ==="
        echo ""
        echo "--- Current DNS Snapshot ---"
        cat "$dns_hist_dir/dns_current_snapshot.txt" 2>/dev/null || echo "N/A"
        echo ""
        echo "--- DNS Changes ---"
        cat "$dns_hist_dir/dns_changes.txt" 2>/dev/null || echo "No changes detected"
    } > "$dns_hist_dir/dns_history.txt" 2>/dev/null || true

    local total_count
    total_count=$(find "$dns_hist_dir" -type f 2>/dev/null | wc -l)
    log "INFO" "DNS historical mining complete: $total_count result files"
    echo "$total_count" > "$dns_hist_dir/count.txt"
}
