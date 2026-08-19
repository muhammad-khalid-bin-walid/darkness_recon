#!/bin/bash
# Certificate Transparency phase - CT log mining, subdomain discovery, cert expiry

cert_transparency_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local ct_dir="$output_dir/cert_transparency"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$ct_dir"

    log "INFO" "Starting Certificate Transparency mining for $domain"
    py_log "INFO" "cert_transparency_phase" --phase "cert_transparency" --target "$domain"

    # ===== CRT.SH CT LOG MINING =====
    log "INFO" "Querying crt.sh for CT log entries..."
    if tool_available "curl"; then
        curl -s "https://crt.sh/?q=%25.${domain}&output=json" \
            -o "$ct_dir/crtsh_raw.json" 2>/dev/null || true

        if [ -s "$ct_dir/crtsh_raw.json" ]; then
            python3 -c "
import json, sys
try:
    with open('$ct_dir/crtsh_raw.json') as f:
        data = json.load(f)
    subdomains = set()
    entries = []
    for cert in data:
        name = cert.get('name_value', '')
        issuer = cert.get('issuer_name', '')
        not_before = cert.get('not_before', '')
        not_after = cert.get('not_after', '')
        serial = cert.get('serial_number', '')
        crt_id = cert.get('id', '')
        entry = {
            'name': name, 'issuer': issuer,
            'not_before': not_before, 'not_after': not_after,
            'serial': serial, 'crt_id': crt_id
        }
        entries.append(entry)
        for n in name.split('\n'):
            n = n.strip().lower()
            if n:
                subdomains.add(n)

    with open('$ct_dir/crtsh_subdomains.txt', 'w') as f:
        for s in sorted(subdomains):
            f.write(s + '\n')
    with open('$ct_dir/crtsh_entries.json', 'w') as f:
        json.dump(entries, f, indent=2)
    print(f'subdomains={len(subdomains)},certs={len(entries)}')
except Exception as e:
    print(f'error={e}', file=sys.stderr)
" 2>/dev/null || true
        fi
    fi

    # ===== CTFR TOOL (if available) =====
    log "INFO" "Running CTFR for additional CT data..."
    if tool_available "ctfr"; then
        ctfr -d "$domain" -o "$ct_dir/ctfr_subdomains.txt" 2>>"$LOGS_DIR/ctfr.log" || true
    fi

    # ===== CENSYS CT LOGS =====
    log "INFO" "Querying Censys for certificate data..."
    if tool_available "curl" && [ -n "${CENSYS_API_ID:-}" ] && [ -n "${CENSYS_API_SECRET:-}" ]; then
        curl -s -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
            "https://search.censys.io/api/v2/certificates/search?q=parsed.subject.common_name:$domain&per_page=100" \
            -o "$ct_dir/censys_certs.json" 2>/dev/null || true

        if [ -s "$ct_dir/censys_certs.json" ]; then
            python3 -c "
import json, sys
try:
    with open('$ct_dir/censys_certs.json') as f:
        data = json.load(f)
    hits = data.get('result', {}).get('hits', [])
    subdomains = set()
    certs = []
    for hit in hits:
        names = hit.get('parsed', {}).get('subject', {}).get('common_name', [])
        if isinstance(names, str):
            names = [names]
        for n in names:
            subdomains.add(n.lower())
        certs.append({
            'names': names,
            'issuer': hit.get('parsed', {}).get('issuer', {}).get('common_name', ''),
            'not_after': hit.get('parsed', {}).get('validity', {}).get('end', ''),
            'serial': hit.get('parsed', {}).get('serial_number', '')
        })
    with open('$ct_dir/censys_ct_subdomains.txt', 'w') as f:
        for s in sorted(subdomains):
            f.write(s + '\n')
    with open('$ct_dir/censys_certs.json', 'w') as f:
        json.dump(certs, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true
        fi
    fi

    # ===== CONSOLIDATE SUBDOMAINS FROM CT =====
    log "INFO" "Consolidating CT-discovered subdomains..."
    {
        cat "$ct_dir/crtsh_subdomains.txt" 2>/dev/null
        cat "$ct_dir/ctfr_subdomains.txt" 2>/dev/null
        cat "$ct_dir/censys_ct_subdomains.txt" 2>/dev/null
    } | sort -u > "$ct_dir/ct_subdomains.txt" 2>/dev/null || true

    # ===== CERTIFICATE EXPIRY TRACKING =====
    log "INFO" "Tracking certificate expiry dates..."
    python3 -c "
import json, os, sys
from datetime import datetime

ct_dir = '$ct_dir'
expiry_entries = []
seen = set()

# From crt.sh entries
crtsh_file = os.path.join(ct_dir, 'crtsh_entries.json')
if os.path.exists(crtsh_file):
    with open(crtsh_file) as f:
        entries = json.load(f)
    for e in entries:
        not_after = e.get('not_after', '')
        name = e.get('name', '')
        key = f'{name}:{not_after}'
        if key not in seen and not_after:
            seen.add(key)
            try:
                exp_date = datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%SZ')
                days_left = (exp_date - datetime.utcnow()).days
                status = 'expired' if days_left < 0 else ('expiring_soon' if days_left < 30 else 'valid')
                expiry_entries.append({
                    'name': name, 'not_after': not_after,
                    'days_left': days_left, 'status': status,
                    'issuer': e.get('issuer', '')
                })
            except ValueError:
                pass

with open(os.path.join(ct_dir, 'cert_expiry.json'), 'w') as f:
    json.dump(expiry_entries, f, indent=2)

with open(os.path.join(ct_dir, 'cert_expiry.txt'), 'w') as f:
    f.write('=== CERTIFICATE EXPIRY TRACKING ===\n\n')
    for e in sorted(expiry_entries, key=lambda x: x.get('days_left', 0)):
        f.write(f\"{e['name']}: expires {e['not_after']} ({e['days_left']} days) [{e['status']}]\n\")
" 2>/dev/null || true

    # ===== SUBDOMAIN DISCOVERY FINDINGS =====
    local ct_sub_count
    ct_sub_count=$(wc -l < "$ct_dir/ct_subdomains.txt" 2>/dev/null || echo 0)

    if [ "$ct_sub_count" -gt 0 ]; then
        write_finding "{\"type\":\"ct_subdomains\",\"target\":\"$domain\",\"count\":$ct_sub_count,\"source\":\"crt.sh,censys,ctfr\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$ct_dir/ct_finding.json" || true
    fi

    # ===== EXPIRY FINDINGS =====
    local expired_count
    expired_count=$(grep -c '"expired"' "$ct_dir/cert_expiry.json" 2>/dev/null || echo 0)
    local expiring_count
    expiring_count=$(grep -c '"expiring_soon"' "$ct_dir/cert_expiry.json" 2>/dev/null || echo 0)

    if [ "$expired_count" -gt 0 ] || [ "$expiring_count" -gt 0 ]; then
        write_finding "{\"type\":\"cert_expiry\",\"target\":\"$domain\",\"expired\":$expired_count,\"expiring_soon\":$expiring_count,\"severity\":\"high\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$ct_dir/expiry_finding.json" || true
    fi

    log "INFO" "CT mining complete: $ct_sub_count subdomains, $expired_count expired certs"
    local total_count=$((ct_sub_count + expired_count + expiring_count))
    echo "$total_count" > "$ct_dir/count.txt"
}
