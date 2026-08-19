#!/bin/bash
# Track 9 - ML/Triage/Future: Program change monitoring, scope updates, new asset detection

program_monitoring_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/program_monitoring"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting program monitoring phase for $domain"
    py_log "INFO" "program_monitoring_phase_start" --phase "program_monitoring" --target "$domain" 2>/dev/null || true

    local monitor_config="$phase_dir/monitor_config.json"
    local change_log="$phase_dir/change_log.txt"
    local count=0

    # Historical asset directory
    local asset_history="$OUTPUT_DIR/$domain/asset_history"
    mkdir -p "$asset_history" 2>/dev/null || true

    log "INFO" "Monitoring program changes and detecting new assets..."

    python3 -c "
import json, os, sys, time
from collections import Counter

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'
asset_history = '$asset_history'

# Collect current assets from all phases
current_assets = {
    'subdomains': set(),
    'endpoints': set(),
    'ip_addresses': set(),
    'technologies': set(),
    'ports': set(),
    'cloud_assets': set(),
    'certificates': set()
}

base = os.path.join(output_dir)
if os.path.isdir(base):
    for entry in os.listdir(base):
        if entry in ('program_monitoring', 'asset_history'):
            continue
        pdir = os.path.join(base, entry)
        if not os.path.isdir(pdir):
            continue
        for f in os.listdir(pdir):
            fpath = os.path.join(pdir, f)
            if f.endswith('.json'):
                try:
                    with open(fpath) as fh:
                        data = json.load(fh)
                        items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
                        for item in items:
                            if isinstance(item, dict):
                                # Extract subdomains
                                val = item.get('subdomain', item.get('host', item.get('domain', '')))
                                if val and domain in str(val):
                                    current_assets['subdomains'].add(str(val))
                                # Extract URLs/endpoints
                                url = item.get('url', item.get('endpoint', item.get('target', '')))
                                if url:
                                    current_assets['endpoints'].add(str(url)[:200])
                                # Extract IPs
                                ip = item.get('ip', item.get('address', item.get('ip_address', '')))
                                if ip:
                                    current_assets['ip_addresses'].add(str(ip))
                                # Extract technologies
                                tech = item.get('technology', item.get('tech', item.get('software', '')))
                                if tech:
                                    current_assets['technologies'].add(str(tech))
                                # Extract ports
                                port = item.get('port', item.get('service_port', ''))
                                if port:
                                    current_assets['ports'].add(str(port))
                                # Extract cloud assets
                                if entry in ('cloud', 'cloud_asset', 'cloud_acl', 'cloud_iam'):
                                    cloud_val = item.get('url', item.get('resource', item.get('bucket', '')))
                                    if cloud_val:
                                        current_assets['cloud_assets'].add(str(cloud_val)[:200])
                except:
                    pass
            elif f.endswith('.txt'):
                try:
                    with open(fpath) as fh:
                        for line in fh:
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            if entry in ('subdomains', 'live'):
                                current_assets['subdomains'].add(line)
                            elif entry == 'ports':
                                current_assets['ports'].add(line)
                            elif entry in ('dns', 'dns_ssl_whois'):
                                current_assets['ip_addresses'].add(line)
                except:
                    pass

# Load previous asset snapshot
prev_assets = {
    'subdomains': set(),
    'endpoints': set(),
    'ip_addresses': set(),
    'technologies': set(),
    'ports': set(),
    'cloud_assets': set(),
    'certificates': set()
}

snapshot_files = sorted([f for f in os.listdir(asset_history) if f.endswith('_snapshot.json')]) if os.path.isdir(asset_history) else []
if snapshot_files:
    try:
        with open(os.path.join(asset_history, snapshot_files[-1])) as fh:
            prev_data = json.load(fh)
            for key in prev_assets:
                prev_assets[key] = set(prev_data.get(key, []))
    except:
        pass

# Save current snapshot
snapshot = {k: list(v) for k, v in current_assets.items()}
snapshot_file = os.path.join(asset_history, f'{int(time.time())}_snapshot.json')
try:
    with open(snapshot_file, 'w') as f:
        json.dump(snapshot, f, indent=2)
except:
    pass

# Detect changes
changes = []
for asset_type in current_assets:
    curr = current_assets[asset_type]
    prev = prev_assets[asset_type]
    new_items = curr - prev
    removed_items = prev - curr

    if new_items:
        changes.append({
            'type': 'new_assets',
            'asset_type': asset_type,
            'count': len(new_items),
            'items': list(new_items)[:50]
        })
    if removed_items:
        changes.append({
            'type': 'removed_assets',
            'asset_type': asset_type,
            'count': len(removed_items),
            'items': list(removed_items)[:50]
        })

# Write config
config = {
    'domain': domain,
    'current_assets': {k: len(v) for k, v in current_assets.items()},
    'total_assets': sum(len(v) for v in current_assets.values()),
    'changes_detected': len(changes),
    'new_assets_total': sum(c['count'] for c in changes if c['type'] == 'new_assets'),
    'removed_assets_total': sum(c['count'] for c in changes if c['type'] == 'removed_assets'),
    'monitoring_config': {
        'snapshot_interval': 'per_scan',
        'alert_on_new_subdomains': True,
        'alert_on_new_endpoints': True,
        'alert_on_scope_change': True
    },
    'changes': changes
}

with open(os.path.join(phase_dir, 'monitor_config.json'), 'w') as f:
    json.dump(config, f, indent=2, default=str)

# Write change log
with open(os.path.join(phase_dir, 'change_log.txt'), 'w') as f:
    f.write(f'Program Change Log - {domain}\n')
    f.write('=' * 50 + '\n\n')
    f.write(f'Current assets: {sum(len(v) for v in current_assets.values())}\n')
    f.write(f'Changes detected: {len(changes)}\n\n')
    f.write('Asset Inventory:\n')
    for asset_type, items in sorted(current_assets.items()):
        f.write(f'  {asset_type}: {len(items)}\n')
    f.write('\nChanges:\n')
    if changes:
        for c in changes:
            f.write(f\"  [{c['type']}] {c['asset_type']}: {c['count']} items\")
            if c['items']:
                f.write(f\" (e.g. {c['items'][0]})\")
            f.write('\n')
    else:
        f.write('  No changes detected (first scan or no previous baseline)\n')

print(len(changes))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$monitor_config" ]; then
        write_finding "{\"type\":\"program_monitoring_complete\",\"target\":\"$domain\",\"changes_detected\":$count,\"method\":\"asset_comparison\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_monitor.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Program monitoring phase complete: $count changes detected for $domain"
    py_log "INFO" "program_monitoring_phase_complete" --phase "program_monitoring" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
