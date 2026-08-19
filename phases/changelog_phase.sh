#!/bin/bash
# Track 9 - ML/Triage/Future: Automated changelog generation, version tracking, release notes

changelog_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/changelog"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting changelog generation phase for $domain"
    py_log "INFO" "changelog_phase_start" --phase "changelog" --target "$domain" 2>/dev/null || true

    local changelog_md="$phase_dir/changelog.md"
    local version_history="$phase_dir/version_history.txt"
    local count=0

    # Historical scans directory
    local history_dir="$OUTPUT_DIR/$domain"
    mkdir -p "$history_dir" 2>/dev/null || true

    log "INFO" "Generating automated changelog from scan history..."

    python3 -c "
import json, os, sys, time
from collections import Counter

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'
history_dir = '$history_dir'

# Find all scan runs
scan_runs = []
if os.path.isdir(history_dir):
    for entry in sorted(os.listdir(history_dir)):
        if entry.startswith('recon_'):
            ts = entry.replace('recon_', '')
            scan_path = os.path.join(history_dir, entry)
            if os.path.isdir(scan_path):
                scan_runs.append({'timestamp': ts, 'path': scan_path})

# Analyze current scan
current_scan = {
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'findings': Counter(),
    'phases': set(),
    'total': 0
}

base = os.path.join(output_dir)
if os.path.isdir(base):
    for entry in os.listdir(base):
        if entry in ('changelog',):
            continue
        pdir = os.path.join(base, entry)
        if not os.path.isdir(pdir):
            continue
        current_scan['phases'].add(entry)
        for f in os.listdir(pdir):
            if f.endswith('.json'):
                try:
                    with open(os.path.join(pdir, f)) as fh:
                        data = json.load(fh)
                        items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
                        for item in items:
                            if isinstance(item, dict):
                                sev = str(item.get('severity', item.get('level', 'info'))).lower()
                                current_scan['findings'][sev] += 1
                                current_scan['total'] += 1
                except:
                    pass

# Analyze previous scans for comparison
prev_scans = []
for scan in scan_runs[:-1]:
    scan_data = {'timestamp': scan['timestamp'], 'findings': Counter(), 'total': 0, 'phases': set()}
    scan_base = scan['path']
    if os.path.isdir(scan_base):
        for entry in os.listdir(scan_base):
            pdir = os.path.join(scan_base, entry)
            if not os.path.isdir(pdir):
                continue
            scan_data['phases'].add(entry)
            for f in os.listdir(pdir):
                if f.endswith('.json'):
                    try:
                        with open(os.path.join(pdir, f)) as fh:
                            data = json.load(fh)
                            items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
                            for item in items:
                                if isinstance(item, dict):
                                    sev = str(item.get('severity', item.get('level', 'info'))).lower()
                                    scan_data['findings'][sev] += 1
                                    scan_data['total'] += 1
                    except:
                        pass
    prev_scans.append(scan_data)

# Generate changelog entries
changelog_entries = []

# Version numbering
scan_number = len(scan_runs)
version = f'v{scan_number}.0.0'

# Compare with previous scan
if prev_scans:
    prev = prev_scans[-1]
    curr_total = current_scan['total']
    prev_total = prev['total']
    diff = curr_total - prev_total

    # Phase changes
    new_phases = current_scan['phases'] - prev.get('phases', set())
    removed_phases = prev.get('phases', set()) - current_scan['phases']

    # Severity changes
    sev_changes = {}
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        c = current_scan['findings'].get(sev, 0)
        p = prev['findings'].get(sev, 0)
        if c != p:
            sev_changes[sev] = {'current': c, 'previous': p, 'change': c - p}

    changelog_entries.append({
        'version': version,
        'date': current_scan['timestamp'],
        'summary': f'Scan #{scan_number} - {\"increase\" if diff > 0 else \"decrease\"} of {abs(diff)} findings',
        'changes': {
            'new_findings': max(diff, 0),
            'resolved_findings': max(-diff, 0),
            'new_phases': list(new_phases),
            'removed_phases': list(removed_phases),
            'severity_changes': sev_changes
        }
    })
else:
    changelog_entries.append({
        'version': version,
        'date': current_scan['timestamp'],
        'summary': f'Initial scan baseline - {current_scan[\"total\"]} findings across {len(current_scan[\"phases\"])} phases',
        'changes': {
            'initial_scan': True,
            'total_findings': current_scan['total'],
            'phases_run': list(current_scan['phases'])
        }
    })

# Write changelog markdown
with open(os.path.join(phase_dir, 'changelog.md'), 'w') as f:
    f.write(f'# Changelog - {domain}\n\n')
    f.write('All notable scan changes are documented here.\n\n')
    for entry in changelog_entries:
        f.write(f\"## [{entry['version']}] - {entry['date']}\n\n\")
        f.write(f\"### Summary\n{entry['summary']}\n\n\")
        changes = entry['changes']
        if changes.get('new_phases'):
            f.write(f\"### Added\n- New phases: {', '.join(changes['new_phases'])}\n\n\")
        if changes.get('removed_phases'):
            f.write(f\"### Removed\n- Phases: {', '.join(changes['removed_phases'])}\n\n\")
        if changes.get('severity_changes'):
            f.write(f\"### Changed\n\")
            for sev, data in changes['severity_changes'].items():
                direction = 'increased' if data['change'] > 0 else 'decreased'
                f.write(f\"- {sev.capitalize()} findings {direction} by {abs(data['change'])} (was {data['previous']}, now {data['current']})\n\")
            f.write('\n')

# Write version history
with open(os.path.join(phase_dir, 'version_history.txt'), 'w') as f:
    f.write(f'Version History - {domain}\n')
    f.write('=' * 50 + '\n\n')
    f.write(f'Total scans: {len(scan_runs)}\n')
    f.write(f'Current version: {version}\n')
    f.write(f'Current findings: {current_scan[\"total\"]}\n\n')
    f.write('Version Log:\n')
    for entry in changelog_entries:
        f.write(f\"  {entry['version']} ({entry['date']}): {entry['summary']}\n\")
    f.write('\nScan Timeline:\n')
    for scan in scan_runs[-10:]:
        f.write(f\"  {scan['timestamp']}\n\")

print(len(changelog_entries))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$changelog_md" ]; then
        write_finding "{\"type\":\"changelog_generated\",\"target\":\"$domain\",\"versions_documented\":$count,\"method\":\"automated_changelog\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_changelog.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Changelog phase complete: $count versions documented for $domain"
    py_log "INFO" "changelog_phase_complete" --phase "changelog" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
