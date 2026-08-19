#!/bin/bash
# Track 9 - ML/Triage/Future: Retrospective analysis of past scans, trend detection, improvement tracking

retrospective_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/retrospective"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting retrospective analysis phase for $domain"
    py_log "INFO" "retrospective_phase_start" --phase "retrospective" --target "$domain" 2>/dev/null || true

    local retrospective_report="$phase_dir/retrospective_report.json"
    local trends_file="$phase_dir/trends.txt"
    local count=0

    # Historical scans directory
    local history_dir="$OUTPUT_DIR/$domain"
    mkdir -p "$history_dir" 2>/dev/null || true

    log "INFO" "Performing retrospective analysis of past scans..."

    python3 -c "
import json, os, sys
from collections import Counter, defaultdict

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'
history_dir = '$history_dir'

# Find all past scan directories for this domain
past_scans = []
if os.path.isdir(history_dir):
    for entry in os.listdir(history_dir):
        if entry.startswith('recon_') and entry != os.path.basename(output_dir):
            scan_path = os.path.join(history_dir, entry)
            if os.path.isdir(scan_path):
                # Parse timestamp from directory name
                ts = entry.replace('recon_', '')
                past_scans.append({'timestamp': ts, 'path': scan_path})

past_scans.sort(key=lambda x: x['timestamp'])

# Analyze current scan
current_findings = Counter()
current_phases = set()
base = os.path.join(output_dir)
if os.path.isdir(base):
    for entry in os.listdir(base):
        if entry == 'retrospective':
            continue
        pdir = os.path.join(base, entry)
        if not os.path.isdir(pdir):
            continue
        current_phases.add(entry)
        for f in os.listdir(pdir):
            if f.endswith('.json'):
                try:
                    with open(os.path.join(pdir, f)) as fh:
                        data = json.load(fh)
                        items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
                        for item in items:
                            if isinstance(item, dict):
                                sev = str(item.get('severity', item.get('level', 'info'))).lower()
                                current_findings[sev] += 1
                except:
                    pass

# Analyze past scans
scan_history = []
for scan in past_scans:
    scan_findings = Counter()
    scan_phases = set()
    scan_base = scan['path']
    if os.path.isdir(scan_base):
        for entry in os.listdir(scan_base):
            pdir = os.path.join(scan_base, entry)
            if not os.path.isdir(pdir):
                continue
            scan_phases.add(entry)
            for f in os.listdir(pdir):
                if f.endswith('.json'):
                    try:
                        with open(os.path.join(pdir, f)) as fh:
                            data = json.load(fh)
                            items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
                            for item in items:
                                if isinstance(item, dict):
                                    sev = str(item.get('severity', item.get('level', 'info'))).lower()
                                    scan_findings[sev] += 1
                    except:
                        pass
    scan_history.append({
        'timestamp': scan['timestamp'],
        'total': sum(scan_findings.values()),
        'severity_dist': dict(scan_findings),
        'phases': list(scan_phases)
    })

# Trend detection
trends = []
if len(scan_history) > 1:
    totals = [s['total'] for s in scan_history]
    if len(totals) >= 2:
        diff = totals[-1] - totals[-2]
        pct = (diff / totals[-2] * 100) if totals[-2] > 0 else 0
        trends.append({
            'metric': 'total_findings',
            'trend': 'increasing' if diff > 0 else 'decreasing' if diff < 0 else 'stable',
            'change': diff,
            'change_pct': round(pct, 1)
        })

    # Severity trends
    for sev in ['critical', 'high', 'medium', 'low']:
        sev_counts = [s['severity_dist'].get(sev, 0) for s in scan_history]
        if len(sev_counts) >= 2:
            diff = sev_counts[-1] - sev_counts[-2]
            if diff != 0:
                trends.append({
                    'metric': f'{sev}_findings',
                    'trend': 'increasing' if diff > 0 else 'decreasing',
                    'change': diff,
                    'current': sev_counts[-1]
                })

    # Phase coverage changes
    if len(scan_history) >= 2:
        prev_phases = set(scan_history[-2].get('phases', []))
        curr_phases = set(scan_history[-1].get('phases', []))
        new_phases = curr_phases - prev_phases
        removed_phases = prev_phases - curr_phases
        if new_phases:
            trends.append({'metric': 'new_phases', 'phases': list(new_phases)})
        if removed_phases:
            trends.append({'metric': 'removed_phases', 'phases': list(removed_phases)})

# Build report
report = {
    'domain': domain,
    'current_scan': {
        'total_findings': sum(current_findings.values()),
        'severity_dist': dict(current_findings),
        'phases_run': list(current_phases)
    },
    'historical_scans': len(scan_history),
    'scan_history': scan_history[-10:] if len(scan_history) > 10 else scan_history,
    'trends': trends,
    'improvement_areas': []
}

# Identify improvement areas
if current_findings.get('critical', 0) > 0:
    report['improvement_areas'].append('Critical findings require immediate remediation')
if not scan_history:
    report['improvement_areas'].append('No historical baseline - establishing baseline now')
else:
    prev_total = scan_history[-1]['total'] if scan_history else 0
    curr_total = sum(current_findings.values())
    if curr_total > prev_total * 1.5:
        report['improvement_areas'].append('Significant increase in findings - review scope changes')

with open(os.path.join(phase_dir, 'retrospective_report.json'), 'w') as f:
    json.dump(report, f, indent=2, default=str)

# Write trends file
with open(os.path.join(phase_dir, 'trends.txt'), 'w') as f:
    f.write(f'Retrospective Analysis - {domain}\n')
    f.write('=' * 50 + '\n\n')
    f.write(f'Current scan findings: {sum(current_findings.values())}\n')
    f.write(f'Historical scans: {len(scan_history)}\n\n')
    f.write('Severity Distribution (Current):\n')
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        f.write(f'  {sev.upper():10s}: {current_findings.get(sev, 0)}\n')
    f.write('\nTrends Detected:\n')
    if trends:
        for t in trends:
            f.write(f\"  - {t['metric']}: {t.get('trend', 'N/A')} (change: {t.get('change', 'N/A')})\n\")
    else:
        f.write('  No trends detected (insufficient historical data)\n')
    f.write('\nImprovement Areas:\n')
    for area in report['improvement_areas']:
        f.write(f'  - {area}\n')

print(len(trends))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$retrospective_report" ]; then
        write_finding "{\"type\":\"retrospective_analysis_complete\",\"target\":\"$domain\",\"trends_detected\":$count,\"method\":\"historical_comparison\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_retrospective.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Retrospective phase complete: $count trends detected for $domain"
    py_log "INFO" "retrospective_phase_complete" --phase "retrospective" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
