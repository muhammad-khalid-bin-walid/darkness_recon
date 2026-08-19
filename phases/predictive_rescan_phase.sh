#!/bin/bash
# Track 9 - ML/Triage/Future: Predictive re-scan scheduling, vulnerability lifecycle tracking

predictive_rescan_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/predictive_rescan"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting predictive rescan phase for $domain"
    py_log "INFO" "predictive_rescan_phase_start" --phase "predictive_rescan" --target "$domain" 2>/dev/null || true

    local rescan_schedule="$phase_dir/rescan_schedule.json"
    local prediction_model="$phase_dir/prediction_model.txt"
    local count=0

    log "INFO" "Building predictive re-scan schedule..."

    python3 -c "
import json, os, sys, time
from collections import Counter

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'

# Collect current scan findings
all_findings = []
base = os.path.join(output_dir)
if os.path.isdir(base):
    for entry in os.listdir(base):
        if entry in ('predictive_rescan', 'retrospective', 'self_tuning'):
            continue
        pdir = os.path.join(base, entry)
        if not os.path.isdir(pdir):
            continue
        for f in os.listdir(pdir):
            if f.endswith('.json'):
                try:
                    with open(os.path.join(pdir, f)) as fh:
                        data = json.load(fh)
                        items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
                        for item in items:
                            if isinstance(item, dict):
                                item['_source_phase'] = entry
                                all_findings.append(item)
                except:
                    pass

# Vulnerability lifecycle stages
lifecycle_stages = {
    'discovered': {'rescan_days': 7, 'priority': 'high'},
    'confirmed': {'rescan_days': 3, 'priority': 'critical'},
    'remediated': {'rescan_days': 30, 'priority': 'medium'},
    'verified': {'rescan_days': 90, 'priority': 'low'},
    'monitoring': {'rescan_days': 180, 'priority': 'low'}
}

# Severity-based re-scan intervals
severity_intervals = {
    'critical': {'rescan_hours': 24, 'escalation_hours': 4},
    'high': {'rescan_hours': 72, 'escalation_hours': 24},
    'medium': {'rescan_hours': 168, 'escalation_hours': 72},
    'low': {'rescan_hours': 720, 'escalation_hours': 168},
    'info': {'rescan_hours': 2160, 'escalation_hours': 720}
}

# Build rescan schedule
rescan_tasks = []
severity_counts = Counter()
phase_findings = Counter()

for finding in all_findings:
    sev = str(finding.get('severity', finding.get('level', 'info'))).lower()
    severity_counts[sev] += 1
    phase = finding.get('_source_phase', 'unknown')
    phase_findings[phase] += 1

# Create rescan tasks per severity level
for sev in ['critical', 'high', 'medium', 'low', 'info']:
    if severity_counts.get(sev, 0) > 0:
        interval = severity_intervals.get(sev, severity_intervals['info'])
        rescan_tasks.append({
            'severity': sev,
            'finding_count': severity_counts[sev],
            'rescan_interval_hours': interval['rescan_hours'],
            'escalation_interval_hours': interval['escalation_hours'],
            'next_rescan': f\"$(date -u -d '+{interval['rescan_hours']} hours' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)\",
            'auto_escalate': sev in ['critical', 'high']
        })

# Phase-specific rescan recommendations
phase_rescan = []
for phase, cnt in phase_findings.items():
    if cnt > 0:
        base_interval = 168  # 1 week default
        if any(s.get('severity') in ['critical', 'high'] for s in rescan_tasks):
            base_interval = 48
        phase_rescan.append({
            'phase': phase,
            'findings': cnt,
            'recommended_interval_hours': base_interval,
            'next_scheduled': f\"$(date -u -d '+{base_interval} hours' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)\"
        })

# Build config
config = {
    'domain': domain,
    'total_findings': len(all_findings),
    'severity_distribution': dict(severity_counts),
    'rescan_tasks': rescan_tasks,
    'phase_rescan_schedule': phase_rescan,
    'global_config': {
        'min_interval_hours': 24,
        'max_interval_hours': 2160,
        'auto_escalation_enabled': True,
        'notification_hours_before': 1
    },
    'lifecycle_stages': list(lifecycle_stages.keys())
}

with open(os.path.join(phase_dir, 'rescan_schedule.json'), 'w') as f:
    json.dump(config, f, indent=2, default=str)

# Write prediction model
with open(os.path.join(phase_dir, 'prediction_model.txt'), 'w') as f:
    f.write(f'Predictive Re-scan Model for {domain}\n')
    f.write('=' * 50 + '\n\n')
    f.write(f'Total findings: {len(all_findings)}\n')
    f.write(f'Severity distribution:\n')
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        f.write(f'  {sev.upper():10s}: {severity_counts.get(sev, 0)}\n')
    f.write(f'\nRe-scan Schedule:\n')
    for task in rescan_tasks:
        f.write(f\"  [{task['severity'].upper():8s}] {task['finding_count']} findings - rescan every {task['rescan_interval_hours']}h\")
        if task['auto_escalate']:
            f.write(f\" (escalate if unresolved within {task['escalation_interval_hours']}h)\")
        f.write('\n')
    f.write(f'\nPhase-specific Schedule:\n')
    for pr in phase_rescan:
        f.write(f\"  {pr['phase']}: {pr['findings']} findings - every {pr['recommended_interval_hours']}h\n\")
    f.write(f'\nLifecycle Stages:\n')
    for stage, params in lifecycle_stages.items():
        f.write(f\"  {stage}: rescan every {params['rescan_days']}d (priority: {params['priority']})\n\")

print(len(rescan_tasks) + len(phase_rescan))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$rescan_schedule" ]; then
        write_finding "{\"type\":\"predictive_rescan_complete\",\"target\":\"$domain\",\"rescan_tasks\":$count,\"method\":\"lifecycle_prediction\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_rescan.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Predictive rescan phase complete: $count rescan tasks for $domain"
    py_log "INFO" "predictive_rescan_phase_complete" --phase "predictive_rescan" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
