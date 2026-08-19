#!/bin/bash
# Track 9 - ML/Triage/Future: Model drift detection, performance monitoring, retraining triggers

model_drift_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/model_drift"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting model drift detection phase for $domain"
    py_log "INFO" "model_drift_phase_start" --phase "model_drift" --target "$domain" 2>/dev/null || true

    local drift_report="$phase_dir/drift_report.json"
    local model_metrics="$phase_dir/model_metrics.txt"
    local count=0

    # Baseline metrics from previous runs
    local baseline_dir="$OUTPUT_DIR/$domain/history"
    mkdir -p "$baseline_dir" 2>/dev/null || true

    log "INFO" "Analyzing model drift across scan history..."

    python3 -c "
import json, os, sys, time
from collections import Counter, defaultdict

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'
baseline_dir = '$baseline_dir'

# Collect current scan metrics
current_metrics = {
    'severity_distribution': Counter(),
    'phase_findings': Counter(),
    'confidence_scores': [],
    'finding_types': Counter()
}

base = os.path.join(output_dir)
if os.path.isdir(base):
    for entry in os.listdir(base):
        if entry in ('model_drift',):
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
                                sev = str(item.get('severity', item.get('level', 'info'))).lower()
                                current_metrics['severity_distribution'][sev] += 1
                                current_metrics['phase_findings'][entry] += 1
                                conf = item.get('confidence', item.get('score', 0))
                                if isinstance(conf, (int, float)) and conf > 0:
                                    current_metrics['confidence_scores'].append(conf)
                                ftype = item.get('type', item.get('finding', 'unknown'))
                                current_metrics['finding_types'][str(ftype)] += 1
                except:
                    pass

# Load historical baselines
historical = []
if os.path.isdir(baseline_dir):
    for f in sorted(os.listdir(baseline_dir)):
        if f.endswith('_metrics.json'):
            try:
                with open(os.path.join(baseline_dir, f)) as fh:
                    historical.append(json.load(fh))
            except:
                pass

# Save current as baseline
current_baseline = {
    'timestamp': int(time.time()),
    'severity_distribution': dict(current_metrics['severity_distribution']),
    'phase_findings': dict(current_metrics['phase_findings']),
    'total_findings': sum(current_metrics['severity_distribution'].values()),
    'avg_confidence': round(sum(current_metrics['confidence_scores']) / len(current_metrics['confidence_scores']), 3) if current_metrics['confidence_scores'] else 0
}

baseline_file = os.path.join(baseline_dir, f'{int(time.time())}_metrics.json')
try:
    with open(baseline_file, 'w') as f:
        json.dump(current_baseline, f, indent=2)
except:
    pass

# Drift detection
drift_indicators = []
retrain_needed = False

if len(historical) >= 2:
    prev = historical[-1]
    curr = current_baseline

    # Severity distribution drift (KL-divergence approximation)
    all_sevs = set(list(prev.get('severity_distribution', {}).keys()) + list(curr.get('severity_distribution', {}).keys()))
    prev_total = sum(prev.get('severity_distribution', {}).values()) or 1
    curr_total = sum(curr.get('severity_distribution', {}).values()) or 1

    severity_drift = 0
    for s in all_sevs:
        p_prev = prev.get('severity_distribution', {}).get(s, 0) / prev_total
        p_curr = curr.get('severity_distribution', {}).get(s, 0) / curr_total
        if p_prev > 0 and p_curr > 0:
            import math
            severity_drift += p_curr * math.log(p_curr / p_prev)

    if abs(severity_drift) > 0.5:
        drift_indicators.append({
            'type': 'severity_distribution_drift',
            'score': round(severity_drift, 4),
            'threshold': 0.5,
            'severity': 'HIGH'
        })
        retrain_needed = True

    # Confidence score drift
    prev_conf = prev.get('avg_confidence', 0)
    curr_conf = curr.get('avg_confidence', 0)
    conf_drift = abs(curr_conf - prev_conf)
    if conf_drift > 0.2:
        drift_indicators.append({
            'type': 'confidence_score_drift',
            'prev_avg': prev_conf,
            'curr_avg': curr_conf,
            'drift': round(conf_drift, 4),
            'severity': 'MEDIUM'
        })

    # Finding count drift
    prev_count = prev.get('total_findings', 0)
    curr_count = curr.get('total_findings', 0)
    if prev_count > 0:
        count_ratio = curr_count / prev_count
        if count_ratio > 3.0 or count_ratio < 0.25:
            drift_indicators.append({
                'type': 'finding_count_drift',
                'prev_count': prev_count,
                'curr_count': curr_count,
                'ratio': round(count_ratio, 2),
                'severity': 'HIGH'
            })
            retrain_needed = True

# Build report
report = {
    'domain': domain,
    'current_metrics': {
        'total_findings': current_baseline['total_findings'],
        'avg_confidence': current_baseline['avg_confidence'],
        'severity_distribution': current_baseline['severity_distribution'],
        'unique_finding_types': len(current_metrics['finding_types'])
    },
    'historical_runs': len(historical),
    'drift_indicators': drift_indicators,
    'drift_detected': len(drift_indicators) > 0,
    'retrain_recommended': retrain_needed,
    'monitoring_config': {
        'check_interval_scans': 3,
        'severity_drift_threshold': 0.5,
        'confidence_drift_threshold': 0.2,
        'count_ratio_threshold': 3.0
    }
}

with open(os.path.join(phase_dir, 'drift_report.json'), 'w') as f:
    json.dump(report, f, indent=2, default=str)

# Write metrics file
with open(os.path.join(phase_dir, 'model_metrics.txt'), 'w') as f:
    f.write(f'Model Drift Report - {domain}\n')
    f.write('=' * 50 + '\n\n')
    f.write(f'Current scan metrics:\n')
    f.write(f'  Total findings: {current_baseline[\"total_findings\"]}\n')
    f.write(f'  Avg confidence: {current_baseline[\"avg_confidence\"]}\n')
    f.write(f'  Unique finding types: {len(current_metrics[\"finding_types\"])}\n\n')
    f.write(f'Historical runs analyzed: {len(historical)}\n')
    f.write(f'Drift indicators found: {len(drift_indicators)}\n')
    f.write(f'Retrain recommended: {retrain_needed}\n\n')
    if drift_indicators:
        f.write('Drift Details:\n')
        for d in drift_indicators:
            f.write(f\"  [{d['severity']}] {d['type']}: {json.dumps({k:v for k,v in d.items() if k not in ['type','severity']})}\n\")
    else:
        f.write('No significant drift detected.\n')

print(len(drift_indicators))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$drift_report" ]; then
        write_finding "{\"type\":\"model_drift_complete\",\"target\":\"$domain\",\"drift_indicators\":$count,\"method\":\"historical_comparison\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_drift.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Model drift phase complete: $count drift indicators for $domain"
    py_log "INFO" "model_drift_phase_complete" --phase "model_drift" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
