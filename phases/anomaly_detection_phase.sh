#!/bin/bash
# Track 9 - ML/Triage/Future: Anomaly detection in scan results, baseline comparison, outlier identification

anomaly_detection_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/anomaly_detection"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting anomaly detection phase for $domain"
    py_log "INFO" "anomaly_detection_phase_start" --phase "anomaly_detection" --target "$domain" 2>/dev/null || true

    local anomaly_config="$phase_dir/anomaly_config.json"
    local anomalies_file="$phase_dir/anomalies.txt"
    local count=0

    # Baseline file from previous scans
    local baseline_file="$OUTPUT_DIR/$domain/baseline_metrics.json"

    log "INFO" "Running anomaly detection across scan results..."

    python3 -c "
import json, os, sys, statistics
from collections import Counter, defaultdict

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'
baseline_file = '$baseline_file'

# Load all findings from all phase directories
all_findings = []
phase_metrics = defaultdict(lambda: {'count': 0, 'severities': [], 'confidence_scores': []})
base = os.path.join(output_dir)
if os.path.isdir(base):
    for entry in os.listdir(base):
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
                                phase_metrics[entry]['count'] += 1
                                sev = item.get('severity', item.get('level', 'info'))
                                phase_metrics[entry]['severities'].append(sev)
                                conf = item.get('confidence', item.get('score', 0))
                                if isinstance(conf, (int, float)) and conf > 0:
                                    phase_metrics[entry]['confidence_scores'].append(conf)
                except:
                    pass

# Load baseline if available
baseline = {}
if os.path.isfile(baseline_file):
    try:
        with open(baseline_file) as f:
            baseline = json.load(f)
    except:
        pass

# Anomaly detection: statistical outlier analysis
anomalies = []
metric_vectors = {}

for phase, metrics in phase_metrics.items():
    counts = metrics['count']
    confs = metrics['confidence_scores']
    sevs = Counter(metrics['severities'])

    avg_conf = statistics.mean(confs) if confs else 0
    std_conf = statistics.stdev(confs) if len(confs) > 1 else 0
    max_conf = max(confs) if confs else 0

    metric_vectors[phase] = {
        'count': counts,
        'avg_confidence': round(avg_conf, 3),
        'std_confidence': round(std_conf, 3),
        'critical_count': sevs.get('critical', 0),
        'high_count': sevs.get('high', 0)
    }

    # Check against baseline
    if phase in baseline:
        base_metrics = baseline[phase]
        base_count = base_metrics.get('count', 0)
        if base_count > 0:
            count_ratio = counts / base_count if base_count > 0 else 1
            if count_ratio > 3.0:
                anomalies.append({
                    'type': 'count_spike',
                    'phase': phase,
                    'current_count': counts,
                    'baseline_count': base_count,
                    'ratio': round(count_ratio, 2),
                    'severity': 'HIGH'
                })
            elif count_ratio < 0.1 and base_count > 5:
                anomalies.append({
                    'type': 'count_drop',
                    'phase': phase,
                    'current_count': counts,
                    'baseline_count': base_count,
                    'ratio': round(count_ratio, 2),
                    'severity': 'MEDIUM'
                })

    # Check for unusual severity distributions
    total_sev = sum(sevs.values())
    if total_sev > 0:
        crit_ratio = sevs.get('critical', 0) / total_sev
        if crit_ratio > 0.3:
            anomalies.append({
                'type': 'high_critical_ratio',
                'phase': phase,
                'critical_ratio': round(crit_ratio, 3),
                'severity': 'HIGH'
            })

# Identify outlier phases (highest finding density)
all_counts = [v['count'] for v in metric_vectors.values()]
if all_counts:
    mean_count = statistics.mean(all_counts)
    std_count = statistics.stdev(all_counts) if len(all_counts) > 1 else 0
    for phase, vec in metric_vectors.items():
        if std_count > 0 and (vec['count'] - mean_count) / std_count > 2.0:
            anomalies.append({
                'type': 'outlier_phase',
                'phase': phase,
                'count': vec['count'],
                'z_score': round((vec['count'] - mean_count) / std_count, 2),
                'severity': 'MEDIUM'
            })

# Write config
config = {
    'domain': domain,
    'total_findings': len(all_findings),
    'phases_analyzed': len(phase_metrics),
    'anomalies_detected': len(anomalies),
    'baseline_available': bool(baseline),
    'detection_methods': ['statistical_outlier', 'baseline_comparison', 'severity_distribution'],
    'thresholds': {
        'count_spike_ratio': 3.0,
        'count_drop_ratio': 0.1,
        'critical_ratio_threshold': 0.3,
        'z_score_threshold': 2.0
    },
    'phase_metrics': metric_vectors
}

with open(os.path.join(phase_dir, 'anomaly_config.json'), 'w') as f:
    json.dump(config, f, indent=2)

# Write anomalies file
with open(os.path.join(phase_dir, 'anomalies.txt'), 'w') as f:
    f.write(f'Anomaly Detection Report for {domain}\n')
    f.write('=' * 50 + '\n\n')
    f.write(f'Total findings: {len(all_findings)}\n')
    f.write(f'Phases analyzed: {len(phase_metrics)}\n')
    f.write(f'Anomalies detected: {len(anomalies)}\n')
    f.write(f'Baseline available: {bool(baseline)}\n\n')
    if anomalies:
        f.write('Anomalies:\n')
        for i, a in enumerate(anomalies, 1):
            f.write(f\"  {i}. [{a['severity']}] {a['type']} in {a.get('phase', 'global')}\n\")
            for k, v in a.items():
                if k not in ['type', 'phase', 'severity']:
                    f.write(f\"     {k}: {v}\n\")
            f.write('\n')
    else:
        f.write('No anomalies detected.\n')

print(len(anomalies))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$anomaly_config" ]; then
        write_finding "{\"type\":\"anomaly_detection_complete\",\"target\":\"$domain\",\"anomalies_found\":$count,\"method\":\"statistical_outlier\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_anomaly.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Anomaly detection phase complete: $count anomalies detected for $domain"
    py_log "INFO" "anomaly_detection_phase_complete" --phase "anomaly_detection" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
