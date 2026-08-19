#!/bin/bash
# Track 9 - ML/Triage/Future: Self-tuning scan parameters, historical performance analysis, optimization

self_tuning_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/self_tuning"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting self-tuning phase for $domain"
    py_log "INFO" "self_tuning_phase_start" --phase "self_tuning" --target "$domain" 2>/dev/null || true

    local tuning_config="$phase_dir/tuning_config.json"
    local tuning_history="$phase_dir/tuning_history.txt"
    local count=0

    # Historical performance directory
    local history_dir="$OUTPUT_DIR/$domain/history"
    mkdir -p "$history_dir" 2>/dev/null || true

    log "INFO" "Analyzing historical performance for parameter optimization..."

    python3 -c "
import json, os, sys, time
from collections import defaultdict

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'
history_dir = '$history_dir'

# Gather current scan metrics
current_metrics = {
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'domain': domain,
    'phase_durations': {},
    'phase_findings': {},
    'resource_usage': {}
}

# Analyze current phase outputs
total_findings = 0
base = os.path.join(output_dir)
if os.path.isdir(base):
    for entry in os.listdir(base):
        pdir = os.path.join(base, entry)
        if not os.path.isdir(pdir):
            continue
        finding_count = 0
        for f in os.listdir(pdir):
            if f.endswith('.json'):
                try:
                    with open(os.path.join(pdir, f)) as fh:
                        data = json.load(fh)
                        if isinstance(data, list):
                            finding_count += len(data)
                        elif isinstance(data, dict):
                            finding_count += 1
                except:
                    pass
        current_metrics['phase_findings'][entry] = finding_count
        total_findings += finding_count

# Load historical data if available
historical_runs = []
if os.path.isdir(history_dir):
    for f in sorted(os.listdir(history_dir)):
        if f.endswith('_metrics.json'):
            try:
                with open(os.path.join(history_dir, f)) as fh:
                    historical_runs.append(json.load(fh))
            except:
                pass

# Save current run as history
history_file = os.path.join(history_dir, f'{int(time.time())}_metrics.json')
try:
    with open(history_file, 'w') as f:
        json.dump(current_metrics, f, indent=2)
except:
    pass

# Compute tuning recommendations
recommendations = []
tuning_params = {
    'threads': 150,
    'timeout': 300,
    'rate_limit': 1000,
    'max_retries': 2,
    'scan_depth': 3
}

# Analyze finding density per phase to optimize
phase_densities = {}
for phase, cnt in current_metrics['phase_findings'].items():
    if cnt > 0:
        phase_densities[phase] = cnt

# High-density phases may benefit from more threads
for phase, density in sorted(phase_densities.items(), key=lambda x: x[1], reverse=True)[:5]:
    if density > 100:
        recommendations.append({
            'phase': phase,
            'recommendation': 'increase_threads',
            'reason': f'High finding density ({density} findings)',
            'suggested_threads': min(tuning_params['threads'] * 2, 400)
        })

# Phases with zero findings may be wasteful
for phase, density in phase_densities.items():
    if density == 0:
        recommendations.append({
            'phase': phase,
            'recommendation': 'skip_or_reduce',
            'reason': 'No findings - consider skipping in future scans',
            'suggested_action': 'reduce_depth_or_skip'
        })

# Historical trend analysis
if len(historical_runs) > 1:
    trend_findings = [r.get('phase_findings', {}) for r in historical_runs]
    recommendations.append({
        'phase': 'global',
        'recommendation': 'trend_analysis',
        'reason': f'{len(historical_runs)} historical runs available',
        'trend': 'increasing' if total_findings > sum(trend_findings[-1].values()) else 'stable'
    })

# Build tuning config
config = {
    'domain': domain,
    'current_run': current_metrics,
    'historical_runs_count': len(historical_runs),
    'total_findings': total_findings,
    'optimized_params': tuning_params,
    'recommendations': recommendations,
    'phase_densities': phase_densities,
    'optimization_target': 'maximize_findings_per_unit_time'
}

with open(os.path.join(phase_dir, 'tuning_config.json'), 'w') as f:
    json.dump(config, f, indent=2, default=str)

# Write tuning history
with open(os.path.join(phase_dir, 'tuning_history.txt'), 'w') as f:
    f.write(f'Self-Tuning History for {domain}\n')
    f.write('=' * 50 + '\n\n')
    f.write(f'Current run total findings: {total_findings}\n')
    f.write(f'Historical runs analyzed: {len(historical_runs)}\n')
    f.write(f'Recommendations generated: {len(recommendations)}\n\n')
    f.write('Optimized Parameters:\n')
    for k, v in tuning_params.items():
        f.write(f'  {k}: {v}\n')
    f.write('\nRecommendations:\n')
    for i, rec in enumerate(recommendations, 1):
        f.write(f\"  {i}. [{rec.get('phase', 'global')}] {rec['recommendation']}: {rec['reason']}\n\")
    f.write('\nPhase Finding Densities:\n')
    for phase, density in sorted(phase_densities.items(), key=lambda x: x[1], reverse=True):
        f.write(f'  {phase}: {density}\n')

print(len(recommendations))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$tuning_config" ]; then
        write_finding "{\"type\":\"self_tuning_complete\",\"target\":\"$domain\",\"recommendations\":$count,\"method\":\"historical_analysis\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_tuning.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Self-tuning phase complete: $count recommendations for $domain"
    py_log "INFO" "self_tuning_phase_complete" --phase "self_tuning" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
