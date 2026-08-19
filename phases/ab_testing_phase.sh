#!/bin/bash
# Track 9 - ML/Triage/Future: A/B testing for scan methodologies, effectiveness comparison

ab_testing_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/ab_testing"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting A/B testing phase for $domain"
    py_log "INFO" "ab_testing_phase_start" --phase "ab_testing" --target "$domain" 2>/dev/null || true

    local ab_test_config="$phase_dir/ab_test_config.json"
    local test_results="$phase_dir/test_results.txt"
    local count=0

    # Historical scans directory for comparison
    local history_dir="$OUTPUT_DIR/$domain"
    mkdir -p "$history_dir" 2>/dev/null || true

    log "INFO" "Running A/B testing analysis across scan methodologies..."

    python3 -c "
import json, os, sys
from collections import Counter, defaultdict

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'
history_dir = '$history_dir'

# Define methodology variants
methodologies = {
    'variant_a': {
        'name': 'Deep Scan',
        'description': 'Full depth crawling with parameter fuzzing',
        'phases_weight': {'crawl': 3, 'fuzz': 5, 'nuclei': 5, 'vuln': 4},
        'thread_count': 200,
        'timeout': 600,
        'scan_depth': 5
    },
    'variant_b': {
        'name': 'Fast Scan',
        'description': 'Quick enumeration with high-value templates only',
        'phases_weight': {'crawl': 1, 'fuzz': 2, 'nuclei': 3, 'vuln': 2},
        'thread_count': 400,
        'timeout': 120,
        'scan_depth': 2
    }
}

# Analyze current scan as baseline
current_results = {
    'total_findings': 0,
    'phase_findings': Counter(),
    'severity_dist': Counter(),
    'unique_types': set(),
    'coverage_score': 0,
    'efficiency_score': 0
}

base = os.path.join(output_dir)
if os.path.isdir(base):
    phases_found = 0
    for entry in os.listdir(base):
        if entry == 'ab_testing':
            continue
        pdir = os.path.join(base, entry)
        if not os.path.isdir(pdir):
            continue
        phases_found += 1
        finding_count = 0
        for f in os.listdir(pdir):
            if f.endswith('.json'):
                try:
                    with open(os.path.join(pdir, f)) as fh:
                        data = json.load(fh)
                        items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
                        for item in items:
                            if isinstance(item, dict):
                                finding_count += 1
                                sev = str(item.get('severity', item.get('level', 'info'))).lower()
                                current_results['severity_dist'][sev] += 1
                                ftype = item.get('type', item.get('finding', 'unknown'))
                                current_results['unique_types'].add(str(ftype))
                except:
                    pass
        current_results['phase_findings'][entry] = finding_count
        current_results['total_findings'] += finding_count

    current_results['coverage_score'] = phases_found
    current_results['unique_types_count'] = len(current_results['unique_types'])

# Simulate variant effectiveness
# Variant A (Deep): higher finding count, higher time, better coverage
# Variant B (Fast): lower finding count, lower time, less coverage

variant_simulations = {}
for variant_id, variant in methodologies.items():
    sim = {
        'methodology': variant['name'],
        'description': variant['description'],
        'simulated_findings': 0,
        'simulated_severity_dist': {},
        'estimated_time_minutes': 0,
        'coverage_pct': 0,
        'efficiency_ratio': 0
    }

    # Simulate based on methodology weights and current results
    total_weight = sum(variant['phases_weight'].values())
    sim_findings = 0
    sim_sev = Counter()

    for phase, weight in variant['phases_weight'].items():
        # Scale findings by weight ratio
        base_findings = current_results['phase_findings'].get(phase, current_results['total_findings'] // max(len(methodologies['variant_a']['phases_weight']), 1))
        scale = weight / 5.0  # Normalize to max weight
        phase_findings = int(base_findings * scale * (variant['thread_count'] / 200.0))
        sim_findings += phase_findings

        # Distribute severities
        for sev, cnt in current_results['severity_dist'].items():
            scaled = int(cnt * scale * 0.8)
            sim_sev[sev] += scaled

    # Time estimation
    time_per_finding = variant['timeout'] / max(sim_findings, 1)
    sim_time = max(sim_findings * time_per_finding / 60, 5)

    # Coverage
    sim['simulated_findings'] = sim_findings
    sim['simulated_severity_dist'] = dict(sim_sev)
    sim['estimated_time_minutes'] = round(sim_time, 1)
    sim['coverage_pct'] = round(min(sim_findings / max(current_results['total_findings'], 1) * 100, 100), 1)
    sim['efficiency_ratio'] = round(sim_findings / max(sim_time, 1), 2)

    variant_simulations[variant_id] = sim

# Recommendation
best_variant = max(variant_simulations.items(), key=lambda x: x[1]['efficiency_ratio'])
recommendation = {
    'recommended_variant': best_variant[0],
    'reason': f\"Highest efficiency ratio: {best_variant[1]['efficiency_ratio']} findings/minute\",
    'variant_a_vs_b': {
        'finding_difference': variant_simulations['variant_a']['simulated_findings'] - variant_simulations['variant_b']['simulated_findings'],
        'time_difference': variant_simulations['variant_a']['estimated_time_minutes'] - variant_simulations['variant_b']['estimated_time_minutes']
    }
}

# Write config
config = {
    'domain': domain,
    'current_baseline': {
        'total_findings': current_results['total_findings'],
        'phases_covered': current_results['coverage_score'],
        'unique_finding_types': current_results['unique_types_count'],
        'severity_distribution': dict(current_results['severity_dist'])
    },
    'methodologies': methodologies,
    'simulated_results': variant_simulations,
    'recommendation': recommendation,
    'test_config': {
        'comparison_metrics': ['findings_count', 'efficiency_ratio', 'coverage_pct', 'severity_distribution'],
        'statistical_significance': 'simulated',
        'sample_size': 1
    }
}

with open(os.path.join(phase_dir, 'ab_test_config.json'), 'w') as f:
    json.dump(config, f, indent=2, default=str)

# Write test results
with open(os.path.join(phase_dir, 'test_results.txt'), 'w') as f:
    f.write(f'A/B Test Results - {domain}\n')
    f.write('=' * 50 + '\n\n')
    f.write(f'Current baseline: {current_results[\"total_findings\"]} findings\n\n')
    for vid, sim in variant_simulations.items():
        f.write(f'--- {sim[\"methodology\"]} ({vid}) ---\n')
        f.write(f'  Simulated findings: {sim[\"simulated_findings\"]}\n')
        f.write(f'  Estimated time: {sim[\"estimated_time_minutes\"]} min\n')
        f.write(f'  Coverage: {sim[\"coverage_pct\"]}%\n')
        f.write(f'  Efficiency: {sim[\"efficiency_ratio\"]} findings/min\n')
        f.write(f'  Severity: {sim[\"simulated_severity_dist\"]}\n\n')
    f.write(f'Recommendation: {recommendation[\"recommended_variant\"]}\n')
    f.write(f'Reason: {recommendation[\"reason\"]}\n')
    f.write(f'Finding diff (A-B): {recommendation[\"variant_a_vs_b\"][\"finding_difference\"]}\n')
    f.write(f'Time diff (A-B): {recommendation[\"variant_a_vs_b\"][\"time_difference\"]} min\n')

print(len(methodologies))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$ab_test_config" ]; then
        write_finding "{\"type\":\"ab_testing_complete\",\"target\":\"$domain\",\"variants_tested\":$count,\"method\":\"methodology_comparison\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_ab_test.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "A/B testing phase complete: $count variants compared for $domain"
    py_log "INFO" "ab_testing_phase_complete" --phase "ab_testing" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
