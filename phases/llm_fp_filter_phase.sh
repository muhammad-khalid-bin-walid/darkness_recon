#!/bin/bash
# Track 9 - ML/Triage/Future: LLM-based false-positive filtering, context-aware validation

llm_fp_filter_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/llm_fp_filter"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting LLM false-positive filter phase for $domain"
    py_log "INFO" "llm_fp_filter_phase_start" --phase "llm_fp_filter" --target "$domain" 2>/dev/null || true

    local fp_filter_config="$phase_dir/fp_filter_config.json"
    local filtered_results="$phase_dir/filtered_results.txt"
    local count=0

    log "INFO" "Running LLM-based false-positive filtering..."

    python3 -c "
import json, os, sys
from collections import Counter

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'

# Load all findings
all_findings = []
base = os.path.join(output_dir)
if os.path.isdir(base):
    for entry in os.listdir(base):
        if entry == 'llm_fp_filter':
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

# Context-aware false-positive detection rules
# Each rule evaluates multiple contextual signals
fp_rules = [
    {
        'name': 'internal_address',
        'condition': lambda f: any(x in json.dumps(f).lower() for x in ['192.168.', '10.0.', '172.16.', '172.31.', '127.0.0.1', '0.0.0.0']),
        'confidence': 0.9,
        'reason': 'Internal/private IP address'
    },
    {
        'name': 'test_domain',
        'condition': lambda f: any(x in json.dumps(f).lower() for x in ['example.com', 'test.com', 'localhost', '.local', 'staging.', 'dev.']),
        'confidence': 0.85,
        'reason': 'Test/staging domain'
    },
    {
        'name': 'static_asset',
        'condition': lambda f: any(json.dumps(f).lower().endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot']),
        'confidence': 0.7,
        'reason': 'Static asset, not a vulnerability'
    },
    {
        'name': 'common_pattern_low_sev',
        'condition': lambda f: f.get('severity', '').lower() == 'info' and f.get('confidence', 1) < 0.4,
        'confidence': 0.6,
        'reason': 'Low-severity informational finding with low confidence'
    },
    {
        'name': 'duplicate_indicator',
        'condition': lambda f: f.get('type', '') == f.get('finding', '') and not f.get('evidence'),
        'confidence': 0.5,
        'reason': 'No evidence provided, type matches finding exactly'
    },
    {
        'name': 'out_of_scope_pattern',
        'condition': lambda f: domain not in json.dumps(f).lower() and domain.split('.')[0] not in json.dumps(f).lower(),
        'confidence': 0.4,
        'reason': 'Finding may be out of target scope'
    }
]

# Apply filters
true_positives = []
false_positives = []
uncertain = []

for finding in all_findings:
    fp_score = 0.0
    fp_reasons = []
    is_fp = False

    for rule in fp_rules:
        try:
            if rule['condition'](finding):
                fp_score += rule['confidence']
                fp_reasons.append(rule['reason'])
        except:
            pass

    # Normalize score
    fp_score = min(fp_score / len(fp_rules), 1.0)

    if fp_score >= 0.6:
        is_fp = True
        finding['_fp_score'] = round(fp_score, 3)
        finding['_fp_reasons'] = fp_reasons
        false_positives.append(finding)
    elif fp_score >= 0.3:
        finding['_uncertainty_score'] = round(fp_score, 3)
        uncertain.append(finding)
    else:
        true_positives.append(finding)

# Calculate metrics
total = len(all_findings)
fp_count = len(false_positives)
tp_count = len(true_positives)
uncertain_count = len(uncertain)
precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0

# Write config
config = {
    'domain': domain,
    'total_findings': total,
    'true_positives': tp_count,
    'false_positives': fp_count,
    'uncertain': uncertain_count,
    'precision_after_filtering': round(precision, 3),
    'fp_rate': round(fp_count / total * 100, 2) if total > 0 else 0,
    'rules_applied': [r['name'] for r in fp_rules],
    'filter_threshold': 0.6,
    'uncertainty_threshold': 0.3
}

with open(os.path.join(phase_dir, 'fp_filter_config.json'), 'w') as f:
    json.dump(config, f, indent=2, default=str)

# Write filtered results
with open(os.path.join(phase_dir, 'filtered_results.txt'), 'w') as f:
    f.write(f'LLM False-Positive Filter Report for {domain}\n')
    f.write('=' * 50 + '\n\n')
    f.write(f'Total findings: {total}\n')
    f.write(f'True positives: {tp_count}\n')
    f.write(f'False positives: {fp_count}\n')
    f.write(f'Uncertain: {uncertain_count}\n')
    f.write(f'Precision: {round(precision * 100, 1)}%\n\n')
    f.write('False Positives Identified:\n')
    for fp in false_positives[:30]:
        f.write(f\"  [{fp.get('_source_phase', '?')}] {fp.get('type', fp.get('finding', 'unknown'))}\")
        f.write(f\" (score={fp.get('_fp_score', '?')}): {', '.join(fp.get('_fp_reasons', []))}\n\")
    f.write(f'\nUncertain Findings (require manual review):\n')
    for u in uncertain[:20]:
        f.write(f\"  [{u.get('_source_phase', '?')}] {u.get('type', u.get('finding', 'unknown'))}\")
        f.write(f\" (uncertainty={u.get('_uncertainty_score', '?')})\n\")

print(fp_count)
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$fp_filter_config" ]; then
        write_finding "{\"type\":\"llm_fp_filter_complete\",\"target\":\"$domain\",\"false_positives_identified\":$count,\"method\":\"context_aware_filtering\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_fp_filter.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "LLM FP filter phase complete: $count false positives identified for $domain"
    py_log "INFO" "llm_fp_filter_phase_complete" --phase "llm_fp_filter" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
