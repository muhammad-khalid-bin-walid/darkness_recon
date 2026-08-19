#!/bin/bash
# Track 9 - ML/Triage/Future: ML-based finding classification, severity prediction, false-positive detection

ml_classifier_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/ml_classifier"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting ML classifier phase for $domain"
    py_log "INFO" "ml_classifier_phase_start" --phase "ml_classifier" --target "$domain" 2>/dev/null || true

    local classifier_config="$phase_dir/classifier_config.json"
    local classification_report="$phase_dir/classification_report.txt"
    local count=0

    # Load all findings from previous phases
    log "INFO" "Loading findings for ML classification..."

    python3 -c "
import json, os, sys
from collections import Counter

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'

# Load all findings from all phase directories
all_findings = []
phase_dirs_to_scan = []
base = os.path.join(output_dir)
if os.path.isdir(base):
    for entry in os.listdir(base):
        full = os.path.join(base, entry)
        if os.path.isdir(full):
            phase_dirs_to_scan.append(full)

for pdir in phase_dirs_to_scan:
    for f in os.listdir(pdir):
        if f.endswith('.json'):
            try:
                with open(os.path.join(pdir, f)) as fh:
                    data = json.load(fh)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                item['_source_phase'] = os.path.basename(pdir)
                                item['_source_file'] = f
                                all_findings.append(item)
                    elif isinstance(data, dict):
                        data['_source_phase'] = os.path.basename(pdir)
                        data['_source_file'] = f
                        all_findings.append(data)
            except:
                pass

# Severity keyword rules for classification
severity_rules = {
    'critical': ['rce', 'remote code', 'sql injection', 'sqli', 'command injection',
                 'authentication bypass', 'privilege escalation', 'aws key', 'azure connection',
                 's3 bucket', 'credentials exposed', 'private key'],
    'high': ['xss', 'cross-site', 'csrf', 'ssrf', 'xxe', 'deserialization',
             'directory listing', 'backup exposure', 'source code', 'git exposed',
             'idor', 'open redirect', 'cors misconfig', 'hsts missing'],
    'medium': ['information disclosure', 'server version', 'header missing',
               'cookie flags', 'tls', 'ssl', 'deprecated', 'verbose error',
               'missing csp', 'missing xfo'],
    'low': ['informational', 'best practice', 'hardening', 'notice', 'hint',
            'verbose banner', 'server header', 'x-powered-by']
}

# False positive indicators
fp_indicators = [
    'example.com', 'test.example', 'localhost', '127.0.0.1', '0.0.0.0',
    '192.168.', '10.0.', '172.16.', '172.31.',
    'internal', 'staging', 'dev.', 'test.', 'demo.', 'sandbox',
    '.css', '.js', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff',
    'font', 'image', 'static', 'asset'
]

# Classify each finding
classified = []
severity_counts = Counter()
fp_count = 0

for finding in all_findings:
    finding_text = json.dumps(finding).lower()
    predicted_severity = 'info'
    confidence = 0.5
    is_fp = False

    # Check for false positive
    for fp in fp_indicators:
        if fp in finding_text:
            is_fp = True
            break

    # Classify severity
    for sev, keywords in severity_rules.items():
        for kw in keywords:
            if kw in finding_text:
                predicted_severity = sev
                confidence = 0.7 if sev in ['critical', 'high'] else 0.6
                break
        if predicted_severity != 'info':
            break

    if predicted_severity == 'info':
        confidence = 0.3

    result = {
        'original': finding,
        'predicted_severity': predicted_severity,
        'classification_confidence': round(confidence, 2),
        'is_false_positive': is_fp,
        'source_phase': finding.get('_source_phase', 'unknown'),
        'features_used': list(set([k for k in finding.keys() if not k.startswith('_')]))
    }
    classified.append(result)
    severity_counts[predicted_severity] += 1
    if is_fp:
        fp_count += 1

# Build classifier config
config = {
    'model_type': 'rule_based_severity_classifier',
    'domain': domain,
    'total_findings': len(all_findings),
    'severity_distribution': dict(severity_counts),
    'false_positives_identified': fp_count,
    'features_extracted': ['severity_keywords', 'context_patterns', 'source_phase'],
    'confidence_thresholds': {
        'verified': 0.9,
        'high': 0.7,
        'medium': 0.5,
        'low': 0.3
    },
    'rules_applied': len(severity_rules)
}

with open(os.path.join(phase_dir, 'classifier_config.json'), 'w') as f:
    json.dump(config, f, indent=2)

# Write classification report
with open(os.path.join(phase_dir, 'classification_report.txt'), 'w') as f:
    f.write(f'ML Classification Report for {domain}\n')
    f.write('=' * 50 + '\n\n')
    f.write(f'Total findings analyzed: {len(all_findings)}\n')
    f.write(f'False positives identified: {fp_count}\n\n')
    f.write('Severity Distribution:\n')
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        cnt = severity_counts.get(sev, 0)
        f.write(f'  {sev.upper():10s}: {cnt}\n')
    f.write('\nTop Classified Findings:\n')
    for item in sorted(classified, key=lambda x: x['classification_confidence'], reverse=True)[:20]:
        sev = item['predicted_severity']
        conf = item['classification_confidence']
        fp_flag = ' [FP]' if item['is_false_positive'] else ''
        f.write(f'  [{sev.upper():8s}] (conf={conf}){fp_flag} {item[\"source_phase\"]}\n')

print(len(classified))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$classifier_config" ]; then
        write_finding "{\"type\":\"ml_classification_complete\",\"target\":\"$domain\",\"findings_classified\":$count,\"method\":\"rule_based_severity\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_classifier.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "ML classifier phase complete: $count findings classified for $domain"
    py_log "INFO" "ml_classifier_phase_complete" --phase "ml_classifier" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
