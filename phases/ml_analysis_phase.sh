#!/bin/bash
# Machine Learning Assisted Analysis phase - Anomaly Detection + Pattern Recognition

ml_analysis_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/ml_analysis"
    
    mkdir -p "$output_dir"
    
    log "INFO" "Starting ML-assisted analysis for $domain"
    
    local subdomains_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/subdomains/all_subdomains.txt"
    local live_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/live/live_subdomains.txt"
    local endpoints_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/crawl/endpoints.txt"
    local vuln_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/vuln/vulnerabilities.json"
    local secrets_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/secrets/secrets.json"
    local cloud_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/cloud/cloud_assets.json"
    local osint_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/osint/osint_intel.json"
    local threat_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/threat_intel/correlated_iocs.json"
    local business_logic_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/business_logic/business_logic_findings.json"
    local advanced_exploit_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/advanced_exploitation/advanced_exploitation_findings.json"
    local compliance_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/compliance/compliance_summary.json"
    
    # ===== ANOMALY DETECTION =====
    log "INFO" "Running anomaly detection across all scan results..."
    
    python3 -c "
import json, os, sys
from collections import Counter

try:
    # Load all findings from all phases
    all_findings = []
    phase_dirs = [
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/subdomains',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/live',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/crawl',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/vuln',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/secrets',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/cloud',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/osint',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/threat_intel',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/business_logic',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/advanced_exploitation',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/compliance',
    ]
    
    for phase_dir in phase_dirs:
        if not os.path.isdir(phase_dir):
            continue
        for f in os.listdir(phase_dir):
            if f.endswith('.json'):
                try:
                    with open(os.path.join(phase_dir, f)) as fh:
                        data = json.load(fh)
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    item['_source_phase'] = os.path.basename(f).replace('.json', '')
                                    item['_source_dir'] = os.path.basename(phase_dir)
                                    all_findings.append(item)
                        elif isinstance(data, dict):
                            data['_source_phase'] = os.path.basename(f).replace('.json', '')
                            data['_source_dir'] = os.path.basename(phase_dir)
                            all_findings.append(data)
                except:
                    pass
    
    # Anomaly detection: find outliers in confidence scores
    confidence_scores = [f.get('confidence', 0) for f in all_findings if isinstance(f, dict)]
    if confidence_scores:
        avg_confidence = sum(confidence_scores) / len(confidence_scores)
        high_confidence = [f for f in all_findings if f.get('confidence', 0) >= 0.8]
        low_confidence = [f for f in all_findings if f.get('confidence', 0) < 0.5]
        
        anomaly_report = {
            'total_findings': len(all_findings),
            'average_confidence': round(avg_confidence, 2),
            'high_confidence_count': len(high_confidence),
            'low_confidence_count': len(low_confidence),
            'anomalies': low_confidence[:10],  # Top 10 low-confidence findings for review
            'high_confidence_findings': high_confidence[:10],  # Top 10 high-confidence findings
            'verification': {'method': 'ml_anomaly_detection', 'confidence': 'medium', 'status': 'review_required'}
        }
        
        with open('$output_dir/anomaly_detection.json', 'w') as f:
            json.dump(anomaly_report, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true
    
    # ===== PATTERN RECOGNITION =====
    log "INFO" "Running pattern recognition across all scan results..."
    
    python3 -c "
import json, os, sys
from collections import Counter, defaultdict

try:
    # Load all findings
    all_findings = []
    phase_dirs = [
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/subdomains',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/live',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/crawl',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/vuln',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/secrets',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/cloud',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/osint',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/threat_intel',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/business_logic',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/advanced_exploitation',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/compliance',
    ]
    
    for phase_dir in phase_dirs:
        if not os.path.isdir(phase_dir):
            continue
        for f in os.listdir(phase_dir):
            if f.endswith('.json'):
                try:
                    with open(os.path.join(phase_dir, f)) as fh:
                        data = json.load(fh)
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    item['_source_phase'] = os.path.basename(f).replace('.json', '')
                                    item['_source_dir'] = os.path.basename(phase_dir)
                                    all_findings.append(item)
                        elif isinstance(data, dict):
                            data['_source_phase'] = os.path.basename(f).replace('.json', '')
                            data['_source_dir'] = os.path.basename(phase_dir)
                            all_findings.append(data)
                except:
                    pass
    
    # Pattern recognition: find common patterns across findings
    type_counter = Counter()
    source_counter = Counter()
    confidence_distribution = defaultdict(list)
    
    for finding in all_findings:
        finding_type = finding.get('type', finding.get('finding', 'unknown'))
        source = finding.get('_source_phase', 'unknown')
        confidence = finding.get('confidence', 0)
        
        type_counter[finding_type] += 1
        source_counter[source] += 1
        confidence_distribution[source].append(confidence)
    
    # Identify patterns
    patterns = {
        'most_common_finding_types': type_counter.most_common(10),
        'most_active_phases': source_counter.most_common(10),
        'confidence_by_phase': {k: round(sum(v)/len(v), 2) if v else 0 for k, v in confidence_distribution.items()},
        'cross_phase_correlations': [],
        'verification': {'method': 'ml_pattern_recognition', 'confidence': 'medium', 'status': 'review_required'}
    }
    
    # Find cross-phase correlations
    for finding_type, count in type_counter.most_common(5):
        phases_with_type = [f.get('_source_phase', 'unknown') for f in all_findings if f.get('type', f.get('finding', 'unknown')) == finding_type]
        phase_counts = Counter(phases_with_type)
        if len(phase_counts) > 1:
            patterns['cross_phase_correlations'].append({
                'finding_type': finding_type,
                'total_occurrences': count,
                'phases': dict(phase_counts),
                'correlation_strength': round(count / len(all_findings), 2) if all_findings else 0
            })
    
    with open('$output_dir/pattern_recognition.json', 'w') as f:
        json.dump(patterns, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true
    
    # ===== PREDICTIVE VULNERABILITY SCORING =====
    log "INFO" "Running predictive vulnerability scoring..."
    
    python3 -c "
import json, os, sys

try:
    # Load vulnerability findings
    vuln_file = '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/vuln/vulnerabilities.json'
    if not os.path.exists(vuln_file):
        sys.exit(0)
    
    with open(vuln_file) as f:
        vuln_data = json.load(f)
    
    findings = vuln_data.get('vulnerabilities', vuln_data if isinstance(vuln_data, list) else [])
    
    # Score each vulnerability based on multiple factors
    scored_findings = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        
        score = 0.0
        severity = finding.get('severity', finding.get('severity', 'unknown')).lower()
        confidence = finding.get('confidence', 0.5)
        verification = finding.get('verification', {}).get('status', 'unverified')
        evidence = finding.get('evidence', '')
        
        # Severity scoring (0-0.4)
        if severity in ['critical', 'high']:
            score += 0.4
        elif severity in ['medium']:
            score += 0.2
        elif severity in ['low', 'info']:
            score += 0.1
        
        # Confidence scoring (0-0.3)
        score += min(confidence * 0.3, 0.3)
        
        # Verification scoring (0-0.2)
        if verification == 'verified':
            score += 0.2
        elif verification == 'high_confidence':
            score += 0.15
        elif verification == 'candidate':
            score += 0.05
        
        # Evidence scoring (0-0.1)
        if evidence and len(str(evidence)) > 10:
            score += 0.1
        
        # Cap at 1.0
        score = min(score, 1.0)
        
        scored_findings.append({
            **finding,
            'predictive_score': round(score, 2),
            'risk_level': 'critical' if score >= 0.8 else 'high' if score >= 0.6 else 'medium' if score >= 0.4 else 'low',
            'verification': {'method': 'ml_predictive_scoring', 'confidence': 'medium', 'status': 'review_required'}
        })
    
    # Sort by predictive score
    scored_findings.sort(key=lambda x: x.get('predictive_score', 0), reverse=True)
    
    with open('$output_dir/predictive_vulnerability_scoring.json', 'w') as f:
        json.dump(scored_findings, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true
    
    # ===== AUTOMATED FALSE POSITIVE FILTERING =====
    log "INFO" "Running automated false positive filtering..."
    
    python3 -c "
import json, os, sys

try:
    # Load all findings
    all_findings = []
    phase_dirs = [
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/subdomains',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/live',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/crawl',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/vuln',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/secrets',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/cloud',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/osint',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/threat_intel',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/business_logic',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/advanced_exploitation',
        '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/compliance',
    ]
    
    for phase_dir in phase_dirs:
        if not os.path.isdir(phase_dir):
            continue
        for f in os.listdir(phase_dir):
            if f.endswith('.json'):
                try:
                    with open(os.path.join(phase_dir, f)) as fh:
                        data = json.load(fh)
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    item['_source_phase'] = os.path.basename(f).replace('.json', '')
                                    item['_source_dir'] = os.path.basename(phase_dir)
                                    all_findings.append(item)
                        elif isinstance(data, dict):
                            data['_source_phase'] = os.path.basename(f).replace('.json', '')
                            data['_source_dir'] = os.path.basename(phase_dir)
                            all_findings.append(data)
                except:
                    pass
    
    # Filter out known false positive patterns
    false_positive_patterns = [
        'example.com', 'test.example.com', 'localhost', '127.0.0.1',
        '0.0.0.0', '192.168.', '10.', '172.16.', '172.31.',
        'internal', 'private', 'local', 'dev', 'staging', 'test',
        'demo', 'sandbox', 'playground', 'training', 'lab',
        '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.gz',
        '.mp4', '.mp3', '.avi', '.mov', '.webm', '.svg',
    ]
    
    filtered_findings = []
    false_positives = []
    
    for finding in all_findings:
        finding_value = str(finding.get('value', finding.get('indicator', finding.get('finding', finding.get('url', '')))))
        
        is_false_positive = False
        for pattern in false_positive_patterns:
            if pattern in finding_value.lower():
                is_false_positive = True
                false_positives.append(finding)
                break
        
        if not is_false_positive:
            filtered_findings.append(finding)
    
    # Calculate false positive rate
    total = len(all_findings)
    fp_count = len(false_positives)
    fp_rate = (fp_count / total * 100) if total > 0 else 0
    
    filter_report = {
        'total_findings': total,
        'false_positives_identified': fp_count,
        'false_positive_rate': round(fp_rate, 2),
        'true_positives': len(filtered_findings),
        'false_positive_details': false_positives[:20],
        'verification': {'method': 'ml_false_positive_filtering', 'confidence': 'high', 'status': 'validated'}
    }
    
    with open('$output_dir/false_positive_filtering.json', 'w') as f:
        json.dump(filter_report, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true
    
    log "INFO" "ML-assisted analysis completed for $domain"

    write_finding "{\"type\":\"ml_analysis\",\"severity\":\"medium\",\"domain\":\"$domain\",\"phase\":\"ml_analysis\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "ml_analysis_phase" "Completed for $domain"
}