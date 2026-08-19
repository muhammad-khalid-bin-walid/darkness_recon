#!/bin/bash
# Finding Validation & Correlation Engine
# Cross-references findings across all phases, validates with multiple sources, scores confidence

validate_and_correlate_findings() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local validation_dir="$output_dir/validation"
    
    mkdir -p "$validation_dir"
    
    log "INFO" "Starting finding validation and correlation for $domain"
    
    # ========================================================================
    # 1. COLLECT ALL FINDINGS FROM ALL PHASES
    # ========================================================================
    log "INFO" "Collecting findings from all phases..."
    
    local all_findings_file="$validation_dir/all_findings_raw.jsonl"
    : > "$all_findings_file"
    
    # Find all JSON output files from phases
    find "$output_dir" -name "*.json" -type f 2>/dev/null | while read -r json_file; do
        # Skip already processed validation files
        [[ "$json_file" == *"validation"* ]] && continue
        [[ "$json_file" == *"report"* ]] && continue
        
        # Extract findings from various JSON formats
        python3 << 'PYEOF' "$json_file" "$all_findings_file" 2>/dev/null || true
import json, sys, os
import hashlib

json_file = sys.argv[1]
output_file = sys.argv[2]

try:
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    findings = []
    
    # Handle different JSON structures
    if isinstance(data, dict):
        # Check for common keys
        if 'findings' in data:
            findings = data['findings']
        elif 'vulnerabilities' in data:
            findings = data['vulnerabilities']
        elif 'results' in data:
            findings = data['results']
        elif 'data' in data:
            findings = data['data']
        else:
            # Single finding object
            findings = [data]
    elif isinstance(data, list):
        findings = data
    
    phase_name = os.path.basename(os.path.dirname(json_file))
    tool_name = os.path.basename(json_file).replace('.json', '')
    
    with open(output_file, 'a') as out:
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            
            # Normalize finding
            normalized = {
                'source_file': json_file,
                'phase': phase_name,
                'tool': tool_name,
                'raw_finding': finding,
                'collected_at': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
            }
            
            # Extract key identifiers
            for key in ['id', 'vuln_id', 'cve', 'ghsa', 'title', 'type', 'url', 'host', 'ip', 'endpoint', 'parameter', 'payload']:
                if key in finding:
                    normalized[key] = finding[key]
            
            # Extract severity
            for key in ['severity', 'risk', 'level', 'cvss', 'score']:
                if key in finding:
                    normalized['severity'] = finding[key]
                    break
            
            # Extract confidence
            if 'confidence' in finding:
                normalized['confidence'] = finding[key]
            elif 'verified' in finding and finding['verified']:
                normalized['confidence'] = 0.9
            
            # Generate content hash for deduplication
            content_str = json.dumps(finding, sort_keys=True)
            normalized['content_hash'] = hashlib.md5(content_str.encode()).hexdigest()[:16]
            
            out.write(json.dumps(normalized) + '\n')
except Exception as e:
    pass
PYEOF
    done
    
    # ========================================================================
    # 2. DEDUPLICATION BY CONTENT HASH
    # ========================================================================
    log "INFO" "Deduplicating findings..."
    
    python3 << 'PYEOF' "$validation_dir" 2>/dev/null || true
import json, sys, os
from collections import defaultdict

validation_dir = sys.argv[1]
input_file = os.path.join(validation_dir, 'all_findings_raw.jsonl')
output_file = os.path.join(validation_dir, 'findings_deduped.jsonl')

seen_hashes = {}
all_findings = []

with open(input_file, 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
            content_hash = finding.get('content_hash', '')
            
            if content_hash and content_hash in seen_hashes:
                # Merge sources
                existing_idx = seen_hashes[content_hash]
                all_findings[existing_idx]['sources'] = all_findings[existing_idx].get('sources', []) + [finding.get('tool', 'unknown')]
                all_findings[existing_idx]['source_files'] = all_findings[existing_idx].get('source_files', []) + [finding.get('source_file', '')]
                # Increase confidence with multiple sources
                current_conf = all_findings[existing_idx].get('confidence', 0.5)
                all_findings[existing_idx]['confidence'] = min(current_conf + 0.1, 1.0)
                all_findings[existing_idx]['source_count'] = all_findings[existing_idx].get('source_count', 1) + 1
            else:
                finding['sources'] = [finding.get('tool', 'unknown')]
                finding['source_files'] = [finding.get('source_file', '')]
                finding['source_count'] = 1
                seen_hashes[content_hash] = len(all_findings)
                all_findings.append(finding)
        except:
            pass

with open(output_file, 'w') as f:
    for finding in all_findings:
        f.write(json.dumps(finding) + '\n')

print(f"Deduplicated: {len(seen_hashes)} unique findings from {sum(1 for _ in open(input_file))} raw")
PYEOF

    # ========================================================================
    # 3. CROSS-REFERENCE VALIDATION
    # ========================================================================
    log "INFO" "Cross-referencing findings across sources..."
    
    python3 << 'PYEOF' "$validation_dir" 2>/dev/null || true
import json, sys, os, re
from urllib.parse import urlparse

validation_dir = sys.argv[1]
input_file = os.path.join(validation_dir, 'findings_deduped.jsonl')
output_file = os.path.join(validation_dir, 'findings_correlated.jsonl')

# Load all findings
findings = []
with open(input_file, 'r') as f:
    for line in f:
        line = line.strip()
        if line:
            findings.append(json.loads(line))

# Build indexes for correlation
by_url = defaultdict(list)
by_host = defaultdict(list)
by_parameter = defaultdict(list)
by_cve = defaultdict(list)
by_type = defaultdict(list)

for idx, finding in enumerate(findings):
    raw = finding.get('raw_finding', {})
    
    # Index by URL
    url = raw.get('url') or raw.get('endpoint') or raw.get('host') or finding.get('url') or finding.get('host')
    if url:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path.split('/')[0]
        by_host[host].append(idx)
        by_url[url].append(idx)
    
    # Index by parameter
    param = raw.get('parameter') or raw.get('param') or finding.get('parameter')
    if param:
        by_parameter[param].append(idx)
    
    # Index by CVE
    cve = raw.get('cve') or raw.get('cve_id') or finding.get('cve')
    if cve and cve.upper().startswith('CVE-'):
        by_cve[cve.upper()].append(idx)
    
    # Index by type
    vtype = raw.get('type') or raw.get('vuln_type') or finding.get('type')
    if vtype:
        by_type[vtype].append(idx)

# Cross-reference findings
correlated = []
for idx, finding in enumerate(findings):
    raw = finding.get('raw_finding', {})
    correlations = []
    confidence = finding.get('confidence', 0.5)
    source_count = finding.get('source_count', 1)
    
    # Check for same URL in multiple sources
    url = raw.get('url') or raw.get('endpoint') or raw.get('host')
    if url and len(by_url.get(url, [])) > 1:
        correlations.append({
            'type': 'same_url_multiple_sources',
            'count': len(by_url[url]),
            'sources': list(set(findings[i].get('tool') for i in by_url[url]))
        })
        confidence = min(confidence + 0.15, 1.0)
    
    # Check for same host with different vulnerabilities
    host = None
    if url:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path.split('/')[0]
    if host and len(by_host.get(host, [])) > 3:
        correlations.append({
            'type': 'host_multiple_vulns',
            'vuln_count': len(by_host[host]),
            'vuln_types': list(set(findings[i].get('raw_finding', {}).get('type', '') for i in by_host[host] if findings[i].get('raw_finding', {}).get('type')))
        })
    
    # Check for CVE correlation
    cve = raw.get('cve') or raw.get('cve_id')
    if cve and cve.upper().startswith('CVE-'):
        if len(by_cve.get(cve.upper(), [])) > 1:
            correlations.append({
                'type': 'cve_multiple_sources',
                'cve': cve.upper(),
                'count': len(by_cve[cve.upper()])
            })
            confidence = min(confidence + 0.2, 1.0)
    
    # Check for same parameter across endpoints (potential IDOR/mass assignment)
    param = raw.get('parameter') or raw.get('param')
    if param and len(by_parameter.get(param, [])) > 2:
        correlations.append({
            'type': 'parameter_reuse',
            'parameter': param,
            'endpoint_count': len(by_parameter[param])
        })
        confidence = min(confidence + 0.1, 1.0)
    
    # Update finding with correlation data
    finding['correlations'] = correlations
    finding['confidence'] = confidence
    finding['validation_status'] = 'validated' if confidence >= 0.7 else 'candidate' if confidence >= 0.4 else 'low_confidence'
    finding['source_count'] = source_count
    
    # Severity adjustment based on correlation
    severity = raw.get('severity') or finding.get('severity') or 'unknown'
    if isinstance(severity, str):
        severity = severity.lower()
    
    if confidence >= 0.8 and severity in ['critical', 'high']:
        finding['severity'] = severity
        finding['risk_level'] = 'confirmed_high'
    elif confidence >= 0.7 and severity in ['critical', 'high', 'medium']:
        finding['severity'] = severity
        finding['risk_level'] = 'likely'
    elif confidence >= 0.5:
        finding['risk_level'] = 'possible'
    else:
        finding['risk_level'] = 'unverified'
    
    correlated.append(finding)

# Write correlated findings
with open(output_file, 'w') as f:
    for finding in correlated:
        f.write(json.dumps(finding) + '\n')

print(f"Correlated {len(correlated)} findings")
validated = sum(1 for f in correlated if f['validation_status'] == 'validated')
candidates = sum(1 for f in correlated if f['validation_status'] == 'candidate')
print(f"Validated: {validated}, Candidates: {candidates}, Low: {len(correlated) - validated - candidates}")
PYEOF

    # ========================================================================
    # 4. FALSE POSITIVE FILTERING
    # ========================================================================
    log "INFO" "Filtering false positives..."
    
    python3 << 'PYEOF' "$validation_dir" 2>/dev/null || true
import json, sys, os, re

validation_dir = sys.argv[1]
input_file = os.path.join(validation_dir, 'findings_correlated.jsonl')
output_file = os.path.join(validation_dir, 'findings_validated.jsonl')

# False positive patterns
fp_patterns = {
    'xss': [
        r'google\.com/search',
        r'facebook\.com/sharer',
        r'twitter\.com/intent',
        r'linkedin\.com/share',
        r'addthis\.com',
        r'static\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico)',
        r'fonts\.googleapis\.com',
        r'cdnjs\.cloudflare\.com',
        r'unpkg\.com',
        r'jsdelivr\.net',
    ],
    'sqli': [
        r'wp-admin',
        r'wp-login',
        r'xmlrpc\.php',
        r'/\.git/',
        r'/\.env',
        r'phpmyadmin',
        r'adminer',
    ],
    'ssrf': [
        r'localhost',
        r'127\.0\.0\.1',
        r'169\.254\.169\.254',
        r'\[::1\]',
    ],
    'redirect': [
        r'accounts\.google\.com',
        r'login\.microsoftonline\.com',
        r'auth\.',
        r'sso\.',
        r'oauth',
    ],
    'info_disclosure': [
        r'robots\.txt',
        r'sitemap\.xml',
        r'\.well-known/',
        r'security\.txt',
        r'humans\.txt',
    ]
}

# Compile regex
compiled_fp = {}
for category, patterns in fp_patterns.items():
    compiled_fp[category] = [re.compile(p, re.IGNORECASE) for p in patterns]

validated_findings = []
false_positives = []

with open(input_file, 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
            raw = finding.get('raw_finding', {})
            url = raw.get('url') or raw.get('endpoint') or raw.get('host') or finding.get('url') or finding.get('host') or ''
            vtype = (raw.get('type') or raw.get('vuln_type') or finding.get('type') or '').lower()
            
            is_fp = False
            fp_reason = ''
            
            # Check false positive patterns for this vulnerability type
            for pattern in compiled_fp.get(vtype, []):
                if pattern.search(url):
                    is_fp = True
                    fp_reason = f"Matches FP pattern for {vtype}: {pattern.pattern}"
                    break
            
            # Generic false positives
            if not is_fp:
                # Very low confidence with no correlations
                if finding.get('confidence', 0) < 0.3 and finding.get('source_count', 1) == 1:
                    is_fp = True
                    fp_reason = "Very low confidence, single source, no correlations"
                
                # Common static assets
                if re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|pdf|zip|gz|mp4|mp3)(\?|$)', url, re.IGNORECASE):
                    is_fp = True
                    fp_reason = "Static asset"
            
            if is_fp:
                finding['false_positive'] = True
                finding['fp_reason'] = fp_reason
                finding['validation_status'] = 'false_positive'
                false_positives.append(finding)
            else:
                finding['false_positive'] = False
                validated_findings.append(finding)
                
        except Exception as e:
            pass

# Write validated findings
with open(output_file, 'w') as f:
    for finding in validated_findings:
        f.write(json.dumps(finding) + '\n')

# Write false positives separately
fp_file = os.path.join(validation_dir, 'false_positives.jsonl')
with open(fp_file, 'w') as f:
    for finding in false_positives:
        f.write(json.dumps(finding) + '\n')

print(f"Validated: {len(validated_findings)}, False Positives: {len(false_positives)}")
PYEOF

    # ========================================================================
    # 5. GENERATE FINAL VALIDATION REPORT
    # ========================================================================
    log "INFO" "Generating validation report..."
    
    python3 << 'PYEOF' "$domain" "$validation_dir" "$output_dir" 2>/dev/null || true
import json, sys, os
from datetime import datetime
from collections import Counter

domain = sys.argv[1]
validation_dir = sys.argv[2]
output_dir = sys.argv[3]

# Load validated findings
findings = []
validated_file = os.path.join(validation_dir, 'findings_validated.jsonl')
with open(validated_file, 'r') as f:
    for line in f:
        line = line.strip()
        if line:
            findings.append(json.loads(line))

# Load false positives
false_positives = []
fp_file = os.path.join(validation_dir, 'false_positives.jsonl')
with open(fp_file, 'r') as f:
    for line in f:
        line = line.strip()
        if line:
            false_positives.append(json.loads(line))

# Statistics
total_raw = len(findings) + len(false_positives)
validated_count = len(findings)
fp_count = len(false_positives)

# By severity
severity_counts = Counter()
confidence_dist = {'high': 0, 'medium': 0, 'low': 0}
validation_status = Counter()
risk_levels = Counter()
sources = Counter()
phases = Counter()

for f in findings:
    raw = f.get('raw_finding', {})
    severity = (raw.get('severity') or f.get('severity') or 'unknown').lower()
    severity_counts[severity] += 1
    
    conf = f.get('confidence', 0.5)
    if conf >= 0.8:
        confidence_dist['high'] += 1
    elif conf >= 0.5:
        confidence_dist['medium'] += 1
    else:
        confidence_dist['low'] += 1
    
    validation_status[f.get('validation_status', 'unknown')] += 1
    risk_levels[f.get('risk_level', 'unknown')] += 1
    
    for src in f.get('sources', []):
        sources[src] += 1
    
    phase = f.get('phase', 'unknown')
    phases[phase] += 1

# By type
type_counts = Counter()
for f in findings:
    raw = f.get('raw_finding', {})
    vtype = (raw.get('type') or raw.get('vuln_type') or f.get('type') or 'unknown').lower()
    type_counts[vtype] += 1

# Top correlated findings
top_correlated = sorted(findings, key=lambda x: x.get('confidence', 0), reverse=True)[:20]

# Generate report
report = {
    'domain': domain,
    'validation_timestamp': datetime.utcnow().isoformat() + 'Z',
    'summary': {
        'total_raw_findings': total_raw,
        'validated_findings': validated_count,
        'false_positives_filtered': fp_count,
        'false_positive_rate': round(fp_count / max(total_raw, 1) * 100, 2),
        'validation_rate': round(validated_count / max(total_raw, 1) * 100, 2)
    },
    'severity_distribution': dict(severity_counts),
    'confidence_distribution': confidence_dist,
    'validation_status': dict(validation_status),
    'risk_levels': dict(risk_levels),
    'top_sources': dict(sources.most_common(10)),
    'top_phases': dict(phases.most_common(10)),
    'vulnerability_types': dict(type_counts.most_common(15)),
    'top_findings': []
}

for f in top_correlated:
    raw = f.get('raw_finding', {})
    report['top_findings'].append({
        'title': raw.get('title') or raw.get('type') or 'Unknown',
        'severity': (raw.get('severity') or f.get('severity') or 'unknown').upper(),
        'confidence': round(f.get('confidence', 0), 2),
        'risk_level': f.get('risk_level', 'unknown'),
        'source_count': f.get('source_count', 1),
        'sources': f.get('sources', []),
        'correlations': len(f.get('correlations', [])),
        'url': raw.get('url') or raw.get('endpoint') or raw.get('host') or '',
        'type': raw.get('type') or raw.get('vuln_type') or f.get('type') or 'unknown'
    })

# Write validation report
with open(os.path.join(validation_dir, 'validation_report.json'), 'w') as f:
    json.dump(report, f, indent=2)

# Also write summary text file
with open(os.path.join(validation_dir, 'validation_summary.txt'), 'w') as f:
    f.write(f"Validation Report for {domain}\n")
    f.write(f"Generated: {datetime.utcnow().isoformat()}Z\n")
    f.write("=" * 60 + "\n\n")
    f.write(f"Total Raw Findings: {total_raw}\n")
    f.write(f"Validated Findings: {validated_count}\n")
    f.write(f"False Positives Filtered: {fp_count}\n")
    f.write(f"False Positive Rate: {report['summary']['false_positive_rate']}%\n")
    f.write(f"Validation Rate: {report['summary']['validation_rate']}%\n\n")
    
    f.write("Severity Distribution:\n")
    for sev, count in severity_counts.most_common():
        f.write(f"  {sev.upper()}: {count}\n")
    f.write("\n")
    
    f.write("Risk Levels:\n")
    for risk, count in risk_levels.most_common():
        f.write(f"  {risk}: {count}\n")
    f.write("\n")
    
    f.write("Top Vulnerability Types:\n")
    for vtype, count in type_counts.most_common(10):
        f.write(f"  {vtype}: {count}\n")
    f.write("\n")
    
    f.write("Top 10 Findings:\n")
    for i, finding in enumerate(report['top_findings'], 1):
        f.write(f"  {i}. [{finding['severity']}] {finding['type']} - {finding['title']}\n")
        f.write(f"      Confidence: {finding['confidence']}, Risk: {finding['risk_level']}, Sources: {finding['source_count']}\n")
        f.write(f"      URL: {finding['url']}\n\n")

print(f"Validation report generated: {validated_file}")
PYEOF

    log "INFO" "Finding validation and correlation complete for $domain"
}

export -f validate_and_correlate_findings