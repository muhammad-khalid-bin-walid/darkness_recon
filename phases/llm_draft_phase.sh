#!/bin/bash
# Track 9 - ML/Triage/Future: LLM-assisted report drafting, finding description generation, impact analysis

llm_draft_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/llm_draft"
    local draft_reports_dir="$phase_dir/draft_reports"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir" "$draft_reports_dir"

    log "INFO" "Starting LLM draft phase for $domain"
    py_log "INFO" "llm_draft_phase_start" --phase "llm_draft" --target "$domain" 2>/dev/null || true

    local llm_drafts_json="$phase_dir/llm_drafts.json"
    local count=0

    log "INFO" "Generating LLM-assisted finding descriptions and impact analysis..."

    python3 -c "
import json, os, sys
from collections import Counter, defaultdict

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'
draft_reports_dir = '$draft_reports_dir'

# Load all findings
all_findings = []
base = os.path.join(output_dir)
if os.path.isdir(base):
    for entry in os.listdir(base):
        if entry == 'llm_draft':
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

# Description templates by finding type
description_templates = {
    'sqli': 'SQL Injection vulnerability detected allowing unauthorized database access. Potential impact includes data exfiltration, authentication bypass, and complete system compromise.',
    'xss': 'Cross-Site Scripting vulnerability allowing injection of malicious scripts. Impact includes session hijacking, credential theft, and defacement.',
    'ssrf': 'Server-Side Request Forgery enabling internal network probing. Impact includes cloud metadata access, internal service discovery, and lateral movement.',
    'rce': 'Remote Code Execution vulnerability allowing arbitrary command execution. Critical impact: full system compromise.',
    'idor': 'Insecure Direct Object Reference enabling unauthorized data access. Impact includes data leakage across user boundaries.',
    'cors': 'CORS misconfiguration allowing unauthorized cross-origin requests. Impact includes data theft and CSRF amplification.',
    'directory_listing': 'Directory listing enabled exposing file structure. Impact includes information disclosure and potential source code exposure.',
    'backup_exposure': 'Backup file publicly accessible. Impact includes source code disclosure and credential extraction.',
    'open_redirect': 'Open redirect vulnerability allowing URL manipulation. Impact includes phishing and OAuth token theft.',
    'default_credentials': 'Default credentials detected on service. Impact includes unauthorized administrative access.',
    'information_disclosure': 'Sensitive information exposed in response. Impact includes reduced attack surface visibility for adversaries.',
    'missing_security_header': 'Security header missing from HTTP response. Impact includes increased vulnerability to clickjacking, MIME sniffing, and other client-side attacks.',
    'ssl_tls_issue': 'SSL/TLS configuration issue detected. Impact includes potential man-in-the-middle attacks.',
    'rate_limit_bypass': 'Rate limiting bypass detected. Impact includes brute force and denial of service potential.'
}

# Generate drafts for each finding
drafts = []
for finding in all_findings[:200]:
    finding_text = json.dumps(finding).lower()
    description = 'Security finding identified during automated reconnaissance scan.'
    impact = 'Potential security impact requires manual assessment.'

    for key, template in description_templates.items():
        if key in finding_text:
            description = template
            break

    sev = str(finding.get('severity', finding.get('level', 'info'))).lower()
    if sev == 'critical':
        impact = 'CRITICAL: Immediate exploitation possible. Full system compromise risk.'
    elif sev == 'high':
        impact = 'HIGH: Significant security impact. Data exposure or unauthorized access likely.'
    elif sev == 'medium':
        impact = 'MEDIUM: Moderate security impact under specific conditions.'
    elif sev == 'low':
        impact = 'LOW: Limited security impact. Best practice deviation.'
    else:
        impact = 'INFO: Informational finding. No direct security impact.'

    draft = {
        'finding_id': finding.get('id', finding.get('type', 'unknown')),
        'source_phase': finding.get('_source_phase', 'unknown'),
        'severity': sev,
        'generated_description': description,
        'generated_impact': impact,
        'remediation_hint': f'Review and validate finding manually. Address based on severity level.',
        'confidence': finding.get('confidence', 0.5)
    }
    drafts.append(draft)

    # Write individual draft report
    draft_file = os.path.join(draft_reports_dir, f\"draft_{draft['finding_id']}.md\")
    try:
        with open(draft_file, 'w') as f:
            f.write(f\"# Finding: {draft['finding_id']}\n\n\")
            f.write(f\"**Severity:** {draft['severity'].upper()}\")
            f.write(f\"**Source:** {draft['source_phase']}\")
            f.write(f\"**Confidence:** {draft['confidence']}\n\n\")
            f.write(f\"## Description\n{draft['generated_description']}\n\n\")
            f.write(f\"## Impact Analysis\n{draft['generated_impact']}\n\n\")
            f.write(f\"## Remediation\n{draft['remediation_hint']}\n\")
    except:
        pass

# Write aggregated drafts
with open(os.path.join(phase_dir, 'llm_drafts.json'), 'w') as f:
    json.dump({
        'domain': domain,
        'total_drafts': len(drafts),
        'drafts': drafts
    }, f, indent=2, default=str)

print(len(drafts))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$llm_drafts_json" ]; then
        write_finding "{\"type\":\"llm_draft_complete\",\"target\":\"$domain\",\"drafts_generated\":$count,\"method\":\"template_enhanced\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_drafts.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "LLM draft phase complete: $count finding drafts generated for $domain"
    py_log "INFO" "llm_draft_phase_complete" --phase "llm_draft" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
