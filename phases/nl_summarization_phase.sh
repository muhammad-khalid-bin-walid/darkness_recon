#!/bin/bash
# Track 9 - ML/Triage/Future: Natural language summarization of findings, executive summary generation

nl_summarization_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/nl_summarization"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting NL summarization phase for $domain"
    py_log "INFO" "nl_summarization_phase_start" --phase "nl_summarization" --target "$domain" 2>/dev/null || true

    local summaries_json="$phase_dir/summaries.json"
    local executive_summary="$phase_dir/executive_summary.md"
    local count=0

    log "INFO" "Generating natural language summaries of scan results..."

    python3 -c "
import json, os, sys
from collections import Counter, defaultdict

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'

# Collect all findings from all phases
all_findings = []
phase_summaries = defaultdict(list)
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
                                phase_summaries[entry].append(item)
                except:
                    pass

# Aggregate metrics
severity_counts = Counter()
phase_counts = Counter()
type_counts = Counter()

for finding in all_findings:
    sev = finding.get('severity', finding.get('level', 'info'))
    severity_counts[str(sev).lower()] += 1
    phase_counts[finding.get('_source_phase', 'unknown')] += 1
    ftype = finding.get('type', finding.get('finding', 'unknown'))
    type_counts[str(ftype)] += 1

# Generate per-phase summaries
summaries = {}
for phase, findings in phase_summaries.items():
    phase_sevs = Counter(f.get('severity', f.get('level', 'info')) for f in findings)
    summaries[phase] = {
        'total_findings': len(findings),
        'severity_breakdown': dict(phase_sevs),
        'top_types': type_counts.most_common(5) if phase == list(phase_summaries.keys())[0] else [],
        'summary_text': f\"Phase {phase} produced {len(findings)} findings.\"
    }

# Generate executive summary
total = len(all_findings)
critical = severity_counts.get('critical', 0)
high = severity_counts.get('high', 0)
medium = severity_counts.get('medium', 0)
low = severity_counts.get('low', 0)
info_count = severity_counts.get('info', 0)

exec_lines = []
exec_lines.append(f'# Executive Summary - {domain}')
exec_lines.append(f'')
exec_lines.append(f'**Scan Date:** {\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}')
exec_lines.append(f'**Target:** {domain}')
exec_lines.append(f'**Total Findings:** {total}')
exec_lines.append(f'')
exec_lines.append(f'## Overview')
exec_lines.append(f'')
exec_lines.append(f'The reconnaissance scan of **{domain}** identified **{total}** findings across **{len(phase_summaries)}** scan phases.')
exec_lines.append(f'')

if critical > 0:
    exec_lines.append(f'### Critical Findings ({critical})')
    exec_lines.append(f'There are **{critical} critical severity** findings that require immediate attention. These may include remote code execution, SQL injection, exposed credentials, or authentication bypass vulnerabilities.')
    exec_lines.append(f'')

if high > 0:
    exec_lines.append(f'### High Severity Findings ({high})')
    exec_lines.append(f'**{high} high severity** findings were identified that should be addressed promptly. These include cross-site scripting, CSRF, SSRF, and other significant security issues.')
    exec_lines.append(f'')

exec_lines.append(f'## Severity Breakdown')
exec_lines.append(f'')
exec_lines.append(f'| Severity | Count |')
exec_lines.append(f'|----------|-------|')
for sev in ['critical', 'high', 'medium', 'low', 'info']:
    exec_lines.append(f'| {sev.capitalize()} | {severity_counts.get(sev, 0)} |')
exec_lines.append(f'')

exec_lines.append(f'## Phase Summary')
exec_lines.append(f'')
exec_lines.append(f'| Phase | Findings |')
exec_lines.append(f'|-------|----------|')
for phase, count in sorted(phase_counts.items(), key=lambda x: x[1], reverse=True):
    exec_lines.append(f'| {phase} | {count} |')
exec_lines.append(f'')

exec_lines.append(f'## Recommendations')
exec_lines.append(f'')
if critical > 0:
    exec_lines.append(f'1. **Immediate Action Required:** Address {critical} critical severity findings.')
if high > 0:
    exec_lines.append(f'2. **Priority Remediation:** Schedule fixes for {high} high severity findings within 48 hours.')
if medium > 0:
    exec_lines.append(f'3. **Planned Remediation:** Address {medium} medium severity findings in the next sprint.')
exec_lines.append(f'4. **Continuous Monitoring:** Re-scan periodically to detect new vulnerabilities.')
exec_lines.append(f'5. **False Positive Review:** Manually verify low-confidence findings before marking as resolved.')

# Write outputs
with open(os.path.join(phase_dir, 'summaries.json'), 'w') as f:
    json.dump({'domain': domain, 'total_findings': total, 'phase_summaries': summaries}, f, indent=2, default=str)

with open(os.path.join(phase_dir, 'executive_summary.md'), 'w') as f:
    f.write('\n'.join(exec_lines))

print(len(all_findings))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$summaries_json" ]; then
        write_finding "{\"type\":\"nl_summarization_complete\",\"target\":\"$domain\",\"findings_summarized\":$count,\"method\":\"aggregated_summary\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_summary.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "NL summarization phase complete: $count findings summarized for $domain"
    py_log "INFO" "nl_summarization_phase_complete" --phase "nl_summarization" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
