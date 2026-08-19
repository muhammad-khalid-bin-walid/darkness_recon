#!/bin/bash
# Track 9 - ML/Triage/Future: Knowledge base management, methodology storage, institutional memory

knowledge_base_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/knowledge_base"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting knowledge base phase for $domain"
    py_log "INFO" "knowledge_base_phase_start" --phase "knowledge_base" --target "$domain" 2>/dev/null || true

    local knowledge_base_json="$phase_dir/knowledge_base.json"
    local methodology_index="$phase_dir/methodology_index.txt"
    local count=0

    # Persistent knowledge base directory
    local kb_dir="$OUTPUT_DIR/$domain/knowledge_base"
    mkdir -p "$kb_dir" 2>/dev/null || true

    log "INFO" "Building and updating knowledge base..."

    python3 -c "
import json, os, sys, time
from collections import Counter, defaultdict

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'
kb_dir = '$kb_dir'

# Load existing knowledge base if available
kb_file = os.path.join(kb_dir, 'knowledge_base.json')
existing_kb = {}
if os.path.isfile(kb_file):
    try:
        with open(kb_file) as f:
            existing_kb = json.load(f)
    except:
        pass

# Collect current scan knowledge
current_knowledge = {
    'scan_findings': Counter(),
    'phases_executed': [],
    'tools_used': set(),
    'technologies_detected': set(),
    'attack_surface': {
        'subdomains': set(),
        'ip_addresses': set(),
        'endpoints': set(),
        'cloud_services': set()
    },
    'vulnerability_patterns': Counter(),
    'methodology_log': []
}

# Ingest findings
base = os.path.join(output_dir)
if os.path.isdir(base):
    for entry in os.listdir(base):
        if entry in ('knowledge_base',):
            continue
        pdir = os.path.join(base, entry)
        if not os.path.isdir(pdir):
            continue
        current_knowledge['phases_executed'].append(entry)
        for f in os.listdir(pdir):
            fpath = os.path.join(pdir, f)
            if f.endswith('.json'):
                try:
                    with open(fpath) as fh:
                        data = json.load(fh)
                        items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
                        for item in items:
                            if isinstance(item, dict):
                                sev = str(item.get('severity', item.get('level', 'info'))).lower()
                                current_knowledge['scan_findings'][sev] += 1
                                ftype = str(item.get('type', item.get('finding', 'unknown')))
                                current_knowledge['vulnerability_patterns'][ftype] += 1
                                # Extract assets
                                host = item.get('host', item.get('subdomain', item.get('domain', '')))
                                if host:
                                    current_knowledge['attack_surface']['subdomains'].add(str(host))
                                ip = item.get('ip', item.get('address', ''))
                                if ip:
                                    current_knowledge['attack_surface']['ip_addresses'].add(str(ip))
                                url = item.get('url', item.get('endpoint', ''))
                                if url:
                                    current_knowledge['attack_surface']['endpoints'].add(str(url)[:200])
                                tech = item.get('technology', item.get('tech', ''))
                                if tech:
                                    current_knowledge['technologies_detected'].add(str(tech))
                except:
                    pass
            elif f.endswith('.txt'):
                try:
                    with open(fpath) as fh:
                        for line in fh:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                if entry == 'subdomains':
                                    current_knowledge['attack_surface']['subdomains'].add(line)
                                elif entry == 'ports':
                                    pass
                except:
                    pass

# Merge with existing knowledge
merged_kb = {
    'domain': domain,
    'last_updated': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'total_scans_recorded': existing_kb.get('total_scans_recorded', 0) + 1,
    'knowledge_summary': {
        'total_findings_seen': sum(current_knowledge['scan_findings'].values()),
        'severity_distribution': dict(current_knowledge['scan_findings']),
        'unique_vulnerability_types': len(current_knowledge['vulnerability_patterns']),
        'phases_catalogued': list(set(current_knowledge['phases_executed'] + existing_kb.get('knowledge_summary', {}).get('phases_catalogued', []))),
        'attack_surface_snapshot': {
            'subdomains': len(current_knowledge['attack_surface']['subdomains']),
            'ip_addresses': len(current_knowledge['attack_surface']['ip_addresses']),
            'endpoints': len(current_knowledge['attack_surface']['endpoints'])
        }
    },
    'top_vulnerability_patterns': [
        {'type': t, 'count': c}
        for t, c in current_knowledge['vulnerability_patterns'].most_common(20)
    ],
    'technologies_catalogued': list(current_knowledge['technologies_detected'])[:50],
    'methodology_index': current_knowledge['phases_executed'],
    'institutional_memory': {
        'first_scan_date': existing_kb.get('institutional_memory', {}).get('first_scan_date', '$(date -u +%Y-%m-%dT%H:%M:%SZ)'),
        'total_scans': existing_kb.get('institutional_memory', {}).get('total_scans', 0) + 1,
        'historical_findings_count': existing_kb.get('institutional_memory', {}).get('historical_findings_count', 0) + sum(current_knowledge['scan_findings'].values()),
        'lessons_learned': existing_kb.get('institutional_memory', {}).get('lessons_learned', [])
    }
}

# Add lesson learned from this scan
total_crit = current_knowledge['scan_findings'].get('critical', 0)
if total_crit > 0:
    merged_kb['institutional_memory']['lessons_learned'].append({
        'date': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
        'lesson': f'Found {total_crit} critical vulnerabilities - prioritize immediate remediation',
        'scan_number': merged_kb['total_scans_recorded']
    })

# Save to persistent KB
try:
    with open(kb_file, 'w') as f:
        json.dump(merged_kb, f, indent=2, default=str)
except:
    pass

# Write phase-local knowledge base
with open(os.path.join(phase_dir, 'knowledge_base.json'), 'w') as f:
    json.dump(merged_kb, f, indent=2, default=str)

# Write methodology index
with open(os.path.join(phase_dir, 'methodology_index.txt'), 'w') as f:
    f.write(f'Knowledge Base Index - {domain}\n')
    f.write('=' * 50 + '\n\n')
    f.write(f'Total scans recorded: {merged_kb[\"total_scans_recorded\"]}\n')
    f.write(f'Last updated: {merged_kb[\"last_updated\"]}\n\n')
    f.write('Methodology Index (Phases Catalogued):\n')
    for i, phase in enumerate(sorted(set(current_knowledge['phases_executed'])), 1):
        f.write(f'  {i}. {phase}\n')
    f.write(f'\nTop Vulnerability Patterns:\n')
    for vp in merged_kb['top_vulnerability_patterns'][:10]:
        f.write(f\"  {vp['type']}: {vp['count']} occurrences\n\")
    f.write(f'\nTechnologies Detected:\n')
    for tech in merged_kb['technologies_catalogued'][:20]:
        f.write(f'  - {tech}\n')
    f.write(f'\nAttack Surface:\n')
    f.write(f\"  Subdomains: {merged_kb['knowledge_summary']['attack_surface_snapshot']['subdomains']}\n\")
    f.write(f\"  IP Addresses: {merged_kb['knowledge_summary']['attack_surface_snapshot']['ip_addresses']}\n\")
    f.write(f\"  Endpoints: {merged_kb['knowledge_summary']['attack_surface_snapshot']['endpoints']}\n\")
    f.write(f'\nInstitutional Memory:\n')
    f.write(f\"  First scan: {merged_kb['institutional_memory']['first_scan_date']}\n\")
    f.write(f\"  Total scans: {merged_kb['institutional_memory']['total_scans']}\n\")
    f.write(f\"  Historical findings: {merged_kb['institutional_memory']['historical_findings_count']}\n\")
    if merged_kb['institutional_memory']['lessons_learned']:
        f.write('  Lessons Learned:\n')
        for ll in merged_kb['institutional_memory']['lessons_learned'][-5:]:
            f.write(f\"    [{ll['date']}] {ll['lesson']}\n\")

print(merged_kb['total_scans_recorded'])
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    if [ -f "$knowledge_base_json" ]; then
        write_finding "{\"type\":\"knowledge_base_updated\",\"target\":\"$domain\",\"scans_recorded\":$count,\"method\":\"institutional_memory\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_knowledge.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Knowledge base phase complete: $count scans recorded for $domain"
    py_log "INFO" "knowledge_base_phase_complete" --phase "knowledge_base" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
