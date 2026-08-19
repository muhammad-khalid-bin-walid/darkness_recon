#!/bin/bash
# Scope & Program Analysis phase - Understand authorization and boundaries

scope_program_analysis_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/scope"

    mkdir -p "$output_dir"

    log "INFO" "Starting scope and program analysis for $domain"

    # ===== PROGRAM RULES EXTRACTION =====
    log "INFO" "Extracting program rules and scope boundaries..."

    local scope_file="$output_dir/scope_rules.txt"
    local in_scope_file="$output_dir/in_scope_assets.txt"
    local out_of_scope_file="$output_dir/out_of_scope_assets.txt"

    # Extract scope rules from common bug bounty platforms
    python3 -c "
import json, os, sys

scope_data = {
    'domain': '$domain',
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'scope_rules': [],
    'in_scope': [],
    'out_of_scope': [],
    'test_types': [],
    'restricted_areas': [],
    'authorization_boundaries': []
}

# Common scope rule patterns to look for
scope_keywords = [
    'in scope', 'out of scope', 'restricted', 'authorization',
    'test type', 'allowed', 'prohibited', 'boundary', 'engagement',
    'rules of engagement', 'scope document', 'program policy'
]

# Check for scope files in output directory
for root, dirs, files in os.walk('$OUTPUT_DIR/$domain/recon_$TIMESTAMP'):
    for f in files:
        if any(kw in f.lower() for kw in ['scope', 'policy', 'rules', 'engagement']):
            filepath = os.path.join(root, f)
            try:
                with open(filepath) as fh:
                    content = fh.read()
                    for keyword in scope_keywords:
                        if keyword in content.lower():
                            scope_data['scope_rules'].append({
                                'file': filepath,
                                'keyword': keyword,
                                'context': content[content.lower().find(keyword):content.lower().find(keyword)+200].strip()
                            })
            except:
                pass

with open('$output_dir/scope_analysis.json', 'w') as f:
    json.dump(scope_data, f, indent=2)
" 2>/dev/null || true

    # ===== TARGET CLASSIFICATION =====
    log "INFO" "Classifying target type and value..."

    python3 -c "
import json, os

try:
    # Analyze the domain to classify target type
    domain = '$domain'

    # Common target classifications
    target_types = {
        'ecommerce': ['shop', 'store', 'buy', 'cart', 'checkout', 'payment', 'order'],
        'finance': ['bank', 'finance', 'trade', 'invest', 'crypto', 'wallet', 'exchange'],
        'healthcare': ['health', 'medical', 'patient', 'clinic', 'hospital', 'pharmacy'],
        'social': ['social', 'chat', 'forum', 'community', 'network', 'media'],
        'enterprise': ['corp', 'enterprise', 'business', 'company', 'org', 'admin'],
        'government': ['gov', 'government', 'city', 'state', 'federal', 'agency'],
        'education': ['school', 'university', 'college', 'edu', 'academic', 'student'],
        'technology': ['tech', 'software', 'app', 'platform', 'api', 'cloud', 'dev'],
        'gaming': ['game', 'gaming', 'play', 'casino', 'bet', 'lottery'],
        'travel': ['travel', 'hotel', 'flight', 'booking', 'tourism', 'trip']
    }

    classification = []
    for target_type, keywords in target_types.items():
        for keyword in keywords:
            if keyword in domain.lower():
                classification.append(target_type)
                break

    # Also check for subdomains that indicate target type
    subdomains_file = '$OUTPUT_DIR/$domain/recon_$TIMESTAMP/subdomains/all_subdomains.txt'
    if os.path.exists(subdomains_file):
        with open(subdomains_file) as f:
            subs = [l.strip() for l in f if l.strip()]
        for sub in subs[:50]:
            for target_type, keywords in target_types.items():
                for keyword in keywords:
                    if keyword in sub.lower() and target_type not in classification:
                        classification.append(target_type)

    result = {
        'domain': domain,
        'target_classifications': classification,
        'high_value_indicators': len(classification) > 0,
        'recommended_test_types': ['sql_injection', 'xss', 'idor', 'business_logic', 'auth'],
        'verification': {'method': 'target_classification', 'confidence': 'medium', 'status': 'review_required'}
    }

    with open('$output_dir/target_classification.json', 'w') as f:
        json.dump(result, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true

    # ===== RESTRICTED AREA IDENTIFICATION =====
    log "INFO" "Identifying restricted areas and boundaries..."

    if [ -f "$output_dir/scope_analysis.json" ]; then
        python3 -c "
import json, os

try:
    with open('$output_dir/scope_analysis.json') as f:
        data = json.load(f)

    # Common restricted patterns
    restricted_patterns = [
        'admin', 'login', 'auth', 'oauth', 'sso', 'mfa', '2fa',
        'payment', 'billing', 'checkout', 'transaction', 'bank',
        'medical', 'health', 'phi', 'hipaa', 'patient',
        'password', 'credential', 'secret', 'key', 'token',
        'internal', 'private', 'staging', 'dev', 'test', 'debug'
    ]

    restricted = []
    for rule in data.get('scope_rules', []):
        for pattern in restricted_patterns:
            if pattern in rule.get('context', '').lower():
                restricted.append({
                    'pattern': pattern,
                    'context': rule.get('context', '')[:200],
                    'source': rule.get('file', '')
                })

    data['restricted_areas'] = restricted

    with open('$output_dir/scope_analysis.json', 'w') as f:
        json.dump(data, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true
    fi

    # ===== SCOPE VALIDATION =====
    log "INFO" "Validating scope boundaries..."

    python3 -c "
import json, os

try:
    scope_file = '$output_dir/scope_analysis.json'
    if not os.path.exists(scope_file):
        scope_data = {'domain': '$domain', 'scope_validated': False}
    else:
        with open(scope_file) as f:
            scope_data = json.load(f)

    # Check for common scope violations
    violations = []
    for rule in scope_data.get('scope_rules', []):
        context = rule.get('context', '')
        if 'out of scope' in context.lower():
            violations.append({'type': 'out_of_scope', 'detail': context[:200]})
        if 'prohibited' in context.lower():
            violations.append({'type': 'prohibited', 'detail': context[:200]})
        if 'restricted' in context.lower():
            violations.append({'type': 'restricted', 'detail': context[:200]})

    scope_data['violations'] = violations
    scope_data['scope_validated'] = len(violations) == 0

    with open(scope_file, 'w') as f:
        json.dump(scope_data, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true

    log "INFO" "Scope and program analysis completed for $domain"

    write_finding "{\"type\":\"scope_program\",\"severity\":\"info\",\"domain\":\"$domain\",\"phase\":\"scope_program_analysis\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "scope_program_analysis_phase" "Completed for $domain"
}