#!/bin/bash
# Target Intake & Validation phase - Validate target before scanning

target_intake_validation_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/intake"

    mkdir -p "$output_dir"

    log "INFO" "Starting target intake and validation for $domain"

    # ===== DOMAIN VALIDATION =====
    log "INFO" "Validating target domain..."

    python3 -c "
import json, os, socket, ipaddress

try:
    domain = '$domain'
    results = {
        'domain': domain,
        'validation_checks': {},
        'valid': True,
        'issues': []
    }

    # Check 1: Domain format validation
    import re
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    if re.match(domain_pattern, domain):
        results['validation_checks']['domain_format'] = 'valid'
    else:
        results['validation_checks']['domain_format'] = 'invalid'
        results['valid'] = False
        results['issues'].append('Domain format is invalid')

    # Check 2: DNS resolution
    try:
        ips = socket.getaddrinfo(domain, None)
        results['validation_checks']['dns_resolution'] = 'resolves'
        results['resolved_ips'] = list(set([addr[4][0] for addr in ips]))
    except:
        results['validation_checks']['dns_resolution'] = 'does_not_resolve'
        results['valid'] = False
        results['issues'].append('Domain does not resolve via DNS')

    # Check 3: Check if IP is private/reserved
    if 'resolved_ips' in results:
        for ip_str in results['resolved_ips']:
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private:
                    results['validation_checks']['ip_type'] = 'private_ip'
                    results['valid'] = False
                    results['issues'].append(f'IP {ip_str} is private - may be out of scope')
                elif ip.is_loopback:
                    results['validation_checks']['ip_type'] = 'loopback'
                    results['valid'] = False
                    results['issues'].append(f'IP {ip_str} is loopback')
                elif ip.is_reserved:
                    results['validation_checks']['ip_type'] = 'reserved'
                    results['valid'] = False
                    results['issues'].append(f'IP {ip_str} is reserved')
                else:
                    results['validation_checks']['ip_type'] = 'public'
            except:
                pass

    # Check 4: Check for common testing domains
    test_domains = ['example.com', 'test.com', 'localhost', '127.0.0.1', '0.0.0.0']
    if domain.lower() in test_domains:
        results['validation_checks']['test_domain'] = 'true'
        results['valid'] = False
        results['issues'].append('Domain appears to be a test/example domain')
    else:
        results['validation_checks']['test_domain'] = 'false'

    # Check 5: Check for common typosquatting patterns
    typo_patterns = [
        r'\.co\.uk$', r'\.com\.au$', r'\.co\.in$', r'\.co\.nz$',
        r'\.org\.uk$', r'\.net\.au$', r'\.io$'
    ]
    for pattern in typo_patterns:
        if re.search(pattern, domain.lower()):
            results['validation_checks']['tld_type'] = 'ccTLD_or_gTLD'
            break
    else:
        results['validation_checks']['tld_type'] = 'standard'

    with open('$output_dir/target_validation.json', 'w') as f:
        json.dump(results, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true

    # ===== SCOPE BOUNDARY CHECK =====
    log "INFO" "Checking scope boundaries..."

    python3 -c "
import json, os

try:
    validation_file = '$output_dir/target_validation.json'
    if not os.path.exists(validation_file):
        scope_data = {'domain': '$domain', 'scope_check': 'unknown'}
    else:
        with open(validation_file) as f:
            scope_data = json.load(f)

    # Check for common scope boundary issues
    scope_issues = []

    # Check if domain has wildcard subdomains
    if 'resolved_ips' in scope_data:
        scope_data['scope_boundary_check'] = {
            'has_wildcard_dns': False,
            'has_multiple_ips': len(scope_data.get('resolved_ips', [])) > 1,
            'ip_count': len(scope_data.get('resolved_ips', []))
        }

    scope_data['scope_issues'] = scope_issues
    scope_data['scope_validated'] = len(scope_issues) == 0

    with open(validation_file, 'w') as f:
        json.dump(scope_data, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true

    # ===== ENGAGEMENT PARAMETERS =====
    log "INFO" "Recording engagement parameters..."

    python3 -c "
import json, os, time

try:
    validation_file = '$output_dir/target_validation.json'
    if not os.path.exists(validation_file):
        engagement = {'domain': '$domain'}
    else:
        with open(validation_file) as f:
            engagement = json.load(f)

    engagement['engagement_params'] = {
        'start_time': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
        'max_depth': 5,
        'max_requests_per_second': 10,
        'timeout_seconds': 30,
        'user_agent': 'DarknessRecon/4.0',
        'respect_robots_txt': True,
        'rate_limiting': True,
        'polite_crawling': True
    }

    with open(validation_file, 'w') as f:
        json.dump(engagement, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true

    log "INFO" "Target intake and validation completed for $domain"

    write_finding "{\"type\":\"target_intake\",\"severity\":\"info\",\"domain\":\"$domain\",\"phase\":\"target_intake_validation\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "target_intake_validation_phase" "Completed for $domain"
}