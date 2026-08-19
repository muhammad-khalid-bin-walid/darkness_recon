#!/usr/bin/env bash
# Track 8: Reporting & Integration - Write-up Library Phase
# Write-up library and methodology documentation, reusable templates

writeup_library_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        echo "Usage: writeup_library_phase <domain>"
        return 1
    fi

    # Source core.sh if not already sourced
    if ! declare -F log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    # Set up output directory
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/writeup_library"
    mkdir -p "$output_dir/writeup_library/writeup_templates"

    log "INFO" "Starting writeup library phase for $domain"

    # Check for required tools
    if ! tool_available "python3"; then
        log "ERROR" "python3 is required for writeup library phase"
        return 1
    fi

    # Initialize outputs
    local methodology_index="$output_dir/writeup_library/methodology_index.txt"

    # Create methodology index
    cat > "$methodology_index.txt" <<EOF
Write-up Library for $domain
============================
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

Methodology Categories:
1. Reconnaissance
   - Subdomain Enumeration
   - Port Scanning
   - Technology Fingerprinting
   - DNS Analysis
   - WHOIS Information

2. Vulnerability Discovery
   - SQL Injection
   - Cross-Site Scripting (XSS)
   - Server-Side Request Forgery (SSRF)
   - Remote Code Execution (RCE)
   - Local File Inclusion (LFI)
   - Remote File Inclusion (RFI)
   - Directory Traversal
   - Authentication Bypass
   - Authorization Bypass
   - Business Logic Flaws

3. Exploitation Techniques
   - Payload Construction
   - Encoding/Bypass Techniques
   - Privilege Escalation
   - Session Hijacking
   - Token Manipulation

4. Reporting
   - Title Writing
   - Impact Assessment
   - Remediation Guidance
   - Proof of Concept Documentation
   - Screenshot Best Practices

5. Platform-Specific
   - HackerOne Format
   - Bugcrowd Format
   - Intigriti Format
   - Custom Platform Format

Templates Available:
- sqli_report_template.md
- xss_report_template.md
- ssrf_report_template.md
- rce_report_template.md
- auth_bypass_template.md
- logic_flaw_template.md
- misconfig_template.md
- info_disclosure_template.md

Total Templates: 8
Last Updated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

    # Create writeup templates
    local templates_dir="$output_dir/writeup_library/writeup_templates"

    # SQL Injection template
    cat > "$templates_dir/sqli_report_template.md" <<EOF
# SQL Injection Report Template

**Title:** SQL Injection in [Parameter] at [URL]
**Severity:** [Critical/High/Medium/Low]
**CVSS:** [Score]

## Summary
[1-2 sentence description]

## Vulnerability Details
- **Type:** SQL Injection
- **Location:** [URL]
- **Parameter:** [Parameter]
- **Method:** [GET/POST]
- **Database:** [MySQL/PostgreSQL/SQLite/etc.]

## Proof of Concept
1. Navigate to [URL]
2. Enter payload: [payload]
3. Observe [response]

## Impact
[Business impact description]

## Remediation
[Fix recommendations]
EOF

    # XSS template
    cat > "$templates_dir/xss_report_template.md" <<EOF
# XSS Report Template

**Title:** [Reflected/Stored/DOM] XSS in [Parameter] at [URL]
**Severity:** [High/Medium/Low]
**CVSS:** [Score]

## Summary
[1-2 sentence description]

## Vulnerability Details
- **Type:** [Reflected/Stored/DOM] XSS
- **Location:** [URL]
- **Parameter:** [Parameter]
- **Context:** [HTML/Attribute/JavaScript/URL]

## Proof of Concept
1. Navigate to [URL]
2. Enter payload: [payload]
3. Observe execution

## Impact
[Impact on users]

## Remediation
[Input validation, output encoding recommendations]
EOF

    # SSRF template
    cat > "$templates_dir/ssrf_report_template.md" <<EOF
# SSRF Report Template

**Title:** Server-Side Request Forgery in [Parameter] at [URL]
**Severity:** [High/Medium/Low]
**CVSS:** [Score]

## Summary
[1-2 sentence description]

## Vulnerability Details
- **Type:** SSRF
- **Location:** [URL]
- **Parameter:** [Parameter]
- **Internal Resources Accessible:** [list]

## Proof of Concept
1. Navigate to [URL]
2. Enter payload: [internal URL]
3. Observe response

## Impact
[Internal network access, data exfiltration]

## Remediation
[URL validation, allowlist approach]
EOF

    # RCE template
    cat > "$templates_dir/rce_report_template.md" <<EOF
# RCE Report Template

**Title:** Remote Code Execution via [Vector] at [URL]
**Severity:** [Critical]
**CVSS:** [Score]

## Summary
[1-2 sentence description]

## Vulnerability Details
- **Type:** RCE
- **Location:** [URL]
- **Vector:** [Command injection/code injection/deserialization]

## Proof of Concept
1. Navigate to [URL]
2. Execute payload: [command]
3. Verify execution

## Impact
[Full system compromise]

## Remediation
[Input sanitization, sandboxing, privilege restriction]
EOF

    # Auth bypass template
    cat > "$templates_dir/auth_bypass_template.md" <<EOF
# Authentication Bypass Report Template

**Title:** Authentication Bypass via [Vector]
**Severity:** [Critical/High]
**CVSS:** [Score]

## Summary
[1-2 sentence description]

## Vulnerability Details
- **Type:** Authentication Bypass
- **Location:** [URL]
- **Method:** [Technique used]

## Proof of Concept
1. [Steps to bypass]
2. [Verification]

## Impact
[Unauthorized access]

## Remediation
[Proper authentication implementation]
EOF

    # Logic flaw template
    cat > "$templates_dir/logic_flaw_template.md" <<EOF
# Business Logic Flaw Report Template

**Title:** Business Logic Flaw in [Feature]
**Severity:** [Medium/Low]
**CVSS:** [Score]

## Summary
[1-2 sentence description]

## Vulnerability Details
- **Type:** Business Logic Flaw
- **Feature:** [Feature name]
- **Expected Behavior:** [What should happen]
- **Actual Behavior:** [What actually happens]

## Proof of Concept
1. [Steps to reproduce]
2. [Observation]

## Impact
[Business impact]

## Remediation
[Server-side validation, business rule enforcement]
EOF

    # Misconfig template
    cat > "$templates_dir/misconfig_template.md" <<EOF
# Security Misconfiguration Report Template

**Title:** Security Misconfiguration in [Component]
**Severity:** [Medium/Low]
**CVSS:** [Score]

## Summary
[1-2 sentence description]

## Vulnerability Details
- **Type:** Security Misconfiguration
- **Component:** [Server/Framework/Application]
- **Configuration:** [Misconfigured setting]

## Proof of Concept
1. [How to identify]
2. [Evidence]

## Impact
[Information disclosure, attack surface]

## Remediation
[Proper configuration, security hardening]
EOF

    # Info disclosure template
    cat > "$templates_dir/info_disclosure_template.md" <<EOF
# Information Disclosure Report Template

**Title:** Information Disclosure via [Vector]
**Severity:** [Low/Informational]
**CVSS:** [Score]

## Summary
[1-2 sentence description]

## Vulnerability Details
- **Type:** Information Disclosure
- **Location:** [URL/Header/Response]
- **Information:** [What is disclosed]

## Proof of Concept
1. [How to access]
2. [What is revealed]

## Impact
[Information leakage]

## Remediation
[Remove sensitive information, proper error handling]
EOF

    # Validate outputs
    if [[ -f "$methodology_index.txt" ]]; then
        log "INFO" "Methodology index created successfully"
        write_finding "$domain" "WRITEUP_LIBRARY" "Writeup library initialized" "info" "$output_dir/writeup_library"
    else
        log "ERROR" "Failed to create methodology index"
    fi

    if [[ -d "$templates_dir" ]]; then
        log "INFO" "Writeup templates directory created"
        write_asset "$domain" "WRITEUP_TEMPLATES" "Reusable writeup templates" "$output_dir/writeup_library"
    fi

    # Structured logging
    py_log "INFO" "writeup_library" "Phase completed" \
        "domain=$domain" \
        "output_dir=$output_dir/writeup_library" \
        "methodology_index=$methodology_index" \
        "templates_dir=$templates_dir"

    # Count results
    local result_count=8
    echo "$result_count" > "$output_dir/writeup_library/count.txt"

    log "INFO" "Writeup library phase completed for $domain"
    return 0
}