#!/usr/bin/env bash
# Track 8: Reporting & Integration - HackerOne Template Phase
# HackerOne submission template generation, structured report output

hackerone_template_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        echo "Usage: hackerone_template_phase <domain>"
        return 1
    fi

    # Source core.sh if not already sourced
    if ! declare -F log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    # Set up output directory
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/hackerone_template"

    log "INFO" "Starting HackerOne template phase for $domain"

    # Check for required tools
    if ! tool_available "python3"; then
        log "ERROR" "python3 is required for HackerOne template phase"
        return 1
    fi

    # Initialize outputs
    local hackerone_report="$output_dir/hackerone_template/hackerone_report.md"
    local submission_ready="$output_dir/hackerone_template/submission_ready.txt"

    # Create HackerOne report template
    cat > "$hackerone_report" <<EOF
# HackerOne Submission Report

**Domain:** $domain
**Generated:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")
**Report ID:** AUTO-GENERATED

## Summary

**Title:** [Vulnerability Title]
**Severity:** [Critical/High/Medium/Low/Informational]
**CVSS Score:** [0.0 - 10.0]
**Weakness:** [CWE-XXX: Description]

## Vulnerability Details

**Type:** [e.g., XSS, SQLi, SSRF, etc.]
**Location:** [URL/Endpoint]
**Parameter:** [Affected parameter]
**Method:** [GET/POST/PUT/DELETE]

## Proof of Concept

### Steps to Reproduce

1. [Step 1]
2. [Step 2]
3. [Step 3]

### Request/Response

\`\`\`http
[HTTP Request]
\`\`\`

\`\`\`
[HTTP Response]
\`\`\`

### Impact

[Description of potential impact]

## Remediation

**Recommendation:** [Fix recommendation]
**Priority:** [Immediate/Short-term/Long-term]

## Classification

- **Weakness:** [CWE]
- **CWE ID:** [CWE-XXX]
- **OWASP Top 10:** [Category]

## Attachments

- [Screenshots]
- [Videos]
- [Code snippets]
EOF

    # Create submission ready file
    cat > "$submission_ready" <<EOF
Submission Readiness Check for $domain
=======================================
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

Checklist:
[ ] Vulnerability title defined
[ ] Severity level assigned
[ ] CVSS score calculated
[ ] Steps to reproduce clear
[ ] Proof of concept provided
[ ] Impact assessment included
[ ] Remediation recommendation added
[ ] Attachments prepared
[ ] Program scope verified
[ ] Disclosure policy reviewed

Status: TEMPLATE READY
Findings Ready for Submission: 0
EOF

    # Validate outputs
    if [[ -f "$hackerone_report" ]]; then
        log "INFO" "HackerOne report template created successfully"
        write_finding "$domain" "HACKERONE_TEMPLATE" "Report template generated" "info" "$output_dir/hackerone_template"
    else
        log "ERROR" "Failed to create HackerOne report template"
    fi

    if [[ -f "$submission_ready" ]]; then
        log "INFO" "Submission readiness file created"
        write_asset "$domain" "SUBMISSION_READY" "Template validation checklist" "$output_dir/hackerone_template"
    fi

    # Structured logging
    py_log "INFO" "hackerone_template" "Phase completed" \
        "domain=$domain" \
        "output_dir=$output_dir/hackerone_template" \
        "hackerone_report=$hackerone_report" \
        "submission_ready=$submission_ready"

    # Count results
    local result_count=2
    echo "$result_count" > "$output_dir/hackerone_template/count.txt"

    log "INFO" "HackerOne template phase completed for $domain"
    return 0
}