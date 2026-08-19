#!/usr/bin/env bash
# Track 8: Reporting & Integration - Bugcrowd Template Phase
# Bugcrowd submission template generation, VRT mapping

bugcrowd_template_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        echo "Usage: bugcrowd_template_phase <domain>"
        return 1
    fi

    # Source core.sh if not already sourced
    if ! declare -F log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    # Set up output directory
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/bugcrowd_template"

    log "INFO" "Starting Bugcrowd template phase for $domain"

    # Check for required tools
    if ! tool_available "python3"; then
        log "ERROR" "python3 is required for Bugcrowd template phase"
        return 1
    fi

    # Initialize outputs
    local bugcrowd_report="$output_dir/bugcrowd_template/bugcrowd_report.md"
    local vrt_mapping="$output_dir/bugcrowd_template/vrt_mapping.txt"

    # Create Bugcrowd report template
    cat > "$bugcrowd_report" <<EOF
# Bugcrowd Submission Report

**Domain:** $domain
**Generated:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")
**Report ID:** AUTO-GENERATED

## VRT (Vulnerability Rating Taxonomy)

**VRT Category:** [Category]
**VRT Subcategory:** [Subcategory]
**VRT Variant:** [Variant]
**Rating:** [Critical/High/Medium/Low/Pending/Informational]

## Vulnerability Summary

**Title:** [Vulnerability Title]
**Description:** [Brief description]
**Impact:** [Business/Technical impact]

## Details

**Affected URL:** [URL]
**Affected Parameter:** [Parameter]
**HTTP Method:** [Method]
**Authentication Required:** [Yes/No]

## Proof of Concept

### Reproduction Steps

1. [Step 1]
2. [Step 2]
3. [Step 3]

### Request Details

\`\`\`http
[HTTP Request]
\`\`\`

### Response Details

\`\`\`
[HTTP Response]
\`\`\`

## Supporting Material

- [Screenshots]
- [Code Analysis]
- [Tool Output]

## Remediation Guidance

**Fix:** [Remediation steps]
**Best Practice:** [Security best practice reference]
EOF

    # Create VRT mapping file
    cat > "$vrt_mapping" <<EOF
VRT Mapping for Bugcrowd Submission
====================================
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

VRT Categories:
- 1342 - Authentication Bypass
- 1344 - Broken Authentication
- 1345 - Broken Access Control
- 1346 - Security Misconfiguration
- 1347 - Cross-Site Scripting (XSS)
- 1348 - SQL Injection
- 1349 - Command Injection
- 1350 - Code Injection
- 1351 - Local/Remote Code Execution
- 1352 - File Inclusion
- 1353 - Path Traversal
- 1354 - Open Redirect
- 1355 - Information Disclosure
- 1356 - Denial of Service
- 1357 - CSRF
- 1358 - Race Condition
- 1359 - Cryptographic Issues
- 1360 - Business Logic

Severity Mapping:
- Critical: CVSS 9.0 - 10.0
- High: CVSS 7.0 - 8.9
- Medium: CVSS 4.0 - 6.9
- Low: CVSS 0.1 - 3.9
- Informational: CVSS 0.0

Findings Mapped: 0
EOF

    # Validate outputs
    if [[ -f "$bugcrowd_report" ]]; then
        log "INFO" "Bugcrowd report template created successfully"
        write_finding "$domain" "BUGCROWD_TEMPLATE" "Report template generated" "info" "$output_dir/bugcrowd_template"
    else
        log "ERROR" "Failed to create Bugcrowd report template"
    fi

    if [[ -f "$vrt_mapping" ]]; then
        log "INFO" "VRT mapping file created"
        write_asset "$domain" "VRT_MAPPING" "Bugcrowd VRT taxonomy mapping" "$output_dir/bugcrowd_template"
    fi

    # Structured logging
    py_log "INFO" "bugcrowd_template" "Phase completed" \
        "domain=$domain" \
        "output_dir=$output_dir/bugcrowd_template" \
        "bugcrowd_report=$bugcrowd_report" \
        "vrt_mapping=$vrt_mapping"

    # Count results
    local result_count=2
    echo "$result_count" > "$output_dir/bugcrowd_template/count.txt"

    log "INFO" "Bugcrowd template phase completed for $domain"
    return 0
}