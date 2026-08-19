#!/usr/bin/env bash
# Phase 299: FAQ Generation, Common Issues, Troubleshooting Answers
# Track 21 - Documentation

docs_faq() {
    local domain="${1:?Usage: docs_faq <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/docs_faq"
    mkdir -p "$phase_dir"

    log "INFO" "[FAQ] Generating FAQ for $domain"

    local faq="$phase_dir/faq.md"
    local common_issues="$phase_dir/common_issues.txt"

    local count=0

    cat > "$faq" <<'FAEOF'
# DarkRecon FAQ

## General

### What is DarkRecon?
DarkRecon is a phase-based security reconnaissance framework organized into tracks and phases for automated security assessment.

### How do I run a scan?
```bash
darkrecon example.com
```

### What are phases?
Phases are individual units of work organized into tracks (Reconnaissance, Scanning, Analysis, etc.).

## Troubleshooting

### Why did my scan fail?
Check:
1. Tool availability (tool_available)
2. Network connectivity
3. Domain validity
4. Output directory permissions

### How do I enable verbose output?
Use the `--verbose` or `--debug` flags.

### What is count.txt?
A file in each phase directory showing the number of results found.

### How do I run a dry run?
```bash
darkrecon --dry-run example.com
```

### Where are results stored?
In the OUTPUT_DIR/domain/recon_TIMESTAMP/ directory.

## Compliance

### What compliance standards are supported?
- PCI-DSS
- GDPR
- SOC2
- ASVS

### How do I generate an audit report?
Run the compliance_audit_export phase.

## Collaboration

### How do multiple operators work together?
Use the collaboration phases (271-280) for coordination, shared review, and workload management.

## Configuration

### How do I change the output directory?
Set the OUTPUT_DIR environment variable:
```bash
export OUTPUT_DIR="/path/to/output"
```

### How do I customize scan profiles?
Use the `--profile` flag: quick, standard, thorough, custom.
FAEOF
    count=$((count + 1))

    log "INFO" "[FAQ] Generating common issues"
    {
        echo "=== Common Issues ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "1. Tool Not Found"
        echo "   Symptom: Phase skips tool execution"
        echo "   Fix: Install tool or check PATH"
        echo ""
        echo "2. Domain Unreachable"
        echo "   Symptom: All requests timeout"
        echo "   Fix: Check network, verify domain"
        echo ""
        echo "3. Permission Denied"
        echo "   Symptom: Cannot write output"
        echo "   Fix: Check OUTPUT_DIR permissions"
        echo ""
        echo "4. Rate Limited"
        echo "   Symptom: HTTP 429 responses"
        echo "   Fix: Add delays, reduce intensity"
        echo ""
        echo "5. Count Mismatch"
        echo "   Symptom: count.txt = 0 but findings exist"
        echo "   Fix: Ensure count.txt is last write"
        echo ""
        echo "6. Memory Error"
        echo "   Symptom: Process killed"
        echo "   Fix: Reduce scan scope, increase limits"
        echo ""
        echo "7. SSL Error"
        echo "   Symptom: Certificate verification failed"
        echo "   Fix: Check certificate validity"
        echo ""
        echo "8. No Output"
        echo "   Symptom: Empty phase directory"
        echo "   Fix: Check phase implementation"
    } > "$common_issues"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "FAQ" "FAQ generated" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "faq_complete" "FAQ generation complete: $count items"
    log "INFO" "[FAQ] Completed: $count items generated"

    return 0
}
