#!/usr/bin/env bash
# Phase 293: Operational Runbooks, Troubleshooting Guides, Incident Response
# Track 21 - Documentation

docs_runbooks() {
    local domain="${1:?Usage: docs_runbooks <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/docs_runbooks"
    mkdir -p "$phase_dir/runbooks"

    log "INFO" "[RUNBOOKS] Generating operational runbooks for $domain"

    local troubleshooting_guide="$phase_dir/troubleshooting_guide.txt"

    local count=0

    cat > "$phase_dir/runbooks/scan_troubleshooting.md" <<'RBEOF'
# Scan Troubleshooting Runbook

## Common Issues

### 1. Tool Not Available
**Symptom:** Phase skips tool execution
**Cause:** Required tool not installed
**Resolution:**
- Check tool availability: `tool_available "toolname"`
- Install missing tool
- Verify PATH configuration

### 2. Domain Unreachable
**Symptom:** All requests timeout
**Cause:** Network issue or domain down
**Resolution:**
- Check network connectivity
- Verify domain resolves: `dig example.com`
- Try with --debug flag
- Increase timeout value

### 3. Rate Limiting
**Symptom:** HTTP 429 responses
**Cause:** Too many requests
**Resolution:**
- Add delays between requests
- Reduce scan intensity
- Use --profile quick

### 4. Permission Denied
**Symptom:** Cannot write to output directory
**Cause:** Insufficient filesystem permissions
**Resolution:**
- Check OUTPUT_DIR permissions
- Run with appropriate user
- Verify disk space

### 5. Count Mismatch
**Symptom:** count.txt shows 0 but findings exist
**Cause:** Findings written before count update
**Resolution:**
- Ensure count.txt is last write
- Check phase implementation
RBEOF
    count=$((count + 1))

    cat > "$phase_dir/runbooks/incident_response.md" <<'IREOF'
# Incident Response Runbook

## Scan Anomaly Detection

### High Severity Findings
1. Document finding immediately
2. Escalate to lead operator
3. Verify false positive status
4. Generate evidence package
5. Notify stakeholders

### Scan Blocking
1. Check for WAF/IDS triggers
2. Reduce scan intensity
3. Switch to passive techniques
4. Wait and retry

### Data Exposure
1. Stop scanning immediately
2. Document exposure scope
3. Secure affected data
4. Report to compliance team
IREOF
    count=$((count + 1))

    log "INFO" "[RUNBOOKS] Generating troubleshooting guide"
    {
        echo "=== Troubleshooting Guide ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Quick Diagnostics:"
        echo "  1. Check tool availability"
        echo "  2. Verify network connectivity"
        echo "  3. Check output directory permissions"
        echo "  4. Review phase count.txt"
        echo "  5. Enable --debug for verbose output"
        echo ""
        echo "Error Codes:"
        echo "  0: Success"
        echo "  1: General error"
        echo "  2: Usage error"
        echo "  3: Domain error"
        echo "  4: Tool missing"
        echo "  5: Network error"
        echo ""
        echo "Recovery Steps:"
        echo "  - Tool missing: Install and retry"
        echo "  - Network error: Check connectivity"
        echo "  - Domain error: Verify domain spelling"
        echo "  - Permission error: Check OUTPUT_DIR"
    } > "$troubleshooting_guide"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "RUNBOOK" "Runbooks generated" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "runbooks_complete" "Runbooks complete: $count items"
    log "INFO" "[RUNBOOKS] Completed: $count items generated"

    return 0
}
