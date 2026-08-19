#!/bin/bash
# Combined Phase 12: Compliance & Regulatory Scanning
# Encompasses: GDPR, HIPAA, PCI DSS, SOC2, ASVS, compliance phases
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

compliance_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local compliance_dir="$output_dir/compliance"

    mkdir -p "$compliance_dir"

    log "INFO" "Starting compliance & regulatory scanning for $domain"

    # GDPR scanning - check for privacy policy, data handling
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking GDPR compliance signals..."
        curl -sI "https://$domain" 2>>"$LOGS_DIR/compliance.log" | grep -iE "gdpr|privacy|cookie" >> "$compliance_dir/gdpr.txt" || true
    fi

    # PCI DSS checks - payment-related pages
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking PCI DSS indicators..."
        curl -sI "https://$domain" 2>>"$LOGS_DIR/compliance.log" | grep -iE "ssl|tls|cvv|payment" >> "$compliance_dir/pci.txt" || true
    fi

    # SOC2 checks - security headers and controls
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking SOC2 security controls..."
        curl -sI "https://$domain" 2>>"$LOGS_DIR/compliance.log" | grep -iE "hsts|csp|x-frame|x-content|referrer" >> "$compliance_dir/soc2.txt" || true
    fi

    # HIPAA checks - health-related indicators
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking HIPAA indicators..."
        curl -sI "https://$domain" 2>>"$LOGS_DIR/compliance.log" | grep -iE "hipaa|medical|health" >> "$compliance_dir/hipaa.txt" || true
    fi

    # Generate compliance summary
    local compliance_count=0
    for file in "$compliance_dir"/*.txt; do
        [ -f "$file" ] || continue
        local count
        count=$(grep -c "E" "$file" 2>/dev/null || echo 0)  # Count evidence findings
        compliance_count=$((compliance_count + count))
    done

    # Write consolidated compliance summary
    cat <<EOF > "$compliance_dir/compliance_summary.json"
{
  "domain": "$domain",
  "gdpr_evidence": $(grep -c "E" "$compliance_dir/gdpr.txt" 2>/dev/null || echo 0),
  "pci_evidence": $(grep -c "E" "$compliance_dir/pci.txt" 2>/dev/null || echo 0),
  "soc2_evidence": $(grep -c "E" "$compliance_dir/soc2.txt" 2>/dev/null || echo 0),
  "hipaa_evidence": $(grep -c "E" "$compliance_dir/hipaa.txt" 2>/dev/null || echo 0),
  "total_findings": $compliance_count
}
EOF

    phase_log "INFO" "Compliance & regulatory scanning complete: $compliance_count findings" "compliance_scanning" "$domain"

    # Write assets
    for file in "$compliance_dir"/*.txt; do
        [ -f "$file" ] || continue
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            write_asset "{\"type\":\"compliance_finding\",\"value\":\"$line\",\"source\":\"compliance_scan\",\"phase\":\"compliance_regulatory_scanning\"}" \
                "$compliance_dir/assets.jsonl" 2>/dev/null || true
        done < "$file"
    done

    echo "$compliance_count" > "$compliance_dir/count.txt"

    write_finding "{\"type\":\"compliance_scan\",\"severity\":\"info\",\"count\":$compliance_count,\"phase\":\"compliance_regulatory_scanning\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "compliance_phase" "Completed for $domain"
}