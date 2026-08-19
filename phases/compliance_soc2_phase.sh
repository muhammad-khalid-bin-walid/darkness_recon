#!/usr/bin/env bash
# Phase 263: SOC2 Control Mapping, Trust Service Criteria, Audit Evidence
# Track 18 - Compliance

compliance_soc2() {
    local domain="${1:?Usage: compliance_soc2 <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/compliance_soc2"
    mkdir -p "$phase_dir"

    log "INFO" "[SOC2] Starting SOC2 control mapping for $domain"

    local soc2_compliance="$phase_dir/soc2_compliance.txt"
    local soc2_evidence="$phase_dir/soc2_evidence.txt"

    : > "$soc2_compliance"
    : > "$soc2_evidence"

    local count=0

    if tool_available "curl"; then
        log "INFO" "[SOC2] Checking security controls (CC6-CC8)"

        local headers
        headers=$(curl -sI --max-time 10 "https://$domain" 2>/dev/null || true)

        if [ -n "$headers" ]; then
            local hsts
            hsts=$(echo "$headers" | grep -ci "strict-transport-security" || true)
            if [ "$hsts" -gt 0 ]; then
                echo "CC6.1: HSTS enforced - PASS" >> "$soc2_compliance"
                echo "Evidence: Strict-Transport-Security header present" >> "$soc2_evidence"
                write_finding "$phase_dir" "SOC2-CC6.1" "HSTS enforced" "high" "passed"
                count=$((count + 1))
            else
                echo "CC6.1: HSTS not enforced - FAIL" >> "$soc2_compliance"
                echo "Evidence: No Strict-Transport-Security header" >> "$soc2_evidence"
                write_finding "$phase_dir" "SOC2-CC6.1" "HSTS missing" "high" "failed"
                count=$((count + 1))
            fi

            local xfo
            xfo=$(echo "$headers" | grep -ci "x-frame-options" || true)
            if [ "$xfo" -gt 0 ]; then
                echo "CC6.6: Clickjacking protection - PASS" >> "$soc2_compliance"
                echo "Evidence: X-Frame-Options header present" >> "$soc2_evidence"
                count=$((count + 1))
            else
                echo "CC6.6: Clickjacking protection - FAIL" >> "$soc2_compliance"
                count=$((count + 1))
            fi

            local server_leak
            server_leak=$(echo "$headers" | grep -i "^server:" | head -1 || true)
            if [ -n "$server_leak" ]; then
                echo "CC6.1: Server header information disclosure - WARN" >> "$soc2_compliance"
                echo "Evidence: $server_leak" >> "$soc2_evidence"
                write_finding "$phase_dir" "SOC2-CC6.1" "Server header leak" "medium" "warning"
                count=$((count + 1))
            fi
        fi
    fi

    if tool_available "nmap"; then
        log "INFO" "[SOC2] Checking network controls (CC6.7)"
        nmap -sV --script ssl-enum-ciphers -p 443 "$domain" 2>/dev/null > "$phase_dir/network_control.txt" || true
        echo "CC6.7: Network service scan completed" >> "$soc2_compliance"
        echo "Evidence: nmap results in network_control.txt" >> "$soc2_evidence"
        count=$((count + 1))
    fi

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "soc2_complete" "SOC2 control mapping complete: $count controls checked"
    log "INFO" "[SOC2] Completed: $count controls mapped"

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_endpoint "$phase_dir" "https://$domain" "GET" "SOC2 compliance target"

    return 0
}
