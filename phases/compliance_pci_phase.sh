#!/usr/bin/env bash
# Phase 262: PCI-DSS Compliance Checking, Requirement Validation, Evidence Collection
# Track 18 - Compliance

compliance_pci() {
    local domain="${1:?Usage: compliance_pci <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/compliance_pci"
    mkdir -p "$phase_dir"

    log "INFO" "[PCI] Starting PCI-DSS compliance checking for $domain"

    local pci_compliance="$phase_dir/pci_compliance.txt"
    local pci_evidence="$phase_dir/pci_evidence.txt"

    : > "$pci_compliance"
    : > "$pci_evidence"

    local count=0

    if tool_available "curl"; then
        log "INFO" "[PCI] Checking payment-related headers and security controls"

        local headers
        headers=$(curl -sI --max-time 10 "https://$domain" 2>/dev/null || true)

        if [ -n "$headers" ]; then
            local csp
            csp=$(echo "$headers" | grep -ci "content-security-policy" || true)
            if [ "$csp" -gt 0 ]; then
                echo "PCI-6.5.8: CSP header present - PASS" >> "$pci_compliance"
                echo "Evidence: Content-Security-Policy header detected" >> "$pci_evidence"
                write_finding "$phase_dir" "PCI-6.5.8" "CSP present" "high" "passed"
                count=$((count + 1))
            else
                echo "PCI-6.5.8: CSP header missing - FAIL" >> "$pci_compliance"
                echo "Evidence: No Content-Security-Policy header" >> "$pci_evidence"
                write_finding "$phase_dir" "PCI-6.5.8" "CSP missing" "high" "failed"
                count=$((count + 1))
            fi

            local xcto
            xcto=$(echo "$headers" | grep -ci "x-content-type-options" || true)
            if [ "$xcto" -gt 0 ]; then
                echo "PCI-6.5.9: X-Content-Type-Options present - PASS" >> "$pci_compliance"
                count=$((count + 1))
            else
                echo "PCI-6.5.9: X-Content-Type-Options missing - FAIL" >> "$pci_compliance"
                count=$((count + 1))
            fi
        fi
    fi

    if tool_available "nmap"; then
        log "INFO" "[PCI] Scanning for required ports (PCI-1.2.1)"
        nmap -p 443,80,21,22,3306,5432 "$domain" 2>/dev/null > "$phase_dir/port_scan.txt" || true
        local open_ports
        open_ports=$(grep -c "open" "$phase_dir/port_scan.txt" 2>/dev/null || echo "0")
        echo "PCI-1.2.1: Open ports scanned - $open_ports found" >> "$pci_compliance"
        echo "Evidence: nmap port scan results in port_scan.txt" >> "$pci_evidence"
        write_asset "$phase_dir" "open_ports" "$open_ports" "count"
        count=$((count + 1))
    fi

    if tool_available "openssl"; then
        log "INFO" "[PCI] Checking certificate validity (PCI-4.1)"
        local cert_info
        cert_info=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || true)
        if [ -n "$cert_info" ]; then
            echo "PCI-4.1: SSL Certificate - $cert_info" >> "$pci_compliance"
            echo "Evidence: $cert_info" >> "$pci_evidence"
            write_finding "$phase_dir" "PCI-4.1" "Certificate valid" "critical" "info"
            count=$((count + 1))
        fi
    fi

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "pci_complete" "PCI-DSS compliance check complete: $count items checked"
    log "INFO" "[PCI] Completed: $count requirements checked"

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_endpoint "$phase_dir" "https://$domain" "GET" "PCI-DSS compliance target"

    return 0
}
