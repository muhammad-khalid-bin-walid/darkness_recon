#!/usr/bin/env bash
# Phase 261: ASVS Requirement Mapping, Verification Status, Gap Analysis
# Track 18 - Compliance

compliance_asvs() {
    local domain="${1:?Usage: compliance_asvs <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/compliance_asvs"
    mkdir -p "$phase_dir"

    log "INFO" "[ASVS] Starting ASVS requirement mapping for $domain"

    local asvs_mapping="$phase_dir/asvs_mapping.json"
    local asvs_gaps="$phase_dir/asvs_gaps.txt"

    echo "[]" > "$asvs_mapping"
    : > "$asvs_gaps"

    local count=0

    if tool_available "curl"; then
        log "INFO" "[ASVS] Checking TLS configuration against ASVS V1 requirements"
        local tls_result
        tls_result=$(curl -sI --max-time 10 "https://$domain" 2>/dev/null || true)
        if [ -n "$tls_result" ]; then
            local has_hsts
            has_hsts=$(echo "$tls_result" | grep -ci "strict-transport-security" || true)
            if [ "$has_hsts" -gt 0 ]; then
                write_finding "$phase_dir" "ASVS-V1.2.1" "HSTS header present" "high" "passed"
                py_log "INFO" "asvs_check" "HSTS present for $domain"
                echo "{\"requirement\":\"V1.2.1\",\"status\":\"passed\",\"control\":\"HSTS\"}" >> "$asvs_mapping.tmp"
                count=$((count + 1))
            else
                write_finding "$phase_dir" "ASVS-V1.2.1" "HSTS header missing" "high" "failed"
                echo "V1.2.1: HSTS header not found" >> "$asvs_gaps"
                echo "{\"requirement\":\"V1.2.1\",\"status\":\"failed\",\"control\":\"HSTS\"}" >> "$asvs_mapping.tmp"
                count=$((count + 1))
            fi
        fi
    fi

    if tool_available "nmap"; then
        log "INFO" "[ASVS] Scanning for TLS versions (ASVS V1.2)"
        nmap --script ssl-enum-ciphers -p 443 "$domain" 2>/dev/null | head -50 > "$phase_dir/tls_scan.txt" || true
        local tls_v13
        tls_v13=$(grep -c "TLSv1.3" "$phase_dir/tls_scan.txt" 2>/dev/null || echo "0")
        if [ "$tls_v13" -gt 0 ]; then
            write_finding "$phase_dir" "ASVS-V1.2.3" "TLS 1.3 supported" "high" "passed"
            echo "{\"requirement\":\"V1.2.3\",\"status\":\"passed\",\"control\":\"TLS1.3\"}" >> "$asvs_mapping.tmp"
            count=$((count + 1))
        else
            write_finding "$phase_dir" "ASVS-V1.2.3" "TLS 1.3 not supported" "high" "failed"
            echo "V1.2.3: TLS 1.3 not supported" >> "$asvs_gaps"
            echo "{\"requirement\":\"V1.2.3\",\"status\":\"failed\",\"control\":\"TLS1.3\"}" >> "$asvs_mapping.tmp"
            count=$((count + 1))
        fi
    fi

    if [ -f "$asvs_mapping.tmp" ]; then
        echo "[" > "$asvs_mapping"
        sed ':a;N;$!ba;s/\n/,/g' "$asvs_mapping.tmp" >> "$asvs_mapping"
        echo "]" >> "$asvs_mapping"
        rm -f "$asvs_mapping.tmp"
    fi

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "asvs_complete" "ASVS mapping complete: $count requirements checked"
    log "INFO" "[ASVS] Completed: $count requirements mapped"

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_endpoint "$phase_dir" "https://$domain" "GET" "ASVS verification target"

    return 0
}
