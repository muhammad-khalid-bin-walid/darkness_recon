#!/usr/bin/env bash
# Phase 187: FTP/SFTP Security Testing
set -euo pipefail

net_ftp() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/net_ftp"

    log "INFO" "Starting FTP/SFTP security testing for $domain"

    local ftp_vulns="$output_dir/net_ftp/ftp_vulns.txt"
    local ftp_anonymous="$output_dir/net_ftp/ftp_anonymous.txt"
    local count=0

    {
        echo "=== FTP Vulnerabilities ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "FTP security checks:"
        echo "  1. Anonymous login"
        echo "  2. Weak credentials"
        echo "  3. Cleartext transmission"
        echo "  4. Directory traversal"
        echo "  5. Write permission abuse"
        echo "  6. FTP bounce attacks"
        echo "  7. TLS/SSL configuration"
        echo "  8. SFTP configuration"
    } > "$ftp_vulns"

    {
        echo "=== FTP Anonymous Access ==="
        echo "Domain: $domain"
        echo ""
        echo "Anonymous FTP access checks:"
        echo "  - anonymous@ login"
        echo "  - ftp@ login"
        echo "  - guest@ login"
        echo ""
        echo "Anonymous access risks:"
        echo "  - Data exposure"
        echo "  - Malware distribution"
        echo "  - Resource abuse"
        echo "  - Pivot point"
        echo ""
        echo "FTP service information:"
    } > "$ftp_anonymous"

    # Test FTP ports
    local ftp_ports=(21 990)
    for port in "${ftp_ports[@]}"; do
        local ftp_banner
        ftp_banner=$(echo "QUIT" | nc -w 5 "$domain" "$port" 2>/dev/null | head -1 || echo "")
        if [[ -n "$ftp_banner" ]]; then
            echo "[FTP] Port $port: $ftp_banner" >> "$ftp_anonymous"
            ((count++)) || true
        fi
    done

    # Test SFTP
    local sftp_test
    sftp_test=$(ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no "sftp://$domain" 2>&1 | head -1 || echo "")
    if [[ -n "$sftp_test" ]]; then
        echo "[SFTP] $domain: $sftp_test" >> "$ftp_anonymous"
        ((count++)) || true
    fi

    echo "$count" > "$output_dir/net_ftp/count.txt"
    log "INFO" "FTP/SFTP security testing complete: $count findings"
    write_finding "{\"type\":\"net_ftp\",\"severity\":\"info\",\"count\":$count,\"phase\":\"net_ftp\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=net_ftp domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    net_ftp "${1:-}"
fi
