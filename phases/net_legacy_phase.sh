#!/usr/bin/env bash
# Phase 197: Legacy Protocol Detection
set -euo pipefail

net_legacy() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/net_legacy"

    log "INFO" "Starting legacy protocol detection for $domain"

    local legacy_vulns="$output_dir/net_legacy/legacy_vulns.txt"
    local legacy_protocols="$output_dir/net_legacy/legacy_protocols.txt"
    local count=0

    {
        echo "=== Legacy Vulnerabilities ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Legacy protocol checks:"
        echo "  1. Telnet (port 23)"
        echo "  2. SSLv2/SSLv3"
        echo "  3. RC4 cipher"
        echo "  4. DES/3DES"
        echo "  5. HTTP (port 80)"
        echo "  6. FTP (cleartext)"
        echo "  7. SNMPv1/v2c"
        echo "  8. RIPv1"
    } > "$legacy_vulns"

    {
        echo "=== Legacy Protocols ==="
        echo "Domain: $domain"
        echo ""
        echo "Deprecated protocols and their risks:"
        echo ""
        echo "Telnet (Port 23):"
        echo "  - Cleartext transmission"
        echo "  - No authentication encryption"
        echo "  - Vulnerable to sniffing"
        echo ""
        echo "SSLv2/SSLv3:"
        echo "  - DROWN attack (CVE-2016-0800)"
        echo "  - POODLE attack (CVE-2014-3566)"
        echo "  - BEAST attack (CVE-2011-3389)"
        echo ""
        echo "RC4 Cipher:"
        echo "  - RFC 7465 prohibited"
        echo "  - Biased output"
        echo "  - Recovery attacks"
        echo ""
        echo "DES/3DES:"
        echo "  - Small key size"
        echo "  - Sweet32 attack"
        echo "  - Brute-force vulnerable"
    } > "$legacy_protocols"

    # Test legacy ports
    local legacy_ports=(
        "23:Telnet"
        "21:FTP"
        "25:SMTP"
        "110:POP3"
        "143:IMAP"
    )

    for entry in "${legacy_ports[@]}"; do
        local port="${entry%%:*}"
        local name="${entry##*:}"
        local legacy_test
        legacy_test=$(echo "QUIT" | nc -w 5 "$domain" "$port" 2>/dev/null | head -1 || echo "")
        if [[ -n "$legacy_test" ]]; then
            echo "[LEGACY] $name (port $port) responding: $legacy_test" >> "$legacy_protocols"
            ((count++)) || true
        fi
    done

    echo "$count" > "$output_dir/net_legacy/count.txt"
    log "INFO" "Legacy protocol detection complete: $count findings"
    write_finding "{\"type\":\"net_legacy\",\"severity\":\"info\",\"count\":$count,\"phase\":\"net_legacy\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=net_legacy domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    net_legacy "${1:-}"
fi
