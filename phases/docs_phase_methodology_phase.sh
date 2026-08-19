#!/usr/bin/env bash
# Phase 292: Per-Phase Methodology Documentation, Technique Descriptions, Tool Usage
# Track 21 - Documentation

docs_phase_methodology() {
    local domain="${1:?Usage: docs_phase_methodology <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/docs_phase_methodology"
    mkdir -p "$phase_dir"

    log "INFO" "[PHASE_METH] Generating phase methodology docs for $domain"

    local phase_methodologies="$phase_dir/phase_methodologies.json"
    local methodology_index="$phase_dir/methodology_index.txt"

    local count=0

    cat > "$phase_methodologies" <<PMEOF
{
  "domain": "$domain",
  "timestamp": "$TIMESTAMP",
  "methodologies": [
    {
      "phase_range": "1-50",
      "track": "Reconnaissance",
      "techniques": [
        "Subdomain enumeration via DNS",
        "Certificate transparency log mining",
        "WHOIS database queries",
        "Passive DNS resolution",
        "Search engine dorking"
      ],
      "tools": ["subfinder", "amass", "dig", "whois", "curl"],
      "output_types": ["domains", "ips", "nameservers", "mx_records"]
    },
    {
      "phase_range": "51-100",
      "track": "Scanning",
      "techniques": [
        "TCP/UDP port scanning",
        "Service version detection",
        "Web technology fingerprinting",
        "SSL/TLS configuration audit",
        "HTTP header analysis"
      ],
      "tools": ["nmap", "whatweb", "httpx", "sslscan", "nikto"],
      "output_types": ["ports", "services", "versions", "technologies"]
    },
    {
      "phase_range": "101-150",
      "track": "Analysis",
      "techniques": [
        "Vulnerability correlation",
        "Risk scoring (CVSS)",
        "Attack surface mapping",
        "Dependency analysis",
        "Configuration review"
      ],
      "tools": ["nuclei", "jq", "python3"],
      "output_types": ["vulnerabilities", "risks", "attack_vectors"]
    },
    {
      "phase_range": "261-270",
      "track": "Compliance",
      "techniques": [
        "Header compliance checking",
        "TLS configuration verification",
        "Privacy policy analysis",
        "Cookie consent detection",
        "Retention policy review"
      ],
      "tools": ["curl", "nmap", "openssl"],
      "output_types": ["compliance_status", "gaps", "evidence"]
    }
  ]
}
PMEOF
    count=$((count + 1))

    log "INFO" "[PHASE_METH] Generating methodology index"
    {
        echo "=== Methodology Index ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "1. Reconnaissance (Phases 1-50)"
        echo "   Techniques: DNS, CT logs, WHOIS, passive DNS"
        echo "   Tools: subfinder, amass, dig, whois, curl"
        echo "   Output: domains, IPs, nameservers"
        echo ""
        echo "2. Scanning (Phases 51-100)"
        echo "   Techniques: Port scan, service detection, fingerprinting"
        echo "   Tools: nmap, whatweb, httpx, sslscan"
        echo "   Output: ports, services, versions"
        echo ""
        echo "3. Analysis (Phases 101-150)"
        echo "   Techniques: Vuln correlation, risk scoring, attack surface"
        echo "   Tools: nuclei, jq, python3"
        echo "   Output: vulnerabilities, risks"
        echo ""
        echo "4. Compliance (Phases 261-270)"
        echo "   Techniques: Header checks, TLS audit, policy review"
        echo "   Tools: curl, nmap, openssl"
        echo "   Output: compliance status, gaps"
        echo ""
        echo "5. Collaboration (Phases 271-280)"
        echo "   Techniques: Multi-operator, shared review, RBAC"
        echo "   Tools: bash, JSON config"
        echo "   Output: configs, status docs"
        echo ""
        echo "6. UX/CLI (Phases 281-290)"
        echo "   Techniques: Interactive mode, TUI, shell completion"
        echo "   Tools: bash, JSON config"
        echo "   Output: configs, scripts"
        echo ""
        echo "7. Documentation (Phases 291-300)"
        echo "   Techniques: Architecture docs, runbooks, changelogs"
        echo "   Tools: bash, markdown"
        echo "   Output: docs, guides"
    } > "$methodology_index"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "METH" "Phase methodology docs generated" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "phase_methodology_complete" "Phase methodology docs complete: $count items"
    log "INFO" "[PHASE_METH] Completed: $count items generated"

    return 0
}
