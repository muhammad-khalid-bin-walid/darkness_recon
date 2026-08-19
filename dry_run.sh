#!/bin/bash
# dry_run.sh — Show what Dark Recon Framework would execute without sending network traffic
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

usage() {
    cat <<EOF
${BOLD}Dark Recon Framework — Dry Run${NC}

Usage: $(basename "$0") [OPTIONS]

Options:
  --target <domain>     Target domain to scan (required)
  --track <N>           Only show phases from a specific track (0-21)
  --phase <name>        Only show a specific phase
  --fast                Show only default/fast-mode phases
  --deep                Show all phases including optional ones
  --scope               Run scope validation check on target
  --json                Output as JSON
  -h, --help            Show this help
EOF
    exit 0
}

# Defaults
TARGET=""
TRACK_FILTER=""
PHASE_FILTER=""
MODE="default"
CHECK_SCOPE=false
JSON_OUTPUT=false

# Parse args
while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --track) TRACK_FILTER="$2"; shift 2 ;;
        --phase) PHASE_FILTER="$2"; shift 2 ;;
        --fast) MODE="fast"; shift ;;
        --deep) MODE="deep"; shift ;;
        --scope) CHECK_SCOPE=true; shift ;;
        --json) JSON_OUTPUT=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: --target is required${NC}" >&2
    exit 1
fi

# Phase definitions: name|track|depends|tools|enabled_by_default|description
# Sourced from phase_manager.sh analysis
declare -a PHASE_DATA=(
    # Track 0: Foundation
    "subdomains|0||subfinder assetfinder amass findomain|true|Subdomain enumeration"
    "dns|0|subdomains|dnsx puredns dnsrecon|true|DNS record analysis"
    "live|0|dns|httpx curl|true|Live host detection"
    "tech|0|live|whatweb wappalyzer httpx|true|Technology fingerprinting"
    "crawl|0|live|katana hakrawler gospider|true|URL and endpoint discovery"
    "params|0|crawl|arjun paramspider|true|Parameter discovery"
    "fuzz|0|live|ffuf gobuster wfuzz|true|Directory and fuzzing"
    "takeovers|0|subdomains live|nuclei subjack|true|Subdomain takeover detection"
    # Track 1: Data Model
    "waf|1|live|wafw00f waf-detect|false|WAF detection"
    "nuclei|1|live|nuclei|false|Template vulnerability scanning"
    "ports|1|live|nmap masscan rustscan|false|Port scanning"
    "ssl|1|live|sslscan testssl.sh|false|SSL/TLS analysis"
    "api|3|api crawl|katana arjun ffuf|false|API endpoint discovery"
    "git|1|live|trufflehog gitleaks|false|Git repository scanning"
    "secrets|1|crawl|trufflehog gitleaks gitallsecrets|false|Secret detection"
    "screenshots|1|live|gowitness|true|Visual reconnaissance"
    "patterns|1|crawl params|jq grep|true|Pattern matching"
    # Track 2: Recon & Discovery
    "asn_pivot|2|subdomains live|asnlookup whois|false|ASN pivot discovery"
    "cloud_asset|2|subdomains live|cloud_enum|false|Cloud asset discovery"
    "origin_ip|2|live ssl|censys shodan|false|Origin IP discovery"
    "cert_transparency|2|subdomains|crt.sh certspotter|false|Certificate transparency"
    # Track 3: Web/API Attack Surface
    "openapi_ingest|3|api crawl|swagger-parser|false|OpenAPI spec ingestion"
    "graphql_abuse|3|api|graphql-cop|false|GraphQL abuse testing"
    "waf_bypass|3|waf live|x8-bypass|false|WAF bypass techniques"
    # Track 5: Cloud/CI/CD
    "cloud|5|subdomains live crawl|ScoutSuite Prowler cloud_enum|false|Cloud security assessment"
    "cicd_config|5|subdomains live|trivy|false|CI/CD config scanning"
    # Track 6: Exploitation/Validation
    "vuln|6|live|nuclei nikto wapiti|false|Vulnerability scanning"
    "service|6|live|nmap|false|Service enumeration"
    "exploitation_validation|6|vuln|custom scripts|true|PoC validation"
    # Track 8: Reporting
    "reporting|8||jq python3|true|Report aggregation"
    # Track 9: ML/Triage
    "ml_analysis|9|reporting database webhooks cicd|python3|true|ML anomaly detection"
    "compliance|9|ml_analysis|python3|true|Compliance scanning"
)

# Phase groupings for fast mode
FAST_PHASES="subdomains dns live tech crawl params fuzz takeovers screenshots patterns reporting ml_analysis compliance exploitation_validation"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║        Dark Recon Framework — Dry Run Preview              ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Target:   ${CYAN}${TARGET}${NC}"
echo -e "  Mode:     ${YELLOW}${MODE}${NC}"
if [ -n "$TRACK_FILTER" ]; then
    echo -e "  Track:    ${YELLOW}${TRACK_FILTER}${NC}"
fi
if [ -n "$PHASE_FILTER" ]; then
    echo -e "  Phase:    ${YELLOW}${PHASE_FILTER}${NC}"
fi
echo ""

# Scope check
if [ "$CHECK_SCOPE" = true ]; then
    echo -e "${BOLD}── Scope Validation ──${NC}"
    if command -v python3 &>/dev/null && [ -f "$SCRIPT_DIR/lib/phase_bridge.sh" ]; then
        source "$SCRIPT_DIR/lib/phase_bridge.sh" 2>/dev/null || true
        if type py_scope_check &>/dev/null; then
            if py_scope_check "$TARGET" "generic" 2>/dev/null; then
                echo -e "  ${GREEN}✓${NC} Target ${TARGET} passes scope validation"
            else
                echo -e "  ${RED}✗${NC} Target ${CYAN}${TARGET}${NC} may be OUT OF SCOPE"
                echo -e "    ${YELLOW}⚠ Proceed with caution — ensure authorized testing${NC}"
            fi
        else
            echo -e "  ${YELLOW}⚠ scope_check not available — skipping validation${NC}"
        fi
    else
        echo -e "  ${YELLOW}⚠ Python/lib not found — skipping scope validation${NC}"
    fi
    echo ""
fi

# Build phase table
echo -e "${BOLD}── Phases ──${NC}"
echo ""

# Header
printf "${BOLD}%-22s %-6s %-28s %-8s %-30s${NC}\n" "PHASE" "TRACK" "TOOLS" "STATUS" "DESCRIPTION"
printf '%.0s─' {1..90}; echo ""

enabled_count=0
total_time=0

for entry in "${PHASE_DATA[@]}"; do
    IFS='|' read -r name track depends tools default desc <<< "$entry"

    # Apply filters
    if [ -n "$TRACK_FILTER" ] && [ "$track" != "$TRACK_FILTER" ]; then
        continue
    fi
    if [ -n "$PHASE_FILTER" ] && [ "$name" != "$PHASE_FILTER" ]; then
        continue
    fi

    # Determine if phase would run
    would_run=false
    if [ "$MODE" = "deep" ]; then
        would_run=true
    elif [ "$MODE" = "fast" ]; then
        if echo "$FAST_PHASES" | grep -qw "$name"; then
            would_run=true
        fi
    else
        # Default mode: only enabled_by_default phases
        if [ "$default" = "true" ]; then
            would_run=true
        fi
    fi

    if [ "$would_run" = true ]; then
        status="${GREEN}ON${NC}"
        enabled_count=$((enabled_count + 1))
        # Estimate time per phase (rough)
        case "$name" in
            subdomains) est=120 ;;
            dns) est=60 ;;
            live) est=90 ;;
            crawl) est=180 ;;
            fuzz) est=300 ;;
            nuclei) est=600 ;;
            ports) est=300 ;;
            ssl) est=120 ;;
            api) est=240 ;;
            cloud) est=600 ;;
            vuln) est=450 ;;
            reporting) est=30 ;;
            *) est=60 ;;
        esac
        total_time=$((total_time + est))
    else
        status="${RED}OFF${NC}"
    fi

    printf "%-22s %-6s %-28s " "$name" "T$track" "$tools"
    echo -e "$status  $desc"
done

echo ""
printf '%.0s─' {1..90}; echo ""

# Summary
mins=$((total_time / 60))
secs=$((total_time % 60))

echo ""
echo -e "  ${BOLD}Summary:${NC}"
echo -e "    Phases enabled: ${CYAN}${enabled_count}${NC}"
echo -e "    Estimated time: ${CYAN}${mins}m ${secs}s${NC} (rough estimate)"
echo -e "    Network traffic: ${RED}NONE (dry run)${NC}"
echo ""

if [ "$JSON_OUTPUT" = true ]; then
    echo "{"
    echo "  \"target\": \"$TARGET\","
    echo "  \"mode\": \"$MODE\","
    echo "  \"enabled_phases\": $enabled_count,"
    echo "  \"estimated_seconds\": $total_time,"
    echo "  \"phases\": ["
    first=true
    for entry in "${PHASE_DATA[@]}"; do
        IFS='|' read -r name track depends tools default desc <<< "$entry"
        would_run=false
        if [ "$MODE" = "deep" ]; then would_run=true
        elif [ "$MODE" = "fast" ] && echo "$FAST_PHASES" | grep -qw "$name"; then would_run=true
        elif [ "$default" = "true" ]; then would_run=true; fi

        if [ "$would_run" = true ]; then
            [ "$first" = true ] || echo ","
            echo -n "    {\"phase\": \"$name\", \"track\": $track, \"tools\": \"$tools\"}"
            first=false
        fi
    done
    echo ""
    echo "  ]"
    echo "}"
fi
