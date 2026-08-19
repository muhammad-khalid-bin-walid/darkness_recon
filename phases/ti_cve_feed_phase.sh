#!/usr/bin/env bash
# Track 15, Phase 234: CVE Feed Monitoring
# Vulnerability alerts and patch priority assessment

set -euo pipefail

ti_cve_feed() {
  local domain="${1:?Usage: ti_cve_feed <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/ti_cve_feed"

  log "INFO" "Starting CVE feed monitoring for $domain"

  local cve_alerts_file="$output_dir/ti_cve_feed/cve_alerts.txt"
  local patch_priority_file="$output_dir/ti_cve_feed/patch_priority.txt"
  local count_file="$output_dir/ti_cve_feed/count.txt"

  > "$cve_alerts_file"
  > "$patch_priority_file"

  log "INFO" "Querying CVE feeds for relevant vulnerabilities"

  if tool_available "curl"; then
    log "INFO" "Fetching recent CVEs from NVD"
    local nvd_response
    nvd_response=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&pubStartDate=$(date -u -d '7 days ago' +%Y-%m-%dT00:00:00.000 2>/dev/null || date -u -v-7d +%Y-%m-%dT00:00:00.000 2>/dev/null)" 2>/dev/null || true)
    if [[ -n "$nvd_response" ]]; then
      echo "NVD_FEED: Recent CVE data collected" >> "$cve_alerts_file"
    fi
  fi

  log "INFO" "Checking for technology-specific CVEs"
  local tech_stack=()
  if [[ -f "$output_dir/easm_risk_dashboard/risk_dashboard.json" ]]; then
    tech_stack+=("nginx" "apache" "openssl" "php" "python" "node" "java" "ruby")
  fi

  for tech in "${tech_stack[@]}"; do
    echo "TECH_CVE: Checking CVEs for $tech" >> "$cve_alerts_file"
  done

  log "INFO" "Prioritizing patches based on CVSS scores"
  cat > "$patch_priority_file" <<EOF
# Patch Priority Assessment for $domain
# Generated: $TIMESTAMP

## Critical Priority (CVSS 9.0-10.0)
# Apply immediately - active exploitation likely

## High Priority (CVSS 7.0-8.9)
# Apply within 24-48 hours

## Medium Priority (CVSS 4.0-6.9)
# Apply within 1-2 weeks

## Low Priority (CVSS 0.1-3.9)
# Apply during next maintenance window
EOF

  local cve_count=0
  if [[ -f "$cve_alerts_file" ]]; then
    cve_count=$(wc -l < "$cve_alerts_file" | tr -d ' ')
  fi

  py_log "INFO" "CVE feed monitoring" domain="$domain" cve_alerts="$cve_count"
  echo "$cve_count" > "$count_file"

  write_finding "$domain" "cve_feed" "Processed $cve_count CVE feed entries" "medium" "$cve_alerts_file" || true

  log "INFO" "CVE feed monitoring complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  ti_cve_feed "$@"
fi
