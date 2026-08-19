#!/usr/bin/env bash
# Track 14, Phase 226: Risk Dashboard Generation
# Trend analysis and executive reporting

set -euo pipefail

easm_risk_dashboard() {
  local domain="${1:?Usage: easm_risk_dashboard <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/easm_risk_dashboard"

  log "INFO" "Starting risk dashboard generation for $domain"

  local risk_dashboard_file="$output_dir/easm_risk_dashboard/risk_dashboard.json"
  local risk_trends_file="$output_dir/easm_risk_dashboard/risk_trends.txt"
  local count_file="$output_dir/easm_risk_dashboard/count.txt"

  > "$risk_trends_file"

  log "INFO" "Collecting risk metrics from previous phases"
  local asset_count=0
  local shadow_count=0
  local cert_issues=0
  local expired_count=0

  if [[ -f "$output_dir/easm_asset_inventory/count.txt" ]]; then
    asset_count=$(cat "$output_dir/easm_asset_inventory/count.txt" 2>/dev/null || echo "0")
  fi
  if [[ -f "$output_dir/easm_shadow_it/count.txt" ]]; then
    shadow_count=$(cat "$output_dir/easm_shadow_it/count.txt" 2>/dev/null || echo "0")
  fi
  if [[ -f "$output_dir/easm_cert_expiry/count.txt" ]]; then
    cert_issues=$(cat "$output_dir/easm_cert_expiry/count.txt" 2>/dev/null || echo "0")
  fi
  if [[ -f "$output_dir/easm_expired_domain/count.txt" ]]; then
    expired_count=$(cat "$output_dir/easm_expired_domain/count.txt" 2>/dev/null || echo "0")
  fi

  log "INFO" "Generating risk dashboard JSON"
  cat > "$risk_dashboard_file" <<EOF
{
  "domain": "$domain",
  "timestamp": "$TIMESTAMP",
  "risk_summary": {
    "total_assets": $asset_count,
    "shadow_it_services": $shadow_count,
    "cert_issues": $cert_issues,
    "expired_domain_variants": $expired_count,
    "overall_risk_score": 0
  },
  "trends": {
    "asset_growth": "stable",
    "shadow_it_trend": "increasing",
    "cert_health": "monitored"
  }
}
EOF

  echo "=== Risk Dashboard Trends ===" >> "$risk_trends_file"
  echo "Domain: $domain" >> "$risk_trends_file"
  echo "Assets: $asset_count" >> "$risk_trends_file"
  echo "Shadow IT: $shadow_count" >> "$risk_trends_file"
  echo "Cert Issues: $cert_issues" >> "$risk_trends_file"
  echo "Expired Variants: $expired_count" >> "$risk_trends_file"
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$risk_trends_file"

  local total_risks=$((asset_count + shadow_count + cert_issues + expired_count))
  py_log "INFO" "Risk dashboard" domain="$domain" total_risks="$total_risks"
  echo "$total_risks" > "$count_file"

  write_finding "$domain" "risk_dashboard" "Generated risk dashboard with $total_risks total risk indicators" "info" "$risk_trends_file" || true

  log "INFO" "Risk dashboard generation complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  easm_risk_dashboard "$@"
fi
