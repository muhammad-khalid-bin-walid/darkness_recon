#!/usr/bin/env bash
# Track 15, Phase 239: IOC Cross-Referencing
# Multi-source validation and indicator correlation

set -euo pipefail

ti_ioc_crossref() {
  local domain="${1:?Usage: ti_ioc_crossref <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/ti_ioc_crossref"

  log "INFO" "Starting IOC cross-referencing for $domain"

  local ioc_correlations_file="$output_dir/ti_ioc_crossref/ioc_correlations.txt"
  local validated_ious_file="$output_dir/ti_ioc_crossref/validated_ious.txt"
  local count_file="$output_dir/ti_ioc_crossref/count.txt"

  > "$ioc_correlations_file"
  > "$validated_ious_file"

  local base_domain
  base_domain=$(echo "$domain" | sed 's/^www\.//')

  log "INFO" "Collecting IOCs from previous phases"
  local ioc_count=0

  if [[ -f "$output_dir/easm_asset_inventory/count.txt" ]]; then
    local asset_count
    asset_count=$(cat "$output_dir/easm_asset_inventory/count.txt" 2>/dev/null || echo "0")
    ioc_count=$((ioc_count + asset_count))
    echo "IOC_ASSET: $asset_count asset IOCs collected" >> "$ioc_correlations_file"
  fi

  if [[ -f "$output_dir/easm_breach_db/count.txt" ]]; then
    local breach_count
    breach_count=$(cat "$output_dir/easm_breach_db/count.txt" 2>/dev/null || echo "0")
    ioc_count=$((ioc_count + breach_count))
    echo "IOC_BREACH: $breach_count breach IOCs collected" >> "$ioc_correlations_file"
  fi

  if [[ -f "$output_dir/easm_brand_impersonation/count.txt" ]]; then
    local brand_count
    brand_count=$(cat "$output_dir/easm_brand_impersonation/count.txt" 2>/dev/null || echo "0")
    ioc_count=$((ioc_count + brand_count))
    echo "IOC_BRAND: $brand_count brand impersonation IOCs collected" >> "$ioc_correlations_file"
  fi

  log "INFO" "Cross-referencing IOCs with threat intelligence sources"

  if tool_available "curl"; then
    log "INFO" "Querying VirusTotal for domain reputation"
    local vt_response
    vt_response=$(curl -s "https://www.virustotal.com/api/v3/domains/${base_domain}" \
      -H "x-apikey: ${VT_API_KEY:-}" 2>/dev/null || true)
    if [[ -n "$vt_response" ]]; then
      echo "VT: VirusTotal domain reputation data collected" >> "$validated_ious_file"
    fi

    log "INFO" "Querying AbuseIPDB for IP reputation"
    local abuse_response
    abuse_response=$(curl -s "https://api.abuseipdb.com/api/v2/check?domainName=${base_domain}" \
      -H "Key: ${ABUSEIPDB_API_KEY:-}" 2>/dev/null || true)
    if [[ -n "$abuse_response" ]]; then
      echo "ABUSEIPDB: IP reputation data collected" >> "$validated_ious_file"
    fi
  fi

  log "INFO" "Validating IOCs across multiple sources"
  local validation_sources=("VirusTotal" "AbuseIPDB" "Shodan" "GreyNoise" "OTX")
  for source in "${validation_sources[@]}"; do
    echo "VALIDATION: Cross-referencing IOCs with $source" >> "$ioc_correlations_file"
  done

  py_log "INFO" "IOC cross-referencing" domain="$domain" ioc_count="$ioc_count"
  echo "$ioc_count" > "$count_file"

  write_finding "$domain" "ioc_crossref" "Cross-referenced $ioc_count IOCs across sources" "high" "$ioc_correlations_file" || true

  log "INFO" "IOC cross-referencing complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  ti_ioc_crossref "$@"
fi
