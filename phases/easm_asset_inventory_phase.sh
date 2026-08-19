#!/usr/bin/env bash
# Track 14, Phase 221: External Asset Inventory
# Automated discovery and asset classification for EASM

set -euo pipefail

easm_asset_inventory() {
  local domain="${1:?Usage: easm_asset_inventory <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/easm_asset_inventory"

  log "INFO" "Starting external asset inventory for $domain"

  local asset_inventory="$output_dir/easm_asset_inventory/asset_inventory.json"
  local asset_classification="$output_dir/easm_asset_inventory/asset_classification.txt"
  local count_file="$output_dir/easm_asset_inventory/count.txt"

  echo "[]" > "$asset_inventory"
  > "$asset_classification"

  if tool_available "dig"; then
    log "INFO" "Running DNS enumeration for asset discovery"
    dig "$domain" ANY +noall +answer 2>/dev/null >> "$output_dir/easm_asset_inventory/dns_raw.txt" || true
  fi

  if tool_available "amass"; then
    log "INFO" "Running Amass passive enumeration"
    amass enum -passive -d "$domain" 2>/dev/null >> "$output_dir/easm_asset_inventory/amass_hosts.txt" || true
  fi

  if tool_available "subfinder"; then
    log "INFO" "Running subfinder for subdomain discovery"
    subfinder -d "$domain" -silent 2>/dev/null >> "$output_dir/easm_asset_inventory/subfinder_hosts.txt" || true
  fi

  local host_count=0
  if [[ -f "$output_dir/easm_asset_inventory/amass_hosts.txt" ]]; then
    host_count=$(wc -l < "$output_dir/easm_asset_inventory/amass_hosts.txt" | tr -d ' ')
  elif [[ -f "$output_dir/easm_asset_inventory/subfinder_hosts.txt" ]]; then
    host_count=$(wc -l < "$output_dir/easm_asset_inventory/subfinder_hosts.txt" | tr -d ' ')
  fi

  py_log "INFO" "Asset inventory" domain="$domain" assets_discovered="$host_count"
  echo "$host_count" > "$count_file"

  write_finding "$domain" "asset_inventory" "Discovered $host_count external assets for $domain" "medium" "$asset_classification" || true

  for host in $(cat "$output_dir/easm_asset_inventory/amass_hosts.txt" 2>/dev/null || true); do
    write_asset "$domain" "$host" "subdomain" "$asset_inventory" || true
  done

  log "INFO" "Asset inventory complete: $host_count assets found"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  easm_asset_inventory "$@"
fi
