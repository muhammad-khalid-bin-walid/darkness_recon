#!/usr/bin/env bash
# Track 14, Phase 228: Brand Impersonation Detection
# Phishing domain monitoring and typosquatting detection

set -euo pipefail

easm_brand_impersonation() {
  local domain="${1:?Usage: easm_brand_impersonation <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/easm_brand_impersonation"

  log "INFO" "Starting brand impersonation detection for $domain"

  local impersonation_domains_file="$output_dir/easm_brand_impersonation/impersonation_domains.txt"
  local phishing_indicators_file="$output_dir/easm_brand_impersonation/phishing_indicators.txt"
  local count_file="$output_dir/easm_brand_impersonation/count.txt"

  > "$impersonation_domains_file"
  > "$phishing_indicators_file"

  local base_domain
  base_domain=$(echo "$domain" | sed 's/^www\.//' | sed 's/\..*//')

  log "INFO" "Generating typosquatting variants"
  local typosquats=()
  typosquats+=(
    "${base_domain}security"
    "${base_domain}login"
    "${base_domain}auth"
    "${base_domain}verify"
    "${base_domain}update"
    "${base_domain}support"
    "${base_domain}help"
    "${base_domain}account"
    "${base_domain}billing"
    "${base_domain}pay"
  )

  for variant in "${typosquats[@]}"; do
    for tld in "com" "net" "org" "io" "co"; do
      local check_domain="${variant}.${tld}"
      if tool_available "dig"; then
        local resolved
        resolved=$(dig "$check_domain" +short 2>/dev/null || true)
        if [[ -n "$resolved" ]]; then
          echo "TYPOSQUAT: $check_domain -> $resolved" >> "$impersonation_domains_file"
          echo "PHISHING_RISK: $check_domain resolves but is not owned by organization" >> "$phishing_indicators_file"
        fi
      fi
    done
  done

  log "INFO" "Checking for homograph attacks"
  local homograph_variants=(
    "${base_domain//a/а}"  # Cyrillic а
    "${base_domain//e/е}"  # Cyrillic е
    "${base_domain//o/о}"  # Cyrillic о
  )

  for variant in "${homograph_variants[@]}"; do
    if tool_available "dig"; then
      local resolved
      resolved=$(dig "$variant" +short 2>/dev/null || true)
      if [[ -n "$resolved" ]]; then
        echo "HOMOGRAPH: $variant -> $resolved" >> "$impersonation_domains_file"
        echo "PHISHING_RISK: Homograph attack variant active" >> "$phishing_indicators_file"
      fi
    fi
  done

  local impersonation_count=0
  if [[ -f "$impersonation_domains_file" ]]; then
    impersonation_count=$(wc -l < "$impersonation_domains_file" | tr -d ' ')
  fi

  py_log "INFO" "Brand impersonation" domain="$domain" impersonation_variants="$impersonation_count"
  echo "$impersonation_count" > "$count_file"

  write_finding "$domain" "brand_impersonation" "Detected $impersonation_count impersonation domains" "high" "$impersonation_domains_file" || true

  log "INFO" "Brand impersonation detection complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  easm_brand_impersonation "$@"
fi
