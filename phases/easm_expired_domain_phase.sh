#!/usr/bin/env bash
# Track 14, Phase 224: Expired Domain Monitoring
# Takedown opportunities and brand protection

set -euo pipefail

easm_expired_domain() {
  local domain="${1:?Usage: easm_expired_domain <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/easm_expired_domain"

  log "INFO" "Starting expired domain monitoring for $domain"

  local expired_domains_file="$output_dir/easm_expired_domain/expired_domains.txt"
  local takedown_candidates_file="$output_dir/easm_expired_domain/takedown_candidates.txt"
  local count_file="$output_dir/easm_expired_domain/count.txt"

  > "$expired_domains_file"
  > "$takedown_candidates_file"

  local base_domain
  base_domain=$(echo "$domain" | sed 's/^www\.//')

  if tool_available "whois"; then
    log "INFO" "Checking domain registration status"
    local whois_output
    whois_output=$(whois "$base_domain" 2>/dev/null || true)
    if echo "$whois_output" | grep -qi "expir\|status.*redemption\|pending\|hold"; then
      echo "DOMAIN_STATUS: $base_domain has special status" >> "$expired_domains_file"
      echo "$base_domain" >> "$takedown_candidates_file"
    fi
  fi

  log "INFO" "Generating typosquatting domains for monitoring"
  local typosquat_variants=()
  typosquat_variants+=(
    "${base_domain//./}$base_domain"
    "${base_domain}.com"
    "${base_domain}security.com"
    "${base_domain}-security.com"
    "${base_domain}login.com"
    "${base_domain}-login.com"
    "${base_domain}auth.com"
    "${base_domain}support.com"
  )

  for variant in "${typosquat_variants[@]}"; do
    if tool_available "dig"; then
      local resolve_result
      resolve_result=$(dig "$variant" +short 2>/dev/null || true)
      if [[ -n "$resolve_result" && "$resolve_result" != *"timed out"* ]]; then
        echo "ACTIVE_VARIANT: $variant -> $resolve_result" >> "$expired_domains_file"
        echo "$variant" >> "$takedown_candidates_file"
      fi
    fi
  done

  local expired_count=0
  if [[ -f "$expired_domains_file" ]]; then
    expired_count=$(wc -l < "$expired_domains_file" | tr -d ' ')
  fi

  py_log "INFO" "Expired domain monitoring" domain="$domain" variants_found="$expired_count"
  echo "$expired_count" > "$count_file"

  write_finding "$domain" "expired_domain" "Found $expired_count domain variants for monitoring" "medium" "$expired_domains_file" || true

  log "INFO" "Expired domain monitoring complete: $expired_count variants"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  easm_expired_domain "$@"
fi
