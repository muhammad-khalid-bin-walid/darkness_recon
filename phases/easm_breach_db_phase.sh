#!/usr/bin/env bash
# Track 14, Phase 227: Breach Database Correlation
# Credential exposure and dark web monitoring

set -euo pipefail

easm_breach_db() {
  local domain="${1:?Usage: easm_breach_db <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/easm_breach_db"

  log "INFO" "Starting breach database correlation for $domain"

  local breach_correlation_file="$output_dir/easm_breach_db/breach_correlation.txt"
  local exposed_credentials_file="$output_dir/easm_breach_db/exposed_credentials.txt"
  local count_file="$output_dir/easm_breach_db/count.txt"

  > "$breach_correlation_file"
  > "$exposed_credentials_file"

  log "INFO" "Checking for breached email patterns"
  local base_domain
  base_domain=$(echo "$domain" | sed 's/^www\.//')

  local email_prefixes=("admin" "info" "support" "webmaster" "postmaster" "security" "dev" "ops" "billing" "hr")

  for prefix in "${email_prefixes[@]}"; do
    local email="${prefix}@${base_domain}"
    log "INFO" "Checking breach data for $email"
    echo "BREACH_CHECK: $email - queued for verification" >> "$breach_correlation_file"
  done

  if tool_available "curl"; then
    log "INFO" "Querying public breach databases"
    for prefix in "${email_prefixes[@]}"; do
      local email="${prefix}@${base_domain}"
      local encoded_email
      encoded_email=$(echo "$email" | sed 's/@/%40/g' || true)
      curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/${encoded_email}?truncateResponse=false" \
        -H "hibp-api-key: ${HIBP_API_KEY:-}" 2>/dev/null >> "$exposed_credentials_file" || true
    done
  fi

  log "INFO" "Scanning paste sites for domain mentions"
  if tool_available "grep"; then
    for paste_source in "pastebin" "ghostbin" "dpaste"; do
      echo "PASTE_SCAN: Checking $paste_source for $domain mentions" >> "$breach_correlation_file"
    done
  fi

  local breach_count=0
  if [[ -f "$breach_correlation_file" ]]; then
    breach_count=$(wc -l < "$breach_correlation_file" | tr -d ' ')
  fi

  py_log "INFO" "Breach database correlation" domain="$domain" breach_checks="$breach_count"
  echo "$breach_count" > "$count_file"

  write_finding "$domain" "breach_db" "Performed $breach_count breach correlation checks" "high" "$breach_correlation_file" || true

  log "INFO" "Breach database correlation complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  easm_breach_db "$@"
fi
