#!/usr/bin/env bash
# Track 14, Phase 225: Certificate Expiry Monitoring
# Renewal tracking and service impact assessment

set -euo pipefail

easm_cert_expiry() {
  local domain="${1:?Usage: easm_cert_expiry <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/easm_cert_expiry"

  log "INFO" "Starting certificate expiry monitoring for $domain"

  local cert_expiry_file="$output_dir/easm_cert_expiry/cert_expiry_monitor.txt"
  local renewal_schedule_file="$output_dir/easm_cert_expiry/renewal_schedule.txt"
  local count_file="$output_dir/easm_cert_expiry/count.txt"

  > "$cert_expiry_file"
  > "$renewal_schedule_file"

  if tool_available "openssl"; then
    log "INFO" "Checking SSL certificate expiry"
    local cert_info
    cert_info=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null || true)

    if [[ -n "$cert_info" ]]; then
      echo "$cert_info" >> "$cert_expiry_file"

      local expiry_date
      expiry_date=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2 || true)
      if [[ -n "$expiry_date" ]]; then
        echo "EXPIRY: $domain cert expires: $expiry_date" >> "$renewal_schedule_file"
      fi

      local issuer
      issuer=$(echo "$cert_info" | grep "issuer" | cut -d= -f2 || true)
      if [[ -n "$issuer" ]]; then
        echo "ISSUER: $domain cert issuer: $issuer" >> "$renewal_schedule_file"
      fi
    fi
  fi

  if tool_available "curl"; then
    log "INFO" "Testing HTTPS certificate chain"
    local curl_output
    curl_output=$(curl -svI "https://$domain" 2>&1 | grep -i "expire\|issuer\|subject\|SSL" || true)
    if [[ -n "$curl_output" ]]; then
      echo "$curl_output" >> "$cert_expiry_file"
    fi
  fi

  local cert_count=0
  if [[ -f "$cert_expiry_file" ]]; then
    cert_count=$(wc -l < "$cert_expiry_file" | tr -d ' ')
  fi

  py_log "INFO" "Certificate expiry monitoring" domain="$domain" cert_lines="$cert_count"
  echo "$cert_count" > "$count_file"

  write_finding "$domain" "cert_expiry" "Collected $cert_count certificate data points" "info" "$cert_expiry_file" || true

  log "INFO" "Certificate expiry monitoring complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  easm_cert_expiry "$@"
fi
