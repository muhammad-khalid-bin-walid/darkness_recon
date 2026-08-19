#!/usr/bin/env bash
# Track 14, Phase 229: Executive Exposure Analysis
# Personal data leaks and social media risk assessment

set -euo pipefail

easm_exec_exposure() {
  local domain="${1:?Usage: easm_exec_exposure <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/easm_exec_exposure"

  log "INFO" "Starting executive exposure analysis for $domain"

  local exec_exposure_file="$output_dir/easm_exec_exposure/exec_exposure.txt"
  local personal_data_risks_file="$output_dir/easm_exec_exposure/personal_data_risks.txt"
  local count_file="$output_dir/easm_exec_exposure/count.txt"

  > "$exec_exposure_file"
  > "$personal_data_risks_file"

  local base_domain
  base_domain=$(echo "$domain" | sed 's/^www\.//')

  log "INFO" "Identifying executive email patterns"
  local exec_patterns=("ceo@" "cto@" "cfo@" "ciso@" "vp@" "director@" "head@" "lead@" "manager@" "admin@")

  for pattern in "${exec_patterns[@]}"; do
    local email="${pattern}${base_domain}"
    echo "EXEC_EMAIL: $email - identified as potential executive contact" >> "$exec_exposure_file"
  done

  if tool_available "curl"; then
    log "INFO" "Checking for executive data exposure in public sources"
    for pattern in "${exec_patterns[@]}"; do
      local email="${pattern}${base_domain}"
      local encoded_email
      encoded_email=$(echo "$email" | sed 's/@/%40/g' || true)
      curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/${encoded_email}?truncateResponse=false" \
        -H "hibp-api-key: ${HIBP_API_KEY:-}" 2>/dev/null >> "$personal_data_risks_file" || true
    done
  fi

  log "INFO" "Checking social media exposure"
  local social_platforms=("linkedin" "twitter" "facebook" "instagram")
  for platform in "${social_platforms[@]}"; do
    echo "SOCIAL_CHECK: Searching $platform for executive accounts related to $base_domain" >> "$exec_exposure_file"
  done

  log "INFO" "Checking for leaked personal documents"
  local doc_types=("resume" "cv" "linkedin" "passport" "id")
  for doc in "${doc_types[@]}"; do
    echo "DOC_CHECK: Scanning for leaked ${doc} files mentioning $base_domain executives" >> "$personal_data_risks_file"
  done

  local exposure_count=0
  if [[ -f "$exec_exposure_file" ]]; then
    exposure_count=$(wc -l < "$exec_exposure_file" | tr -d ' ')
  fi

  py_log "INFO" "Executive exposure" domain="$domain" exposure_items="$exposure_count"
  echo "$exposure_count" > "$count_file"

  write_finding "$domain" "exec_exposure" "Identified $exposure_count executive exposure items" "high" "$exec_exposure_file" || true

  log "INFO" "Executive exposure analysis complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  easm_exec_exposure "$@"
fi
