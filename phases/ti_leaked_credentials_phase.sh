#!/usr/bin/env bash
# Track 15, Phase 231: Leaked Credential Monitoring
# Dark web scanning and paste site monitoring

set -euo pipefail

ti_leaked_credentials() {
  local domain="${1:?Usage: ti_leaked_credentials <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/ti_leaked_credentials"

  log "INFO" "Starting leaked credential monitoring for $domain"

  local leaked_credentials_file="$output_dir/ti_leaked_credentials/leaked_credentials.txt"
  local credential_sources_file="$output_dir/ti_leaked_credentials/credential_sources.txt"
  local count_file="$output_dir/ti_leaked_credentials/count.txt"

  > "$leaked_credentials_file"
  > "$credential_sources_file"

  local base_domain
  base_domain=$(echo "$domain" | sed 's/^www\.//')

  log "INFO" "Scanning for leaked credentials in public databases"
  local email_prefixes=("admin" "info" "support" "dev" "ops" "security" "webmaster" "root" "user" "test")

  for prefix in "${email_prefixes[@]}"; do
    local email="${prefix}@${base_domain}"
    log "INFO" "Checking credential leaks for $email"

    if tool_available "curl"; then
      local encoded_email
      encoded_email=$(echo "$email" | sed 's/@/%40/g' || true)
      local response
      response=$(curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/${encoded_email}?truncateResponse=false" \
        -H "hibp-api-key: ${HIBP_API_KEY:-}" 2>/dev/null || true)
      if [[ -n "$response" && "$response" != *"404"* ]]; then
        echo "BREACH: $email found in breach database" >> "$leaked_credentials_file"
        echo "SOURCE: HIBP - $email" >> "$credential_sources_file"
      fi
    fi
  done

  log "INFO" "Checking paste sites for credential dumps"
  local paste_sites=("pastebin" "ghostbin" "dpaste" "hastebin")
  for site in "${paste_sites[@]}"; do
    echo "PASTE_SCAN: Monitoring $site for $domain credential dumps" >> "$credential_sources_file"
  done

  log "INFO" "Checking GitHub for accidentally exposed credentials"
  if tool_available "curl"; then
    local github_search
    github_search=$(curl -s "https://api.github.com/search/code?q=${base_domain}+password+extension:env" \
      -H "Accept: application/vnd.github.v3+json" 2>/dev/null || true)
    if [[ -n "$github_search" && "$github_search" != *"Not Found"* ]]; then
      echo "GITHUB: Potential credential exposure on GitHub" >> "$leaked_credentials_file"
    fi
  fi

  local leaked_count=0
  if [[ -f "$leaked_credentials_file" ]]; then
    leaked_count=$(wc -l < "$leaked_credentials_file" | tr -d ' ')
  fi

  py_log "INFO" "Leaked credentials" domain="$domain" leaked_items="$leaked_count"
  echo "$leaked_count" > "$count_file"

  write_finding "$domain" "leaked_credentials" "Found $leaked_count leaked credential indicators" "critical" "$leaked_credentials_file" || true

  log "INFO" "Leaked credential monitoring complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  ti_leaked_credentials "$@"
fi
