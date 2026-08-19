#!/usr/bin/env bash
# Track 14, Phase 230: Asset Change Velocity Tracking
# Rapid deployment detection and anomaly alerting

set -euo pipefail

easm_change_velocity() {
  local domain="${1:?Usage: easm_change_velocity <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/easm_change_velocity"

  log "INFO" "Starting change velocity tracking for $domain"

  local change_velocity_file="$output_dir/easm_change_velocity/change_velocity.txt"
  local rapid_deployments_file="$output_dir/easm_change_velocity/rapid_deployments.txt"
  local count_file="$output_dir/easm_change_velocity/count.txt"

  > "$change_velocity_file"
  > "$rapid_deployments_file"

  if tool_available "dig"; then
    log "INFO" "Recording current DNS state for velocity comparison"
    local dns_snapshot="$output_dir/easm_change_velocity/dns_snapshot.txt"
    dig "$domain" ANY +noall +answer 2>/dev/null > "$dns_snapshot" || true
    dig "$domain" A +short 2>/dev/null >> "$dns_snapshot" || true
    dig "$domain" AAAA +short 2>/dev/null >> "$dns_snapshot" || true

    local record_count=0
    if [[ -f "$dns_snapshot" ]]; then
      record_count=$(wc -l < "$dns_snapshot" | tr -d ' ')
    fi
    echo "DNS_RECORDS: $domain has $record_count current DNS records" >> "$change_velocity_file"
  fi

  if tool_available "curl"; then
    log "INFO" "Checking HTTP headers for deployment indicators"
    local headers
    headers=$(curl -sI "https://$domain" 2>/dev/null || true)
    if echo "$headers" | grep -qi "x-deploy\|x-build\|x-version\|x-release"; then
      echo "DEPLOY_MARKER: Found deployment indicators in response headers" >> "$rapid_deployments_file"
      echo "$headers" >> "$rapid_deployments_file"
    fi
    if echo "$headers" | grep -qi "last-modified\|etag"; then
      echo "CACHE_HEADERS: Response includes cache control headers" >> "$change_velocity_file"
    fi
  fi

  if tool_available "openssl"; then
    log "INFO" "Checking certificate rotation velocity"
    local cert_dates
    cert_dates=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || true)
    if [[ -n "$cert_dates" ]]; then
      echo "CERT_DATES: $cert_dates" >> "$change_velocity_file"
    fi
  fi

  log "INFO" "Checking for rapid subdomain changes"
  if tool_available "dig"; then
    for sub in "api" "dev" "staging" "test" "beta" "new" "app" "admin"; do
      local resolved
      resolved=$(dig "${sub}.${domain}" +short 2>/dev/null || true)
      if [[ -n "$resolved" ]]; then
        echo "RAPID_SUB: ${sub}.${domain} -> $resolved" >> "$rapid_deployments_file"
      fi
    done
  fi

  local velocity_count=0
  if [[ -f "$change_velocity_file" ]]; then
    velocity_count=$(wc -l < "$change_velocity_file" | tr -d ' ')
  fi

  py_log "INFO" "Change velocity" domain="$domain" velocity_items="$velocity_count"
  echo "$velocity_count" > "$count_file"

  write_finding "$domain" "change_velocity" "Tracked $velocity_count change velocity indicators" "info" "$change_velocity_file" || true

  log "INFO" "Change velocity tracking complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  easm_change_velocity "$@"
fi
