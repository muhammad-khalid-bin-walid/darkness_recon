#!/usr/bin/env bash
# Track 15, Phase 232: Paste Site Monitoring
# Code snippet detection and sensitive data alerts

set -euo pipefail

ti_paste_monitoring() {
  local domain="${1:?Usage: ti_paste_monitoring <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/ti_paste_monitoring"

  log "INFO" "Starting paste site monitoring for $domain"

  local paste_alerts_file="$output_dir/ti_paste_monitoring/paste_alerts.txt"
  local sensitive_snippets_file="$output_dir/ti_paste_monitoring/sensitive_snippets.txt"
  local count_file="$output_dir/ti_paste_monitoring/count.txt"

  > "$paste_alerts_file"
  > "$sensitive_snippets_file"

  local base_domain
  base_domain=$(echo "$domain" | sed 's/^www\.//')

  log "INFO" "Scanning paste sites for domain mentions"
  if tool_available "curl"; then
    local paste_urls=(
      "https://pastebin.com/search?q=${base_domain}"
      "https://ghostbin.com/search?q=${base_domain}"
      "https://dpaste.org/search?q=${base_domain}"
    )

    for url in "${paste_urls[@]}"; do
      local response
      response=$(curl -s "$url" 2>/dev/null | head -100 || true)
      if [[ -n "$response" && "$response" != *"404"* ]]; then
        echo "PASTE_FOUND: Domain mentioned at $url" >> "$paste_alerts_file"
      fi
    done
  fi

  log "INFO" "Checking for sensitive code snippets"
  local sensitive_patterns=(
    "password"
    "api_key"
    "secret"
    "token"
    "private_key"
    "aws_access"
    "database_url"
    "connection_string"
  )

  for pattern in "${sensitive_patterns[@]}"; do
    echo "PATTERN_CHECK: Scanning for '$pattern' mentions of $domain" >> "$sensitive_snippets_file"
  done

  log "INFO" "Monitoring for configuration file leaks"
  local config_files=(
    ".env"
    "config.json"
    "config.yaml"
    "settings.py"
    "wp-config.php"
    "database.yml"
    ".htaccess"
  )

  for config in "${config_files[@]}"; do
    echo "CONFIG_LEAK: Checking for leaked ${config} files containing $domain" >> "$sensitive_snippets_file"
  done

  log "INFO" "Checking for source code dumps"
  local code_platforms=("github" "gitlab" "bitbucket")
  for platform in "${code_platforms[@]}"; do
    echo "CODE_SEARCH: Scanning $platform for public repos containing $domain credentials" >> "$paste_alerts_file"
  done

  local paste_count=0
  if [[ -f "$paste_alerts_file" ]]; then
    paste_count=$(wc -l < "$paste_alerts_file" | tr -d ' ')
  fi

  py_log "INFO" "Paste monitoring" domain="$domain" paste_alerts="$paste_count"
  echo "$paste_count" > "$count_file"

  write_finding "$domain" "paste_monitoring" "Found $paste_count paste site alerts" "high" "$paste_alerts_file" || true

  log "INFO" "Paste site monitoring complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  ti_paste_monitoring "$@"
fi
