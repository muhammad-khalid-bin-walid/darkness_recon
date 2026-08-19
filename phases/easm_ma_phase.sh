#!/usr/bin/env bash
# Track 14, Phase 223: M&A Target Analysis
# Acquisition surface mapping and integration risk assessment

set -euo pipefail

easm_ma() {
  local domain="${1:?Usage: easm_ma <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/easm_ma"

  log "INFO" "Starting M&A target analysis for $domain"

  local ma_surface_file="$output_dir/easm_ma/ma_surface.txt"
  local integration_risks_file="$output_dir/easm_ma/integration_risks.txt"
  local count_file="$output_dir/easm_ma/count.txt"

  > "$ma_surface_file"
  > "$integration_risks_file"

  if tool_available "dig"; then
    log "INFO" "Mapping acquisition surface - DNS records"
    for record_type in A AAAA MX NS TXT CNAME SRV; do
      dig "$domain" "$record_type" +noall +answer 2>/dev/null >> "$ma_surface_file" || true
    done
  fi

  if tool_available "whois"; then
    log "INFO" "Gathering WHOIS data for surface mapping"
    whois "$domain" 2>/dev/null >> "$output_dir/easm_ma/whois_raw.txt" || true
    if [[ -f "$output_dir/easm_ma/whois_raw.txt" ]]; then
      if grep -qi "expires\|expir" "$output_dir/easm_ma/whois_raw.txt"; then
        echo "DOMAIN_REGISTRATION: Domain expiration data collected" >> "$ma_surface_file"
      fi
    fi
  fi

  if tool_available "nmap"; then
    log "INFO" "Scanning for integration points and services"
    nmap -sV --top-ports 100 -T4 "$domain" 2>/dev/null >> "$output_dir/easm_ma/nmap_services.txt" || true
    if [[ -f "$output_dir/easm_ma/nmap_services.txt" ]]; then
      grep -i "open\|filtered" "$output_dir/easm_ma/nmap_services.txt" >> "$integration_risks_file" || true
    fi
  fi

  log "INFO" "Checking for technology stack integration risks"
  if tool_available "curl"; then
    local headers
    headers=$(curl -sI "https://$domain" 2>/dev/null || true)
    echo "$headers" >> "$integration_risks_file"

    if echo "$headers" | grep -qi "x-powered-by\|server:"; then
      echo "TECH_STACK: Detected technology indicators in headers" >> "$integration_risks_file"
    fi
  fi

  local surface_count=0
  if [[ -f "$ma_surface_file" ]]; then
    surface_count=$(wc -l < "$ma_surface_file" | tr -d ' ')
  fi

  py_log "INFO" "M&A target analysis" domain="$domain" surface_items="$surface_count"
  echo "$surface_count" > "$count_file"

  write_finding "$domain" "ma_surface" "Mapped $surface_count acquisition surface items" "info" "$ma_surface_file" || true

  log "INFO" "M&A target analysis complete: $surface_count surface items"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  easm_ma "$@"
fi
