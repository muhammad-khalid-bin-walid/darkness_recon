#!/usr/bin/env bash
# Track 14, Phase 222: Shadow IT Discovery
# Unauthorized SaaS usage and rogue domain detection for EASM

set -euo pipefail

easm_shadow_it() {
  local domain="${1:?Usage: easm_shadow_it <domain>}"

  source "$(dirname "$0")/../core/core.sh"

  local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
  mkdir -p "$output_dir/easm_shadow_it"

  log "INFO" "Starting shadow IT discovery for $domain"

  local shadow_it_file="$output_dir/easm_shadow_it/shadow_it.txt"
  local rogue_domains_file="$output_dir/easm_shadow_it/rogue_domains.txt"
  local count_file="$output_dir/easm_shadow_it/count.txt"

  > "$shadow_it_file"
  > "$rogue_domains_file"

  if tool_available "dig"; then
    log "INFO" "Checking for unauthorized subdomain takeovers"
    local subdomains_file="$output_dir/easm_shadow_it/subdomains.txt"
    dig "$domain" ANY +noall +answer 2>/dev/null | awk '{print $NF}' | sort -u > "$subdomains_file" || true

    for sub in $(cat "$subdomains_file" 2>/dev/null | head -50); do
      if dig "$sub" CNAME +short 2>/dev/null | grep -qi "herokuapp\|github\.io\|azurewebsites\|amazonaws\|ghost\.io\|surge\.sh"; then
        echo "SUSPECT: $sub -> potential takeover" >> "$shadow_it_file"
        echo "$sub" >> "$rogue_domains_file"
      fi
    done
  fi

  if tool_available "curl"; then
    log "INFO" "Probing for common SaaS shadow IT markers"
    for svc in "slack" "trello" "notion" "asana" "monday" "clickup"; do
      local probe_result
      probe_result=$(curl -sI "https://${svc}.${domain}" 2>/dev/null | head -1 || true)
      if [[ -n "$probe_result" && "$probe_result" != *"404"* && "$probe_result" != *"NXDOMAIN"* ]]; then
        echo "SHADOW_SVC: ${svc}.${domain} -> $probe_result" >> "$shadow_it_file"
      fi
    done
  fi

  local shadow_count=0
  if [[ -f "$shadow_it_file" ]]; then
    shadow_count=$(wc -l < "$shadow_it_file" | tr -d ' ')
  fi

  py_log "INFO" "Shadow IT discovery" domain="$domain" shadow_services="$shadow_count"
  echo "$shadow_count" > "$count_file"

  write_finding "$domain" "shadow_it" "Detected $shadow_count potential shadow IT services" "high" "$shadow_it_file" || true

  log "INFO" "Shadow IT discovery complete: $shadow_count findings"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  easm_shadow_it "$@"
fi
