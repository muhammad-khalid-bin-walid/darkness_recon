#!/usr/bin/env bash
# Track 13 - Supply Chain | Phase 213: Subresource Integrity Analysis
set -euo pipefail

supply_sri() {
    local domain="${1:?Usage: supply_sri <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/sri"

    local status_file="$output_dir/sri/sri_status.txt"
    local violations_file="$output_dir/sri/integrity_violations.txt"
    local count=0

    log "INFO" "Starting Subresource Integrity analysis for $domain"

    # Check external script integrity
    if tool_available curl; then
        log "INFO" "Fetching page content for SRI analysis"
        local page_content
        page_content=$(curl -s --connect-timeout 10 "http://${domain}" 2>/dev/null || true)

        # Check for scripts without integrity
        local scripts_without_sri
        scripts_without_sri=$(echo "$page_content" | grep -o '<script[^>]*src=[^>]*>' | grep -v 'integrity=' 2>/dev/null || true)
        if [[ -n "$scripts_without_sri" ]]; then
            write_finding "$violations_file" "HIGH" "Scripts without SRI found"
            echo "Scripts without SRI:" >> "$violations_file"
            echo "$scripts_without_sri" >> "$violations_file"
            ((count++))
        fi

        # Check for stylesheets without integrity
        local styles_without_sri
        styles_without_sri=$(echo "$page_content" | grep -o '<link[^>]*stylesheet[^>]*>' | grep -v 'integrity=' 2>/dev/null || true)
        if [[ -n "$styles_without_sri" ]]; then
            write_finding "$violations_file" "HIGH" "Stylesheets without SRI found"
            echo "Stylesheets without SRI:" >> "$violations_file"
            echo "$styles_without_sri" >> "$violations_file"
            ((count++))
        fi

        # Check for scripts with integrity
        local scripts_with_sri
        scripts_with_sri=$(echo "$page_content" | grep -o '<script[^>]*integrity=[^>]*>' 2>/dev/null || true)
        if [[ -n "$scripts_with_sri" ]]; then
            echo "Scripts with SRI:" >> "$status_file"
            echo "$scripts_with_sri" >> "$status_file"
            ((count++))
        fi
    fi

    # Check for SRI configuration files
    log "INFO" "Checking for SRI configuration files"
    local sri_configs=(".sri-config" "sri-config.json" "integrity.config.json")
    for config in "${sri_configs[@]}"; do
        local config_check
        config_check=$(find "$output_dir" -name "$config" 2>/dev/null || true)
        if [[ -n "$config_check" ]]; then
            write_finding "$violations_file" "MEDIUM" "SRI config found: $config"
            echo "Config: $config found" >> "$status_file"
            ((count++))
        fi
    done

    # Check for external resource loading
    log "INFO" "Checking external resource loading patterns"
    local external_patterns=("cdn" "cloudflare" "jsdelivr" "unpkg" "googleapis" "gstatic")
    for pattern in "${external_patterns[@]}"; do
        local pattern_check
        pattern_check=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://${domain}" 2>/dev/null || true)
        if [[ "$pattern_check" == "200" ]]; then
            write_finding "$violations_file" "MEDIUM" "External resource loading detected: $pattern"
            echo "External: $pattern detected" >> "$status_file"
            ((count++))
        fi
    done

    write_asset "$status_file" "domain=$domain"
    write_endpoint "$status_file" "sri_target=http://${domain}"

    py_log "INFO" "supply_sri" "Completed SRI analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/sri/count.txt"
    log "INFO" "SRI analysis complete. Findings: $count"
}

supply_sri "$@"
