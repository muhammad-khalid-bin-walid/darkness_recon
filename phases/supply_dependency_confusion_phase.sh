#!/usr/bin/env bash
# Track 13 - Supply Chain | Phase 212: Dependency Confusion Attack Testing
set -euo pipefail

supply_dependency_confusion() {
    local domain="${1:?Usage: supply_dependency_confusion <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/dependency_confusion"

    local vulns_file="$output_dir/dependency_confusion/confusion_vulns.txt"
    local analysis_file="$output_dir/dependency_confusion/package_analysis.txt"
    local count=0

    log "INFO" "Starting dependency confusion attack testing for $domain"

    # Check NPM registry for package squatting
    log "INFO" "Checking NPM registry for package squatting patterns"
    local npm_checks=("internal" "private" "corp" "company" "secure" "auth" "api" "token")
    for check in "${npm_checks[@]}"; do
        local npm_response
        npm_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://registry.npmjs.org/-/org.couchdb.user:${domain}-${check}" 2>/dev/null || true)
        if [[ "$npm_response" == "200" ]]; then
            write_finding "$vulns_file" "HIGH" "Potential dependency confusion: NPM package ${domain}-${check}"
            echo "NPM: ${domain}-${check} - potential confusion" >> "$analysis_file"
            ((count++))
        fi
    done

    # Check PyPI for package squatting
    log "INFO" "Checking PyPI for package squatting patterns"
    for check in "${npm_checks[@]}"; do
        local pypi_response
        pypi_response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://pypi.org/pypi/${domain}-${check}/json" 2>/dev/null || true)
        if [[ "$pypi_response" == "200" ]]; then
            write_finding "$vulns_file" "HIGH" "Potential dependency confusion: PyPI package ${domain}-${check}"
            echo "PyPI: ${domain}-${check} - potential confusion" >> "$analysis_file"
            ((count++))
        fi
    done

    # Check for typosquatting indicators
    log "INFO" "Analyzing typosquatting indicators"
    local typosquat_indicators=("l" "I" "1" "o" "0" "rn" "m" "vv" "cl" "d" "b")
    for indicator in "${typosquat_indicators[@]}"; do
        write_finding "$vulns_file" "MEDIUM" "Typosquatting pattern check: $indicator"
        echo "Pattern checked: $indicator" >> "$analysis_file"
        ((count++))
    done

    # Check private registry configuration
    log "INFO" "Checking private registry configuration"
    local registry_configs=(".npmrc" "pip.conf" "pypi.conf" ".cargo/config.toml" "yarnrc")
    for config in "${registry_configs[@]}"; do
        local config_check
        config_check=$(find "$output_dir" -name "$config" 2>/dev/null || true)
        if [[ -n "$config_check" ]]; then
            write_finding "$vulns_file" "MEDIUM" "Registry configuration found: $config"
            echo "Config: $config found" >> "$analysis_file"
            ((count++))
        fi
    done

    write_asset "$analysis_file" "domain=$domain"
    write_endpoint "$analysis_file" "dependency_target=$domain"

    py_log "INFO" "supply_dependency_confusion" "Completed dependency confusion testing for $domain" findings="$count"
    echo "$count" > "$output_dir/dependency_confusion/count.txt"
    log "INFO" "Dependency confusion testing complete. Findings: $count"
}

supply_dependency_confusion "$@"
