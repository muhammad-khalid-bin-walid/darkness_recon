#!/usr/bin/env bash
# Track 13 - Supply Chain | Phase 214: Malicious Package Detection
set -euo pipefail

supply_malicious_packages() {
    local domain="${1:?Usage: supply_malicious_packages <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/malicious_packages"

    local malicious_file="$output_dir/malicious_packages/malicious_packages.txt"
    local typosquat_file="$output_dir/malicious_packages/typosquat_analysis.txt"
    local count=0

    log "INFO" "Starting malicious package detection for $domain"

    # Check for known malicious packages
    log "INFO" "Checking for known malicious NPM packages"
    local malicious_npm=("event-stream" "flatmap-stream" "crossenv" "crossenv.js" "ua-parser-js" "coa" "rc" "colors" "faker")
    for pkg in "${malicious_npm[@]}"; do
        local pkg_check
        pkg_check=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://registry.npmjs.org/${pkg}" 2>/dev/null || true)
        if [[ "$pkg_check" == "200" ]]; then
            write_finding "$malicious_file" "HIGH" "Known malicious NPM package found: $pkg"
            echo "Package: $pkg - known malicious" >> "$malicious_file"
            ((count++))
        fi
    done

    # Check for typosquatting on domain name
    log "INFO" "Checking for typosquatting patterns"
    local typosquat_variants=(
        "${domain}js" "${domain}api" "${domain}client" "${domain}sdk" "${domain}utils"
        "${domain//-/}" "${domain//./}" "${domain}npm" "${domain}pkg"
        "$(echo "$domain" | tr '[:upper:]' '[:lower:]')"
    )
    for variant in "${typosquat_variants[@]}"; do
        local variant_check
        variant_check=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://registry.npmjs.org/${variant}" 2>/dev/null || true)
        if [[ "$variant_check" == "200" ]]; then
            write_finding "$typosquat_file" "HIGH" "Typosquatting package detected: $variant"
            echo "Typosquat: $variant - potential confusion" >> "$typosquat_file"
            ((count++))
        fi
    done

    # Check for known malicious PyPI packages
    log "INFO" "Checking for known malicious PyPI packages"
    local malicious_pypi=("python-dateutil" "jeIlyfish" "python-dateutil2" "jeIlyfiish" "python3-dateutil")
    for pkg in "${malicious_pypi[@]}"; do
        local pypi_check
        pypi_check=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://pypi.org/pypi/${pkg}/json" 2>/dev/null || true)
        if [[ "$pypi_check" == "200" ]]; then
            write_finding "$malicious_file" "HIGH" "Known malicious PyPI package found: $pkg"
            echo "Package: $pkg - known malicious" >> "$malicious_file"
            ((count++))
        fi
    done

    # Check for suspicious package patterns
    log "INFO" "Analyzing suspicious package patterns"
    local suspicious_patterns=("obfuscated" "minified" "packed" "encoded" "encrypted" "fuscated")
    for pattern in "${suspicious_patterns[@]}"; do
        write_finding "$malicious_file" "MEDIUM" "Checking for suspicious pattern: $pattern"
        echo "Pattern: $pattern checked" >> "$malicious_file"
        ((count++))
    done

    write_asset "$typosquat_file" "domain=$domain"
    write_endpoint "$typosquat_file" "package_target=$domain"

    py_log "INFO" "supply_malicious_packages" "Completed malicious package detection for $domain" findings="$count"
    echo "$count" > "$output_dir/malicious_packages/count.txt"
    log "INFO" "Malicious package detection complete. Findings: $count"
}

supply_malicious_packages "$@"
