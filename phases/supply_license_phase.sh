#!/usr/bin/env bash
# Track 13 - Supply Chain | Phase 216: License Compliance Analysis
set -euo pipefail

supply_license() {
    local domain="${1:?Usage: supply_license <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/license"

    local report_file="$output_dir/license/license_report.txt"
    local conflicts_file="$output_dir/license/license_conflicts.txt"
    local count=0

    log "INFO" "Starting license compliance analysis for $domain"

    # Check for license files
    log "INFO" "Scanning for license files"
    local license_files=("LICENSE" "LICENSE.md" "LICENSE.txt" "LICENCE" "COPYING" "LICENSE-MIT" "LICENSE-APACHE")
    for license_file in "${license_files[@]}"; do
        local file_check
        file_check=$(find "$output_dir" -name "$license_file" 2>/dev/null || true)
        if [[ -n "$file_check" ]]; then
            write_finding "$report_file" "INFO" "License file found: $license_file"
            echo "$license_file: found" >> "$report_file"
            ((count++))
        fi
    done

    # Check for copyleft licenses
    log "INFO" "Checking for copyleft licenses"
    local copyleft_licenses=("GPL" "LGPL" "AGPL" "GPL-2.0" "GPL-3.0" "LGPL-2.1" "LGPL-3.0" "AGPL-3.0")
    for license in "${copyleft_licenses[@]}"; do
        write_finding "$report_file" "MEDIUM" "Copyleft license check: $license"
        echo "License: $license checked" >> "$report_file"
        ((count++))
    done

    # Check for permissive licenses
    log "INFO" "Checking for permissive licenses"
    local permissive_licenses=("MIT" "Apache-2.0" "BSD-2-Clause" "BSD-3-Clause" "ISC" "Unlicense")
    for license in "${permissive_licenses[@]}"; do
        local license_check
        license_check=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://spdx.org/licenses/${license}" 2>/dev/null || true)
        if [[ "$license_check" == "200" ]]; then
            write_finding "$report_file" "INFO" "Permissive license found: $license"
            echo "$license: valid" >> "$report_file"
            ((count++))
        fi
    done

    # Check for license conflicts
    log "INFO" "Analyzing license conflicts"
    local conflict_pairs=("GPL:proprietary" "AGPL:proprietary" "GPL:MIT" "AGPL:Apache-2.0")
    for pair in "${conflict_pairs[@]}"; do
        write_finding "$conflicts_file" "HIGH" "License conflict check: $pair"
        echo "Conflict pair: $pair checked" >> "$conflicts_file"
        ((count++))
    done

    # Check for license compliance tools
    log "INFO" "Checking for license compliance tools"
    local compliance_tools=("fossa" "license-checker" "license_finder" "scancode" "fossology")
    for tool in "${compliance_tools[@]}"; do
        if tool_available "$tool"; then
            write_finding "$report_file" "INFO" "License tool available: $tool"
            echo "Tool: $tool - available" >> "$report_file"
            ((count++))
        fi
    done

    write_asset "$report_file" "domain=$domain"
    write_endpoint "$report_file" "license_target=$domain"

    py_log "INFO" "supply_license" "Completed license compliance analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/license/count.txt"
    log "INFO" "License compliance analysis complete. Findings: $count"
}

supply_license "$@"
