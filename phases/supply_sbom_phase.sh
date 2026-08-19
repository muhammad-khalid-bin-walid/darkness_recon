#!/usr/bin/env bash
# Track 13 - Supply Chain | Phase 211: SBOM Generation and Analysis
set -euo pipefail

supply_sbom() {
    local domain="${1:?Usage: supply_sbom <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/sbom"

    local report_file="$output_dir/sbom/sbom_report.json"
    local dep_file="$output_dir/sbom/dependency_list.txt"
    local count=0

    log "INFO" "Starting SBOM generation and analysis for $domain"

    # Check for SBOM tools
    log "INFO" "Checking available SBOM generation tools"
    local sbom_tools=("syft" "trivy" "cyclonedx" "spdx" "grype" "sw360")
    for tool in "${sbom_tools[@]}"; do
        if tool_available "$tool"; then
            log "INFO" "SBOM tool found: $tool"
            echo "Tool: $tool - available" >> "$dep_file"
            ((count++))
        fi
    done

    # Check for package managers and dependency files
    log "INFO" "Scanning for dependency manifests"
    local manifest_files=("package.json" "requirements.txt" "Pipfile" "Gemfile" "go.mod" "pom.xml" "build.gradle" "Cargo.toml" "composer.json" "yarn.lock" "package-lock.json" "poetry.lock")
    for manifest in "${manifest_files[@]}"; do
        local manifest_check
        manifest_check=$(find "$output_dir" -name "$manifest" 2>/dev/null || true)
        if [[ -n "$manifest_check" ]]; then
            write_finding "$dep_file" "INFO" "Dependency manifest found: $manifest"
            echo "$manifest: found" >> "$dep_file"
            ((count++))
        fi
    done

    # Analyze license compliance
    log "INFO" "Checking license compliance"
    local license_files=("LICENSE" "LICENSE.md" "LICENSE.txt" "LICENCE" "COPYING")
    for license_file in "${license_files[@]}"; do
        local license_check
        license_check=$(find "$output_dir" -name "$license_file" 2>/dev/null || true)
        if [[ -n "$license_check" ]]; then
            write_finding "$dep_file" "INFO" "License file found: $license_file"
            echo "$license_file: found" >> "$dep_file"
            ((count++))
        fi
    done

    # Generate SBOM report structure
    log "INFO" "Generating SBOM report structure"
    cat > "$report_file" << EOF
{
  "domain": "$domain",
  "scan_type": "sbom_generation",
  "tools_found": "$count",
  "status": "analysis_complete",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

    write_asset "$dep_file" "domain=$domain"
    write_endpoint "$dep_file" "sbom_target=$domain"

    py_log "INFO" "supply_sbom" "Completed SBOM analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/sbom/count.txt"
    log "INFO" "SBOM analysis complete. Findings: $count"
}

supply_sbom "$@"
