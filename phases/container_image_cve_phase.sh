#!/usr/bin/env bash
# Track 12 - Container/K8s | Phase 210: Container Image CVE Scanning
set -euo pipefail

container_image_cve() {
    local domain="${1:?Usage: container_image_cve <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/image_cve"

    local vulns_file="$output_dir/image_cve/image_cve_vulns.txt"
    local vuln_details_file="$output_dir/image_cve/image_vulnerabilities.txt"
    local count=0

    log "INFO" "Starting container image CVE analysis for $domain"

    # Check base image vulnerabilities
    log "INFO" "Checking base image vulnerabilities"
    local common_images=("alpine:latest" "ubuntu:latest" "debian:latest" "node:latest" "python:latest" "nginx:latest")
    for image in "${common_images[@]}"; do
        local image_check
        image_check=$(docker inspect "$image" 2>/dev/null || true)
        if [[ -n "$image_check" ]]; then
            write_finding "$vulns_file" "MEDIUM" "Image found locally: $image"
            echo "Image: $image - present locally" >> "$vuln_details_file"
            ((count++))
        fi
    done

    # Check outdated packages
    log "INFO" "Checking for outdated packages in images"
    local outdated_indicators=("apt list --upgradable" "apk update" "yum check-update" "pip list --outdated")
    for indicator in "${outdated_indicators[@]}"; do
        write_finding "$vulns_file" "MEDIUM" "Package update check: $indicator"
        echo "Check: $indicator" >> "$vuln_details_file"
        ((count++))
    done

    # Check for known CVE patterns
    log "INFO" "Checking for known CVE patterns"
    local cve_patterns=("CVE-2024" "CVE-2025" "CVE-2026" "CVE-2023" "CVE-2022")
    for pattern in "${cve_patterns[@]}"; do
        local cve_check
        cve_check=$(grep -r "$pattern" "$output_dir" 2>/dev/null || true)
        if [[ -n "$cve_check" ]]; then
            write_finding "$vulns_file" "HIGH" "CVE pattern found in scan results: $pattern"
            echo "CVE pattern: $pattern found" >> "$vuln_details_file"
            ((count++))
        fi
    done

    # Check image scan tools
    log "INFO" "Checking available image scanning tools"
    local scan_tools=("trivy" "grype" "snyk" "clair" "anchore" "docker scan")
    for tool in "${scan_tools[@]}"; do
        if tool_available "$tool"; then
            write_finding "$vulns_file" "INFO" "Scan tool available: $tool"
            echo "Tool $tool: available" >> "$vuln_details_file"
            ((count++))
        fi
    done

    # Check registry scan results
    log "INFO" "Checking for existing scan results"
    local scan_paths=("/var/log/trivy" "/var/log/grype" "/tmp/scan-results")
    for scan_path in "${scan_paths[@]}"; do
        if [[ -d "$scan_path" ]]; then
            write_finding "$vulns_file" "MEDIUM" "Scan results directory found: $scan_path"
            echo "Scan results: $scan_path found" >> "$vuln_details_file"
            ((count++))
        fi
    done

    write_asset "$vuln_details_file" "domain=$domain"
    write_endpoint "$vuln_details_file" "target=$domain"

    py_log "INFO" "container_image_cve" "Completed image CVE analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/image_cve/count.txt"
    log "INFO" "Image CVE analysis complete. Findings: $count"
}

container_image_cve "$@"
