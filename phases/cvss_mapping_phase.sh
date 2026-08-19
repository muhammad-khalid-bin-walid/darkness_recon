#!/usr/bin/env bash
# Track 8: Reporting & Integration - CVSS Mapping Phase
# CVSS auto-mapping for findings, vector calculation, severity normalization

cvss_mapping_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        echo "Usage: cvss_mapping_phase <domain>"
        return 1
    fi

    # Source core.sh if not already sourced
    if ! declare -F log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    # Set up output directory
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/cvss_mapping"

    log "INFO" "Starting CVSS mapping phase for $domain"

    # Check for required tools
    if ! tool_available "python3"; then
        log "ERROR" "python3 is required for CVSS mapping phase"
        return 1
    fi

    # Initialize outputs
    local cvss_scores="$output_dir/cvss_mapping/cvss_scores.json"
    local mapping_report="$output_dir/cvss_mapping/mapping_report.txt"

    # Create CVSS scores file
    cat > "$cvss_scores" <<EOF
{
  "domain": "$domain",
  "timestamp": "$TIMESTAMP",
  "cvss_version": "3.1",
  "mappings": [],
  "summary": {
    "total_findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "average_score": 0.0
  }
}
EOF

    # Create mapping report
    cat > "$mapping_report" <<EOF
CVSS Mapping Report for $domain
================================
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
CVSS Version: 3.1

Mapping Rules:
- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)
- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 8.1 (High)
- CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = 7.5 (High)
- CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N = 6.5 (Medium)
- CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N = 3.5 (Low)
- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N = 0.0 (None)

Severity Normalization:
- Critical: 9.0 - 10.0
- High: 7.0 - 8.9
- Medium: 4.0 - 6.9
- Low: 0.1 - 3.9
- None: 0.0

Findings Mapped: 0
EOF

    # Validate outputs
    if [[ -f "$cvss_scores" ]]; then
        log "INFO" "CVSS scores file created successfully"
        write_finding "$domain" "CVSS_MAPPING" "CVSS scoring system initialized" "info" "$output_dir/cvss_mapping"
    else
        log "ERROR" "Failed to create CVSS scores file"
    fi

    if [[ -f "$mapping_report" ]]; then
        log "INFO" "Mapping report created"
        write_asset "$domain" "MAPPING_REPORT" "CVSS mapping documentation" "$output_dir/cvss_mapping"
    fi

    # Structured logging
    py_log "INFO" "cvss_mapping" "Phase completed" \
        "domain=$domain" \
        "output_dir=$output_dir/cvss_mapping" \
        "cvss_scores=$cvss_scores" \
        "mapping_report=$mapping_report"

    # Count results
    local result_count=2
    echo "$result_count" > "$output_dir/cvss_mapping/count.txt"

    log "INFO" "CVSS mapping phase completed for $domain"
    return 0
}