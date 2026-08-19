#!/usr/bin/env bash
# Track 8: Reporting & Integration - SARIF/DefectDojo Phase
# SARIF and DefectDojo export, standardized format output

sarif_defectdojo_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        echo "Usage: sarif_defectdojo_phase <domain>"
        return 1
    fi

    # Source core.sh if not already sourced
    if ! declare -F log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    # Set up output directory
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/sarif_defectdojo"

    log "INFO" "Starting SARIF/DefectDojo phase for $domain"

    # Check for required tools
    if ! tool_available "python3"; then
        log "ERROR" "python3 is required for SARIF/DefectDojo phase"
        return 1
    fi

    # Initialize outputs
    local sarif_report="$output_dir/sarif_defectdojo/sarif_report.sarif"
    local defectdojo_import="$output_dir/sarif_defectdojo/defectdojo_import.json"

    # Create SARIF report
    cat > "$sarif_report" <<EOF
{
  "\$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "DarkRecon",
          "version": "1.0.0",
          "semanticVersion": "1.0.0",
          "fullName": "DarkRecon Security Scanner",
          "informationUri": "https://darkrecon.local",
          "rules": []
        }
      },
      "artifacts": [
        {
          "location": {
            "uri": "https://$domain"
          },
          "uriBaseId": "%SRCROOT%"
        }
      ],
      "results": [],
      "invocations": [
        {
          "executionSuccessful": true,
          "startTimeUtc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
          "endTimeUtc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        }
      ]
    }
  ]
}
EOF

    # Create DefectDojo import file
    cat > "$defectdojo_import.json" <<EOF
{
  "domain": "$domain",
  "timestamp": "$TIMESTAMP",
  "scan_type": "DarkRecon",
  "engagement": {
    "name": "DarkRecon Scan - $domain",
    "product": "Auto-Generated",
    "engagement_type": "Technical",
    "lead": null,
    "target_start": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "target_end": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  },
  "test": {
    "title": "DarkRecon Scan Results",
    "test_type": "DarkRecon",
    "environment": "Production",
    "scanner": "DarkRecon v1.0.0"
  },
  "findings": [],
  "metrics": {
    "total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "import_settings": {
    "auto_close": false,
    "close_old_findings": false,
    "deduplication_on_engagement": true,
    "enable_sla": true,
    "sla_days": {
      "critical": 1,
      "high": 7,
      "medium": 30,
      "low": 90
    }
  }
}
EOF

    # Validate outputs
    if [[ -f "$sarif_report" ]]; then
        log "INFO" "SARIF report created successfully"
        write_finding "$domain" "SARIF_REPORT" "SARIF format report generated" "info" "$output_dir/sarif_defectdojo"
    else
        log "ERROR" "Failed to create SARIF report"
    fi

    if [[ -f "$defectdojo_import.json" ]]; then
        log "INFO" "DefectDojo import file created"
        write_asset "$domain" "DEFECTDOJO_IMPORT" "DefectDojo import configuration" "$output_dir/sarif_defectdojo"
    fi

    # Structured logging
    py_log "INFO" "sarif_defectdojo" "Phase completed" \
        "domain=$domain" \
        "output_dir=$output_dir/sarif_defectdojo" \
        "sarif_report=$sarif_report" \
        "defectdojo_import=$defectdojo_import"

    # Count results
    local result_count=2
    echo "$result_count" > "$output_dir/sarif_defectdojo/count.txt"

    log "INFO" "SARIF/DefectDojo phase completed for $domain"
    return 0
}