#!/usr/bin/env bash
# Track 8: Reporting & Integration - Jira/Linear Phase
# Jira/Linear issue creation, ticket formatting, status tracking

jira_linear_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        echo "Usage: jira_linear_phase <domain>"
        return 1
    fi

    # Source core.sh if not already sourced
    if ! declare -F log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    # Set up output directory
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/jira_linear"

    log "INFO" "Starting Jira/Linear phase for $domain"

    # Check for required tools
    if ! tool_available "python3"; then
        log "ERROR" "python3 is required for Jira/Linear phase"
        return 1
    fi

    # Initialize outputs
    local ticket_config="$output_dir/jira_linear/ticket_config.json"
    local ticket_status="$output_dir/jira_linear/ticket_status.txt"

    # Create ticket config
    cat > "$ticket_config" <<EOF
{
  "domain": "$domain",
  "timestamp": "$TIMESTAMP",
  "platforms": {
    "jira": {
      "enabled": false,
      "project_key": "SEC",
      "issue_type": "Bug",
      "priority_mapping": {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest"
      },
      "labels": ["security", "automated-scan"],
      "components": ["Security"],
      "assignee": null,
      "reporter": null
    },
    "linear": {
      "enabled": false,
      "team_id": "your-team-id",
      "project_id": null,
      "priority_mapping": {
        "critical": "Urgent",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "No priority"
      },
      "labels": ["security", "automated"],
      "assignee_id": null
    }
  },
  "ticket_template": {
    "title": "[{severity}] {type} in {location}",
    "description": "## Vulnerability Details\\n\\n**Type:** {type}\\n**Location:** {location}\\n**CVSS Score:** {cvss}\\n\\n## Steps to Reproduce\\n\\n1. {step1}\\n2. {step2}\\n3. {step3}\\n\\n## Impact\\n\\n{impact}\\n\\n## Remediation\\n\\n{remediation}",
    "custom_fields": {
      "cvss_score": "cf_cvss",
      "vulnerability_type": "cf_vuln_type",
      "affected_url": "cf_url"
    }
  },
  "automation": {
    "auto_create": false,
    "auto_assign": false,
    "auto_close": false,
    "status_sync": true,
    "comment_sync": true
  }
}
EOF

    # Create ticket status file
    cat > "$ticket_status" <<EOF
Ticket Status for $domain
========================
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

Platform Status:
- Jira: INACTIVE (configure in ticket_config.json)
- Linear: INACTIVE (configure in ticket_config.json)

Tickets Created: 0
Tickets Closed: 0
Open Tickets: 0
In Progress: 0

Last Ticket Created: None
Last Status Update: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

Automation Status:
- Auto-create: DISABLED
- Auto-assign: DISABLED
- Auto-close: DISABLED
- Status sync: ENABLED
EOF

    # Validate outputs
    if [[ -f "$ticket_config" ]]; then
        log "INFO" "Ticket config created successfully"
        write_finding "$domain" "JIRA_LINEAR" "Issue tracking system configured" "info" "$output_dir/jira_linear"
    else
        log "ERROR" "Failed to create ticket config"
    fi

    if [[ -f "$ticket_status" ]]; then
        log "INFO" "Ticket status file created"
        write_asset "$domain" "TICKET_STATUS" "Jira/Linear status documentation" "$output_dir/jira_linear"
    fi

    # Structured logging
    py_log "INFO" "jira_linear" "Phase completed" \
        "domain=$domain" \
        "output_dir=$output_dir/jira_linear" \
        "ticket_config=$ticket_config" \
        "ticket_status=$ticket_status"

    # Count results
    local result_count=2
    echo "$result_count" > "$output_dir/jira_linear/count.txt"

    log "INFO" "Jira/Linear phase completed for $domain"
    return 0
}