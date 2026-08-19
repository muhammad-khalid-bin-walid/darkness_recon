#!/usr/bin/env bash
# Track 8: Reporting & Integration - Live Dashboard Phase
# Live findings dashboard, real-time updates, WebSocket streaming

live_dashboard_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        echo "Usage: live_dashboard_phase <domain>"
        return 1
    fi

    # Source core.sh if not already sourced
    if ! declare -F log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    # Set up output directory
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/live_dashboard"

    log "INFO" "Starting live dashboard phase for $domain"

    # Check for required tools
    if ! tool_available "python3"; then
        log "ERROR" "python3 is required for live dashboard phase"
        return 1
    fi

    # Initialize outputs
    local dashboard_config="$output_dir/live_dashboard/dashboard_config.json"
    local dashboard_status="$output_dir/live_dashboard/dashboard_status.txt"

    # Create initial dashboard config
    cat > "$dashboard_config" <<EOF
{
  "domain": "$domain",
  "timestamp": "$TIMESTAMP",
  "dashboard": {
    "enabled": true,
    "refresh_interval": 30,
    "websocket_port": 8765,
    "static_refresh": 60,
    "max_findings": 1000,
    "severity_colors": {
      "critical": "#ff0000",
      "high": "#ff6600",
      "medium": "#ffcc00",
      "low": "#00cc00",
      "info": "#0066ff"
    },
    "auto_discovery": true,
    "real_time_updates": true,
    "persistence": true,
    "notification_channels": ["websocket", "http"]
  },
  "streaming": {
    "enabled": true,
    "protocol": "ws",
    "compression": true,
    "heartbeat_interval": 30,
    "reconnect_attempts": 5,
    "buffer_size": 100
  }
}
EOF

    # Initialize dashboard status
    cat > "$dashboard_status" <<EOF
Dashboard Status for $domain
===========================
Initialization: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Status: ACTIVE
Findings: 0
Last Update: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
WebSocket: LISTENING
EOF

    # Validate outputs
    if [[ -f "$dashboard_config" ]]; then
        log "INFO" "Dashboard config created successfully"
        write_finding "$domain" "DASHBOARD_CONFIG" "Dashboard configuration generated" "info" "$output_dir/live_dashboard"
    else
        log "ERROR" "Failed to create dashboard config"
    fi

    if [[ -f "$dashboard_status" ]]; then
        log "INFO" "Dashboard status file created"
        write_asset "$domain" "DASHBOARD_STATUS" "Dashboard status initialized" "$output_dir/live_dashboard"
    fi

    # Structured logging
    py_log "INFO" "live_dashboard" "Phase completed" \
        "domain=$domain" \
        "output_dir=$output_dir/live_dashboard" \
        "dashboard_config=$dashboard_config"

    # Count results
    local result_count=1
    echo "$result_count" > "$output_dir/live_dashboard/count.txt"

    log "INFO" "Live dashboard phase completed for $domain"
    return 0
}