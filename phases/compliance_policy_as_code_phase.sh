#!/usr/bin/env bash
# Phase 266: Policy-as-Code Implementation, Automated Compliance Checks, Drift Detection
# Track 18 - Compliance

compliance_policy_as_code() {
    local domain="${1:?Usage: compliance_policy_as_code <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/compliance_policy_as_code"
    mkdir -p "$phase_dir"

    log "INFO" "[POLICY_AS_CODE] Starting policy-as-code checks for $domain"

    local policy_config="$phase_dir/policy_config.json"
    local compliance_drift="$phase_dir/compliance_drift.txt"

    : > "$compliance_drift"

    local count=0

    cat > "$policy_config" <<'POLICYEOF'
{
  "policies": [
    {
      "name": "tls_minimum_version",
      "rule": "tls_version >= 1.2",
      "severity": "critical",
      "enabled": true
    },
    {
      "name": "security_headers",
      "rule": "headers contains hsts, x-content-type-options, x-frame-options",
      "severity": "high",
      "enabled": true
    },
    {
      "name": "cookie_consent",
      "rule": "cookie_consent_banner_detected",
      "severity": "high",
      "enabled": true
    },
    {
      "name": "no_server_info_leak",
      "rule": "server_header not contains version",
      "severity": "medium",
      "enabled": true
    },
    {
      "name": "privacy_policy_required",
      "rule": "/privacy returns 200",
      "severity": "critical",
      "enabled": true
    }
  ],
  "domain": "DOMAIN_PLACEHOLDER",
  "last_checked": "TIMESTAMP_PLACEHOLDER"
}
POLICYEOF

    sed -i "s/DOMAIN_PLACEHOLDER/$domain/g" "$policy_config" 2>/dev/null || true
    sed -i "s/TIMESTAMP_PLACEHOLDER/$(date -u +%Y-%m-%dT%H:%M:%SZ)/g" "$policy_config" 2>/dev/null || true

    if tool_available "curl"; then
        log "INFO" "[POLICY_AS_CODE] Evaluating policies against target"

        local headers
        headers=$(curl -sI --max-time 10 "https://$domain" 2>/dev/null || true)

        if [ -n "$headers" ]; then
            local hsts
            hsts=$(echo "$headers" | grep -ci "strict-transport-security" || true)
            if [ "$hsts" -eq 0 ]; then
                echo "DRIFT: tls_minimum_version - HSTS missing (expected present)" >> "$compliance_drift"
                write_finding "$phase_dir" "POLICY-TLS" "HSTS drift detected" "critical" "drift"
                count=$((count + 1))
            fi

            local server_leak
            server_leak=$(echo "$headers" | grep -i "^server:" | head -1 || true)
            if echo "$server_leak" | grep -qE "[0-9]+\.[0-9]+"; then
                echo "DRIFT: no_server_info_leak - Server version exposed: $server_leak" >> "$compliance_drift"
                write_finding "$phase_dir" "POLICY-SRV" "Server info leak drift" "medium" "drift"
                count=$((count + 1))
            fi
        else
            echo "DRIFT: Could not reach domain for policy evaluation" >> "$compliance_drift"
            count=$((count + 1))
        fi
    fi

    if [ ! -s "$compliance_drift" ]; then
        echo "No policy drift detected" > "$compliance_drift"
    fi

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "policy_as_code_complete" "Policy-as-code evaluation complete: $count drifts found"
    log "INFO" "[POLICY_AS_CODE] Completed: $count drifts detected"

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_endpoint "$phase_dir" "https://$domain" "GET" "Policy-as-code evaluation target"

    return 0
}
