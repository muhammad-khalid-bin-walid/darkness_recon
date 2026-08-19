#!/bin/bash
# Track 17 - Wireless/IoT | Phase 260: IoT Inventory Correlation
# Asset-to-vulnerability mapping, risk scoring

iot_inventory_correlation_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "iot_inventory_correlation_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/iot_inventory_correlation"
    mkdir -p "$phase_dir"

    log "INFO" "Starting iot_inventory_correlation_phase for $domain"

    local inventory_file="$phase_dir/iot_inventory.json"
    local risk_file="$phase_dir/risk_scores.txt"
    local count=0

    # --- Aggregate all IoT findings ---
    log "INFO" "Aggregating IoT findings from all phases..."
    local all_iot_findings="$phase_dir/all_iot_findings.txt"
    : > "$all_iot_findings"

    local iot_dirs=(
        "$output_dir/iot_device_fingerprint"
        "$output_dir/iot_default_cred"
        "$output_dir/iot_firmware_cve"
        "$output_dir/iot_ics_scada"
        "$output_dir/iot_upnp"
        "$output_dir/iot_mqtt"
        "$output_dir/iot_ble"
        "$output_dir/iot_wireless_posture"
        "$output_dir/iot_smart_building"
    )

    for iot_dir in "${iot_dirs[@]}"; do
        [[ -d "$iot_dir" ]] || continue
        while IFS= read -r -d '' f; do
            cat "$f" >> "$all_iot_findings" 2>/dev/null || true
        done < <(find "$iot_dir" -name '*.txt' -print0 2>/dev/null)
    done

    # --- Build inventory JSON ---
    log "INFO" "Building IoT inventory JSON..."
    local device_count=0
    local vuln_count=0
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0

    # Start JSON output
    echo "[" > "$inventory_file"

    # Process each finding and assign risk scores
    if [[ -f "$all_iot_findings" ]] && [[ -s "$all_iot_findings" ]]; then
        local first_entry=true
        while IFS= read -r finding; do
            [[ -z "$finding" ]] && continue

            local device_type="unknown"
            local severity="low"
            local risk_score=10

            # Classify device type and assign base risk
            if echo "$finding" | grep -qiE 'ICS|SCADA|Modbus|DNP3|PLC|BACnet|Siemens|Honeywell|Schneider|ABB'; then
                device_type="ics_scada"
                severity="critical"
                risk_score=95
                ((critical_count++)) || true
            elif echo "$finding" | grep -qiE 'access.control|door|badge|turnstile|gate'; then
                device_type="access_control"
                severity="critical"
                risk_score=90
                ((critical_count++)) || true
            elif echo "$finding" | grep -qiE 'default.*cred|DEFAULT_CRED|blank.*auth'; then
                device_type="default_credential"
                severity="critical"
                risk_score=88
                ((critical_count++)) || true
            elif echo "$finding" | grep -qiE 'fire.alarm|sprinkler|smoke|elevator|life.safety'; then
                device_type="life_safety"
                severity="critical"
                risk_score=92
                ((critical_count++)) || true
            elif echo "$finding" | grep -qiE 'camera|surveillance|nvr|dvr|rtsp|onvif|video'; then
                device_type="camera"
                severity="high"
                risk_score=75
                ((high_count++)) || true
            elif echo "$finding" | grep -qiE 'hvac|thermostat|climate|energy|power'; then
                device_type="hvac_energy"
                severity="medium"
                risk_score=55
                ((medium_count++)) || true
            elif echo "$finding" | grep -qiE 'MQTT|mqtt'; then
                device_type="mqtt_broker"
                severity="high"
                risk_score=72
                ((high_count++)) || true
            elif echo "$finding" | grep -qiE 'UPnP|upnp|SSDP'; then
                device_type="upnp_device"
                severity="medium"
                risk_score=50
                ((medium_count++)) || true
            elif echo "$finding" | grep -qiE 'BLE|bluetooth|bluetoothle'; then
                device_type="ble_device"
                severity="low"
                risk_score=35
                ((low_count++)) || true
            elif echo "$finding" | grep -qiE 'CVE|vulnerability'; then
                device_type="vulnerable_device"
                severity="high"
                risk_score=80
                ((high_count++)) || true
            elif echo "$finding" | grep -qiE 'rogue.ap|evil.twin|WEP|open.network'; then
                device_type="wireless_issue"
                severity="medium"
                risk_score=60
                ((medium_count++)) || true
            else
                device_type="other"
                severity="low"
                risk_score=20
                ((low_count++)) || true
            fi

            ((device_count++)) || true
            ((vuln_count++)) || true

            # Write JSON entry
            if [[ "$first_entry" == "true" ]]; then
                first_entry=false
            else
                echo "," >> "$inventory_file"
            fi

            local finding_escaped
            finding_escaped=$(echo "$finding" | sed 's/"/\\"/g' | head -c 500)
            local timestamp
            timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

            cat >> "$inventory_file" << INVENTORY_EOF
  {
    "device_id": "iot_${device_count}",
    "domain": "$domain",
    "device_type": "$device_type",
    "severity": "$severity",
    "risk_score": $risk_score,
    "finding": "$finding_escaped",
    "scan_phase": "$device_type",
    "timestamp": "$timestamp",
    "needs_remediation": $([ "$risk_score" -ge 50 ] && echo "true" || echo "false")
  }
INVENTORY_EOF

            # Write risk score line
            echo "[RISK] device_id=iot_${device_count} type=$device_type severity=$severity score=$risk_score finding=${finding_escaped:0:200}" >> "$risk_file"

        done < "$all_iot_findings"
    fi

    echo "]" >> "$inventory_file"

    # --- Generate risk summary ---
    log "INFO" "Generating risk score summary..."
    {
        echo "=== IoT INVENTORY RISK SUMMARY ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Total Devices/Findings: $device_count"
        echo ""
        echo "--- Severity Breakdown ---"
        echo "Critical: $critical_count"
        echo "High: $high_count"
        echo "Medium: $medium_count"
        echo "Low: $low_count"
        echo ""
        if (( device_count > 0 )); then
            echo "Average Risk Score: $(( (critical_count * 95 + high_count * 75 + medium_count * 55 + low_count * 25) / device_count ))"
        fi
        echo ""
        echo "--- Top Priority Remediation ---"
        grep 'severity=critical' "$risk_file" 2>/dev/null | head -5 || echo "No critical findings"
        echo ""
        echo "=================================="
    } > "$phase_dir/risk_summary.txt"

    # --- Write structured findings ---
    if [[ -f "$risk_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "iot_risk_score" "" "" "" || true
        done < "$risk_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "iot_inventory_correlation_phase" "domain=$domain devices=$device_count critical=$critical_count high=$high_count medium=$medium_count low=$low_count"
    log "INFO" "iot_inventory_correlation_phase complete: $device_count devices correlated"
    return 0
}

iot_inventory_correlation_phase "$@"
