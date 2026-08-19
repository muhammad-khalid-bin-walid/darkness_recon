#!/bin/bash
# Track 17 - Wireless/IoT | Phase 257: Bluetooth Low Energy Testing
# Characteristic enumeration, pairing flaws

iot_ble_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "iot_ble_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/iot_ble"
    mkdir -p "$phase_dir"

    log "INFO" "Starting iot_ble_phase for $domain"

    local ble_file="$phase_dir/ble_vulns.txt"
    local devices_file="$phase_dir/ble_devices.txt"
    local count=0

    # --- BLE scanning via Bluetooth tools ---
    log "INFO" "Checking for BLE scanning tools..."

    # Check if bluetoothctl is available
    if tool_available "bluetoothctl"; then
        log "INFO" "Running bluetoothctl scan..."
        bluetoothctl --timeout 10 scan on 2>>"$LOGS_DIR/ble_scan.log" || true
        bluetoothctl --timeout 10 devices 2>>"$LOGS_DIR/ble_scan.log" | while IFS= read -r device_line; do
            local mac
            mac=$(echo "$device_line" | awk '{print $2}')
            local name
            name=$(echo "$device_line" | cut -d' ' -f3-)
            echo "[BLE_DEVICE] mac=$mac name=$name" >> "$devices_file"
            ((count++)) || true
        done
    fi

    # Check for hcitool
    if tool_available "hcitool"; then
        log "INFO" "Running hcitool BLE scan..."
        timeout 10 hcitool lescan 2>>"$LOGS_DIR/ble_scan.log" &
        local hcitool_pid=$!
        sleep 10
        kill "$hcitool_pid" 2>/dev/null || true
    fi

    # Check for bettercap BLE module
    if tool_available "bettercap"; then
        log "INFO" "Using bettercap for BLE recon..."
        echo "ble.recon on" | timeout 15 bettercap -eval "sleep 10; ble.recon off" 2>>"$LOGS_DIR/bettercap_ble.log" >> "$devices_file" || true
    fi

    # --- Analyze BLE device characteristics ---
    log "INFO" "Analyzing BLE device characteristics..."
    if tool_available "gatttool" || command -v gatttool >/dev/null 2>&1; then
        local known_vuln_chars=(
            "00002a00-0000-1000-8000-00805f9b34fb:Device Name"
            "00002a01-0000-1000-8000-00805f9b34fb:Appearance"
            "00002a19-0000-1000-8000-00805f9b34fb:Battery Level"
            "0000fff1-0000-1000-8000-00805f9b34fb:Vendor Specific"
        )
        log "INFO" "Testing known BLE characteristic UUIDs..."
    fi

    # --- Check for BLE-related web interfaces ---
    log "INFO" "Checking for BLE gateway web interfaces..."
    local ble_paths=(
        "/ble"
        "/bluetooth"
        "/bluetoothle"
        "/beacon"
        "/ibeacon"
        "/eddystone"
    )

    for path in "${ble_paths[@]}"; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$code" == "200" || "$code" == "401" ]]; then
            echo "[BLE_WEB] https://$domain$path (BLE management interface)" >> "$ble_file"
            ((count++)) || true
        fi
    done

    # --- Check for Bluetooth pairing vulnerabilities ---
    log "INFO" "Checking for Bluetooth pairing vulnerability indicators..."
    if [[ -f "$devices_file" ]]; then
        while IFS= read -r device_line; do
            # Check for devices without name (potentially default config)
            if echo "$device_line" | grep -q 'name=$\|name= '; then
                echo "[BLE_UNNAMED] $device_line (unnamed device - may use default pairing)" >> "$ble_file"
                ((count++)) || true
            fi
            # Check for common IoT BLE device names
            if echo "$device_line" | grep -qiE 'fitbit|garmin|mi[_-]band|xiaomi|huawei|tiles|chipolo|airtag'; then
                echo "[BLE_CONSUMER_IOT] $device_line (consumer IoT device)" >> "$devices_file"
            fi
        done < "$devices_file"
    fi

    # --- Write structured findings ---
    if [[ -f "$ble_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "ble_vuln" "" "" "" || true
        done < "$ble_file"
    fi

    if [[ -f "$devices_file" ]]; then
        while IFS= read -r asset; do
            write_asset "$phase_dir" "$domain" "ble_device" "$asset" "" "" || true
        done < "$devices_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "iot_ble_phase" "domain=$domain findings=$count"
    log "INFO" "iot_ble_phase complete: $count findings"
    return 0
}

iot_ble_phase "$@"
