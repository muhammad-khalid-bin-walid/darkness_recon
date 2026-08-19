#!/bin/bash
# Track 17 - Wireless/IoT | Phase 258: Wireless Network Posture Analysis
# WPA configuration, rogue AP detection

iot_wireless_posture_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "iot_wireless_posture_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/iot_wireless_posture"
    mkdir -p "$phase_dir"

    log "INFO" "Starting iot_wireless_posture_phase for $domain"

    local posture_file="$phase_dir/wireless_posture.txt"
    local rogue_file="$phase_dir/rogue_aps.txt"
    local count=0

    # --- WiFi network enumeration ---
    log "INFO" "Enumerating wireless networks..."

    if tool_available "iwlist"; then
        log "INFO" "Running iwlist scan..."
        iwlist scan 2>>"$LOGS_DIR/wireless_scan.log" | grep -E 'ESSID|Encryption|Authentication|Channel|Signal' > "$phase_dir/iwlist_results.txt" || true
    fi

    if tool_available "nmcli"; then
        log "INFO" "Running nmcli scan..."
        nmcli device wifi list 2>>"$LOGS_DIR/wireless_scan.log" >> "$phase_dir/nmcli_results.txt" || true
    fi

    # --- Analyze WPA/WPA2 configuration ---
    log "INFO" "Analyzing WPA configuration..."
    if [[ -f "$phase_dir/iwlist_results.txt" ]]; then
        # Check for WEP (weak)
        if grep -qi 'WEP\|WEP104\|WEP40' "$phase_dir/iwlist_results.txt" 2>/dev/null; then
            echo "[WEAK_ENCRYPTION] WEP encryption detected (trivially breakable)" >> "$posture_file"
            ((count++)) || true
        fi

        # Check for open networks
        if grep -qi 'Encryption:on\|off\|Open' "$phase_dir/iwlist_results.txt" 2>/dev/null; then
            local open_count
            open_count=$(grep -ciE 'Encryption:(off|Open)' "$phase_dir/iwlist_results.txt" 2>/dev/null || echo 0)
            if (( open_count > 0 )); then
                echo "[OPEN_NETWORKS] $open_count open (no encryption) networks detected" >> "$posture_file"
                ((count++)) || true
            fi
        fi

        # Check for WPA (not WPA2)
        if grep -qi 'WPA[^2]' "$phase_dir/iwlist_results.txt" 2>/dev/null; then
            echo "[LEGACY_WPA] WPA (non-WPA2) networks detected - weak cipher" >> "$posture_file"
            ((count++)) || true
        fi

        # Check for WPS
        if grep -qi 'WPS\|WPS-PBC\|WPS-PIN' "$phase_dir/iwlist_results.txt" 2>/dev/null; then
            echo "[WPS_ENABLED] WPS enabled - vulnerable to PIN brute force" >> "$posture_file"
            ((count++)) || true
        fi
    fi

    # --- Rogue AP detection ---
    log "INFO" "Checking for rogue access points..."
    local expected_essids_file="$output_dir/config/wireless_essids.txt"
    if [[ -f "$expected_essids_file" ]]; then
        while IFS= read -r essid; do
            [[ -z "$essid" ]] && continue
            if [[ -f "$phase_dir/iwlist_results.txt" ]]; then
                local ap_count
                ap_count=$(grep -ci "\"$essid\"" "$phase_dir/iwlist_results.txt" 2>/dev/null || echo 0)
                if (( ap_count > 1 )); then
                    echo "[ROGUE_AP] ESSID=$essid found $ap_count times (possible rogue AP)" >> "$rogue_file"
                    ((count++)) || true
                fi
            fi
        done < "$expected_essids_file"
    fi

    # Check for evil twin indicators
    if [[ -f "$phase_dir/iwlist_results.txt" ]]; then
        grep -i 'ESSID:' "$phase_dir/iwlist_results.txt" 2>/dev/null | awk -F'"' '{print $2}' | sort | uniq -c | sort -rn | while read -r ap_count essid; do
            if (( ap_count > 2 )); then
                echo "[SUSPECT_AP] ESSID=$essid seen $ap_count times (possible evil twin)" >> "$rogue_file"
                ((count++)) || true
            fi
        done
    fi

    # --- Check for enterprise WiFi weakness ---
    log "INFO" "Checking for enterprise WiFi configuration issues..."
    if [[ -f "$phase_dir/iwlist_results.txt" ]]; then
        if grep -qi 'WPA-EAP\|802.1X' "$phase_dir/iwlist_results.txt" 2>/dev/null; then
            echo "[ENTERPRISE_WIFI] 802.1X/EAP network detected - verify RADIUS config" >> "$posture_file"
            ((count++)) || true
        fi
    fi

    # --- Check for wireless management interfaces exposed ---
    log "INFO" "Checking for wireless management interfaces..."
    local wireless_mgmt_paths=(
        "/wireless"
        "/wifi"
        "/wlan"
        "/access-points"
        "/network"
        "/wireless-settings"
    )

    for path in "${wireless_mgmt_paths[@]}"; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$code" == "200" || "$code" == "401" ]]; then
            echo "[WIRELESS_MGMT] https://$domain$path (wireless management interface)" >> "$posture_file"
            ((count++)) || true
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$posture_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "wireless_posture" "" "" "" || true
        done < "$posture_file"
    fi

    if [[ -f "$rogue_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "rogue_ap" "" "" "" || true
        done < "$rogue_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "iot_wireless_posture_phase" "domain=$domain findings=$count"
    log "INFO" "iot_wireless_posture_phase complete: $count findings"
    return 0
}

iot_wireless_posture_phase "$@"
