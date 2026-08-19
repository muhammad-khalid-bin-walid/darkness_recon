#!/bin/bash
# Track 17 - Wireless/IoT | Phase 251: IoT Device Fingerprinting
# Service identification, manufacturer detection

iot_device_fingerprint_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "iot_device_fingerprint_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/iot_device_fingerprint"
    mkdir -p "$phase_dir"

    log "INFO" "Starting iot_device_fingerprint_phase for $domain"

    local devices_file="$phase_dir/iot_devices.txt"
    local fingerprint_file="$phase_dir/device_fingerprints.txt"
    local count=0

    # --- Nmap service detection scan ---
    log "INFO" "Running Nmap service detection for IoT fingerprinting..."
    if tool_available "nmap"; then
        nmap -sV -sC --open -T4 "$domain" -oX "$phase_dir/nmap_scan.xml" 2>>"$LOGS_DIR/nmap_iot.log" || true
        nmap -sV -sC --open -T4 "$domain" -oN "$phase_dir/nmap_scan.txt" 2>>"$LOGS_DIR/nmap_iot.log" || true
    fi

    # --- Parse Nmap results for IoT indicators ---
    log "INFO" "Parsing Nmap results for IoT device signatures..."
    if [[ -f "$phase_dir/nmap_scan.txt" ]]; then
        # IoT service signatures
        local -a iot_services=(
            "IoT|IoT device detected"
            "mini_httpd|Embedded web server"
            "lighttpd|Embedded web server"
            "thttpd|Embedded web server"
            "GoAhead|Embedded web server"
            "Boa|Embedded web server"
            "uhttpd|OpenWrt HTTP server"
            "Netgear|Netgear device"
            "TP-Link|TP-Link device"
            "D-Link|D-Link device"
            "Hikvision|Hikvision camera"
            "Dahua|Dahua camera"
            "Axis|Axis camera"
            "Reolink|Reolink camera"
            "Ubiquiti|Ubiquiti device"
            "MikroTik|MikroTik router"
            "Cisco|Cisco device"
            "Fortinet|Fortinet device"
            "Palo Alto|Palo Alto device"
            "SonicWall|SonicWall device"
            "Honeywell|Honeywell IoT"
            "Siemens|Siemens PLC"
            "Schneider|Schneider Electric"
            "ABB|ABB controller"
            "Bosch|Bosch device"
            "Hikvision|Hikvision NVR"
            "Dahua|Dahua NVR"
            "RTSP|Camera stream"
            "ONVIF|Camera protocol"
            "MQTT|MQTT broker"
            "CoAP|CoAP protocol"
            "Zigbee|Zigbee gateway"
            "Z-Wave|Z-Wave controller"
            "Lutron|Lutron lighting"
            "Crestron|Crestron AV"
            "AMX|AMX controller"
            "Savant|Savant system"
            "Control4|Control4 system"
        )

        while IFS= read -r line; do
            for iot_sig in "${iot_services[@]}"; do
                local sig_name="${iot_sig%%|*}"
                local sig_desc="${iot_sig##*|}"
                if echo "$line" | grep -qi "$sig_name"; then
                    echo "[IOT_DEVICE] $line (type=$sig_desc)" >> "$devices_file"
                    echo "$line|$sig_name|$sig_desc|$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$fingerprint_file"
                    ((count++)) || true
                fi
            done
        done < "$phase_dir/nmap_scan.txt"
    fi

    # --- HTTP header fingerprinting ---
    log "INFO" "Performing HTTP header fingerprinting for IoT detection..."
    local header_signatures=(
        "Server:.*(?:mini_httpd|lighttpd|thttpd|GoAhead|Boa|uhttpd|nginx/1\.\d+\.\d+)"
        "Server:.*(?:Hikvision|Dahua|Netgear|TP-Link|D-Link)"
        "X-Powered-By:.*(?:Express|ASP\.NET|PHP)"
        "WWW-Authenticate:.*(?:Basic realm=\"(?:Camera|NVR|DVR|Router|Switch))\""
        "Location:.*(?:/cgi-bin|/webcgi|/boaform|/goform)"
    )

    local targets_file="$output_dir/crawl/endpoints.txt"
    if [[ -f "$targets_file" ]]; then
        head -30 "$targets_file" | while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            local headers
            headers=$(curl -sI -m 5 "$url" 2>/dev/null) || true
            for sig in "${header_signatures[@]}"; do
                if echo "$headers" | grep -qiE "$sig"; then
                    local matched
                    matched=$(echo "$headers" | grep -iE "$sig" | head -1)
                    echo "[IOT_HEADER] url=$url header=$matched" >> "$devices_file"
                    ((count++)) || true
                fi
            done
        done
    fi

    # --- UPnP/SSDP discovery ---
    log "INFO" "Checking for UPnP/SSDP IoT indicators..."
    local upnp_paths=(
        "/description.xml"
        "/rootDesc.xml"
        "/tr64desc.xml"
        "/dev0desc.xml"
        "/igddesc.xml"
    )

    for path in "${upnp_paths[@]}"; do
        local upnp_resp
        upnp_resp=$(curl -s -m 5 "https://$domain$path" 2>/dev/null) || true
        if echo "$upnp_resp" | grep -qiE 'device|manufacturer|modelName|friendlyName|UPnP'; then
            echo "[UPNP_DEVICE] https://$domain$path (UPnP device detected)" >> "$devices_file"
            ((count++)) || true
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$devices_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "iot_device" "" "" "" || true
        done < "$devices_file"
    fi

    if [[ -f "$fingerprint_file" ]]; then
        while IFS= read -r asset; do
            write_asset "$phase_dir" "$domain" "iot_fingerprint" "$asset" "" "" || true
        done < "$fingerprint_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "iot_device_fingerprint_phase" "domain=$domain findings=$count"
    log "INFO" "iot_device_fingerprint_phase complete: $count findings"
    return 0
}

iot_device_fingerprint_phase "$@"
