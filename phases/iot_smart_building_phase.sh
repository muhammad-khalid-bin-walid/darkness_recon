#!/bin/bash
# Track 17 - Wireless/IoT | Phase 259: Smart Building System Testing
# Access control, HVAC/security integration

iot_smart_building_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "iot_smart_building_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/iot_smart_building"
    mkdir -p "$phase_dir"

    log "INFO" "Starting iot_smart_building_phase for $domain"

    local vuln_file="$phase_dir/smart_building_vulns.txt"
    local systems_file="$phase_dir/building_systems.txt"
    local count=0

    # --- Scan for building management system ports ---
    log "INFO" "Scanning for building management system ports..."
    local bms_ports=(
        "47808:BACnet"
        "47809:BACnet-IP"
        "502:Modbus"
        "102:S7comm"
        "789:Crimson"
        "44818:EtherNet-IP"
        "47808:MS/TP"
        "20000:DNP3"
        "4840:OPC-UA"
    )

    if tool_available "nmap"; then
        local port_list=""
        for port_entry in "${bms_ports[@]}"; do
            local port_num="${port_entry%%:*}"
            port_list="${port_list}${port_num},"
        done
        port_list="${port_list%,}"
        nmap -sV -p "$port_list" --open -T4 "$domain" -oN "$phase_dir/nmap_bms.txt" 2>>"$LOGS_DIR/bms_scan.log" || true
    fi

    # --- Access control system detection ---
    log "INFO" "Checking for access control system interfaces..."
    local access_paths=(
        "/access-control"
        "/door-control"
        "/badge"
        "/reader"
        "/turnstile"
        "/gate"
        "/intercom"
        "/video-intercom"
        "/sip"
        "/vms"
        "/milestone"
        "/exacq"
        "/genetec"
        "/avigilon"
        "/openpath"
        "/kisi"
        "/brivo"
        "/proxy"
    )

    for path in "${access_paths[@]}"; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$code" == "200" || "$code" == "401" || "$code" == "302" ]]; then
            echo "[ACCESS_CONTROL] https://$domain$path (access control interface, HTTP $code)" >> "$vuln_file"
            ((count++)) || true
        fi
    done

    # --- HVAC system detection ---
    log "INFO" "Checking for HVAC system interfaces..."
    local hvac_paths=(
        "/hvac"
        "/thermostat"
        "/climate"
        "/temperature"
        "/cooling"
        "/heating"
        "/ventilation"
        "/air-quality"
        "/bms"
        "/building-management"
        "/facility"
        "/maintenance"
        "/energymeter"
        "/energy"
        "/power-meter"
    )

    for path in "${hvac_paths[@]}"; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$code" == "200" || "$code" == "401" ]]; then
            echo "[HVAC_SYSTEM] https://$domain$path (HVAC/building system, HTTP $code)" >> "$systems_file"
            ((count++)) || true
        fi
    done

    # --- Video surveillance system detection ---
    log "INFO" "Checking for video surveillance systems..."
    local vss_paths=(
        "/video"
        "/camera"
        "/cam"
        "/live"
        "/streams"
        "/recording"
        "/playback"
        "/nvr"
        "/dvr"
        "/cctv"
        "/surveillance"
        "/rtsp"
        "/onvif"
    )

    for path in "${vss_paths[@]}"; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$code" == "200" || "$code" == "401" || "$code" == "403" ]]; then
            echo "[VIDEO_SURVEILLANCE] https://$domain$path (video system, HTTP $code)" >> "$systems_file"
            ((count++)) || true
        fi
    done

    # --- Elevator and fire safety system detection ---
    log "INFO" "Checking for elevator and fire safety systems..."
    local safety_paths=(
        "/elevator"
        "/fire-alarm"
        "/sprinkler"
        "/smoke-detector"
        "/fire-panel"
        "/emergency"
        "/evacuation"
    )

    for path in "${safety_paths[@]}"; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$code" == "200" || "$code" == "401" ]]; then
            echo "[FIRE_SAFETY] https://$domain$path (fire/safety system, HTTP $code)" >> "$vuln_file"
            ((count++)) || true
        fi
    done

    # --- Check for common smart building API exposure ---
    log "INFO" "Checking for smart building API endpoints..."
    local api_paths=(
        "/api/building"
        "/api/access"
        "/api/cameras"
        "/api/hvac"
        "/api/energy"
        "/api/devices"
        "/api/rooms"
        "/api/floor"
        "/graphql"
    )

    for path in "${api_paths[@]}"; do
        local resp_code
        resp_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$resp_code" == "200" || "$resp_code" == "401" ]]; then
            echo "[SMART_BUILDING_API] https://$domain$path (building API, HTTP $resp_code)" >> "$vuln_file"
            ((count++)) || true
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$vuln_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "smart_building_vuln" "" "" "" || true
        done < "$vuln_file"
    fi

    if [[ -f "$systems_file" ]]; then
        while IFS= read -r asset; do
            write_asset "$phase_dir" "$domain" "building_system" "$asset" "" "" || true
        done < "$systems_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "iot_smart_building_phase" "domain=$domain findings=$count"
    log "INFO" "iot_smart_building_phase complete: $count findings"
    return 0
}

iot_smart_building_phase "$@"
