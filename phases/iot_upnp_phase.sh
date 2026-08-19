#!/bin/bash
# Track 17 - Wireless/IoT | Phase 255: UPnP Discovery and Testing
# SSDP reflection, device exposure

iot_upnp_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "iot_upnp_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/iot_upnp"
    mkdir -p "$phase_dir"

    log "INFO" "Starting iot_upnp_phase for $domain"

    local upnp_file="$phase_dir/upnp_vulns.txt"
    local devices_file="$phase_dir/upnp_devices.txt"
    local count=0

    # --- UPnP description endpoint scanning ---
    log "INFO" "Scanning for UPnP description endpoints..."
    local upnp_paths=(
        "/description.xml"
        "/rootDesc.xml"
        "/tr64desc.xml"
        "/dev0desc.xml"
        "/igddesc.xml"
        "/WANIPConnection.xml"
        "/WANPPPConnection.xml"
        "/WLANConfiguration.xml"
        "/LANConfigSecurity.xml"
        "/DeviceDescription.xml"
        "/UPnP/Control/InternetGatewayDevice"
        "/Rootdev.xml"
    )

    for path in "${upnp_paths[@]}"; do
        local resp
        resp=$(curl -s -m 5 "https://$domain$path" 2>/dev/null) || true
        if echo "$resp" | grep -qiE 'UPnP|device|manufacturer|modelName|serviceType|SCPDURL'; then
            local manufacturer
            manufacturer=$(echo "$resp" | grep -ioP '(?<=<manufacturer>)[^<]+' | head -1) || true
            local model
            model=$(echo "$resp" | grep -ioP '(?<=<modelName>)[^<]+' | head -1) || true
            local friendly
            friendly=$(echo "$resp" | grep -ioP '(?<=<friendlyName>)[^<]+' | head -1) || true

            echo "[UPNP_DEVICE] url=https://$domain$path manufacturer=$manufacturer model=$model name=$friendly" >> "$devices_file"
            ((count++)) || true

            # Check for dangerous UPnP services
            if echo "$resp" | grep -qiE 'WANIPConnection|WANPPPConnection'; then
                echo "[UPNP_WAN] $domain$path - WAN connection service exposed (potential port forwarding abuse)" >> "$upnp_file"
                ((count++)) || true
            fi
            if echo "$resp" | grep -qiE 'X_AVM_DE_|tr64desc'; then
                echo "[UPNP_TR64] $domain$path - TR-064 service exposed" >> "$upnp_file"
                ((count++)) || true
            fi
        fi
    done

    # --- SSDP reflection test ---
    log "INFO" "Testing SSDP for reflection amplification..."
    if tool_available "nmap"; then
        nmap -sU -p 1900 --script=upnp-info,dell-om-info "$domain" -oN "$phase_dir/nmap_ssdp.txt" 2>>"$LOGS_DIR/ssdp.log" || true
        if [[ -f "$phase_dir/nmap_ssdp.txt" ]] && grep -qiE 'open|upnp|ssdp' "$phase_dir/nmap_ssdp.txt" 2>/dev/null; then
            echo "[SSDP_REFLECTION] domain=$domain port=1900/UDP - SSDP open (amplification risk)" >> "$upnp_file"
            ((count++)) || true
        fi
    fi

    # --- Check for UPnP exposed via HTTP headers ---
    log "INFO" "Checking HTTP headers for UPnP indicators..."
    local targets_file="$output_dir/crawl/endpoints.txt"
    if [[ -f "$targets_file" ]]; then
        head -10 "$targets_file" | while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            local headers
            headers=$(curl -sI -m 5 "$url" 2>/dev/null) || true
            if echo "$headers" | grep -qiE 'UPnP|SSDP|upnp/|AVM|fritz|Netgear|TP-Link'; then
                echo "[UPNP_HEADER] url=$url header=$(echo "$headers" | grep -i upnp | head -1)" >> "$upnp_file"
                ((count++)) || true
            fi
        done
    fi

    # --- UPnP port forwarding abuse check ---
    log "INFO" "Checking for UPnP port forwarding exposure..."
    local control_paths=(
        "/control/WANIPConn1"
        "/control/WANPPPConn1"
        "/UPnP/control/InternetGatewayDevice/WANIPConnection1"
    )

    for cpath in "${control_paths[@]}"; do
        local soap_resp
        soap_resp=$(curl -s -m 5 -X POST -H "Content-Type: text/xml; charset=utf-8" \
            -d '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/></s:Body></s:Envelope>' \
            "https://$domain$cpath" 2>/dev/null) || true
        if echo "$soap_resp" | grep -qiE 'NewExternalIPAddress|GetExternalIPAddress'; then
            echo "[UPNP_SOAP] domain=$domain path=$cpath (UPnP SOAP accessible)" >> "$upnp_file"
            ((count++)) || true
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$upnp_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "upnp_vuln" "" "" "" || true
        done < "$upnp_file"
    fi

    if [[ -f "$devices_file" ]]; then
        while IFS= read -r asset; do
            write_asset "$phase_dir" "$domain" "upnp_device" "$asset" "" "" || true
        done < "$devices_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "iot_upnp_phase" "domain=$domain findings=$count"
    log "INFO" "iot_upnp_phase complete: $count findings"
    return 0
}

iot_upnp_phase "$@"
