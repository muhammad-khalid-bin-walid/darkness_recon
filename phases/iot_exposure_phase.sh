#!/usr/bin/env bash
# Phase: IoT Exposure — Device fingerprinting and default credential checks
set -euo pipefail

iot_exposure() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/iot"

    log "INFO" "Starting IoT exposure checks for $domain"

    local iot_devices="$output_dir/iot/devices.txt"
    local iot_vulns="$output_dir/iot/vulnerabilities.txt"
    local count=0

    # IoT management ports to probe
    local iot_ports=(80 443 8080 8443 9090 8000 8888 8081 49152)

    # Default credentials to test (read-only, single attempt each)
    local default_creds=(
        "admin:admin"
        "admin:password"
        "admin:1234"
        "admin:"
        "root:root"
        "root:password"
        "root:1234"
        "ubnt:ubnt"
        "user:user"
        "test:test"
    )

    # Common IoT management paths
    local iot_paths=("/" "/admin" "/login" "/cgi-bin/login" "/webcgi/login"
                     "/boaform/admin" "/device.html" "/status" "/system"
                     "/description.xml" "/rootDesc.xml" "/UPnPDevDesc.xml")

    for port in "${iot_ports[@]}"; do
        # Check if port is open
        if ! nc -w 3 "$domain" "$port" < /dev/null >/dev/null 2>&1; then
            continue
        fi

        log "INFO" "IoT: Port $port open on $domain"

        local scheme="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"

        for path in "${iot_paths[@]}"; do
            local url="${scheme}://${domain}:${port}${path}"
            local response
            response=$(curl -sk -o /dev/null -w "%{http_code}|%{content_type}|%{server}" \
                --connect-timeout 5 --max-time 10 "$url" 2>/dev/null || echo "000||")

            local status
            status=$(echo "$response" | cut -d'|' -f1)
            local content_type
            content_type=$(echo "$response" | cut -d'|' -f2)
            local server
            server=$(echo "$response" | cut -d'|' -f3)

            [[ "$status" == "000" ]] && continue

            # Detect IoT device type from headers
            local device_type="unknown"
            case "$server" in
                *mini_httpd*|*GoAhead*|*Boa*) device_type="embedded_web_server" ;;
                *Hikvision*|*Dahua*|*FLIR*) device_type="ip_camera" ;;
                *Apache*|*nginx*) device_type="generic_server" ;;
                *lighttpd*) device_type="embedded_lighttpd" ;;
            esac

            # Check for UPnP devices
            if [[ "$path" == *".xml" ]] && echo "$content_type" | grep -qi "xml"; then
                device_type="upnp_device"
                local upnp_desc
                upnp_desc=$(curl -sk --connect-timeout 5 --max-time 10 "$url" 2>/dev/null | grep -i "friendlyName" | head -1 || echo "")
                if [[ -n "$upnp_desc" ]]; then
                    echo "[UPnP] $url : $upnp_desc" >> "$iot_devices"
                fi
            fi

            # Test default credentials (single attempt, no brute force)
            for cred in "${default_creds[@]}"; do
                local user
                user=$(echo "$cred" | cut -d: -f1)
                local pass
                pass=$(echo "$cred" | cut -d: -f2)

                local cred_response
                cred_response=$(curl -sk -o /dev/null -w "%{http_code}" \
                    --connect-timeout 5 --max-time 10 \
                    -u "${user}:${pass}" "$url" 2>/dev/null || echo "000")

                if [[ "$cred_response" == "200" || "$cred_response" == "302" ]]; then
                    echo "[DEFAULT_CRED] $url $device_type $user:$pass (HTTP $cred_response)" >> "$iot_vulns"
                    ((count++)) || true
                    break
                fi
            done

            echo "[DEVICE] $url $device_type HTTP/$status" >> "$iot_devices"
            ((count++)) || true
        done
    done

    # Deduplicate
    sort -u "$iot_devices" > "$output_dir/iot/devices_unique.txt" 2>/dev/null || true
    sort -u "$iot_vulns" > "$output_dir/iot/vulns_unique.txt" 2>/dev/null || true

    local device_count
    device_count=$(wc -l < "$output_dir/iot/devices_unique.txt" 2>/dev/null || echo 0)

    echo "$device_count" > "$output_dir/iot/count.txt"
    write_finding "{\"type\":\"iot_exposure\",\"severity\":\"medium\",\"devices\":$device_count,\"domain\":\"$domain\",\"phase\":\"iot_exposure\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    write_asset "{\"type\":\"iot_device\",\"domain\":\"$domain\",\"count\":$device_count}" \
        "$output_dir/assets.jsonl" 2>/dev/null || true
    log "INFO" "IoT exposure checks complete: $device_count devices found"
    py_log "INFO" "iot_exposure_phase" "Completed for $domain — $device_count devices"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    iot_exposure "${1:-}"
fi
