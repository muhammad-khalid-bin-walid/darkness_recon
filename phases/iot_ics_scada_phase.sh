#!/bin/bash
# Track 17 - Wireless/IoT | Phase 254: ICS/SCADA Protocol Testing
# Modbus, DNP3, OPC protocol testing, industrial control security

iot_ics_scada_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "iot_ics_scada_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/iot_ics_scada"
    mkdir -p "$phase_dir"

    log "INFO" "Starting iot_ics_scada_phase for $domain"

    local ics_file="$phase_dir/ics_vulns.txt"
    local scada_file="$phase_dir/scada_exposure.txt"
    local count=0

    # --- Scan for ICS/SCADA ports ---
    log "INFO" "Scanning for ICS/SCADA exposed ports..."
    local ics_ports=(
        "502:Modbus"
        "20000:DNP3"
        "4840:OPC-UA"
        "4843:OPC-UA-Secure"
        "102:S7comm-Siemens"
        "47808:BACnet"
        "789:Crimson-RediNet"
        "2222:EtherNet/IP"
        "44818:EtherNet/IP"
        "22225:EtherNet-IP-RT"
        "1089-1091:FF-HSE"
        "1911:Foxborough"
        "5093:ProConOS"
        "20547:DF1"
        "41794:Triplite-PDU"
        "161:SNMP-ICS"
        "623:IPMI"
        "664:MTConnect"
    )

    if tool_available "nmap"; then
        local port_list=""
        for port_entry in "${ics_ports[@]}"; do
            local port_num="${port_entry%%:*}"
            port_list="${port_list}${port_num},"
        done
        port_list="${port_list%,}"

        log "INFO" "Running Nmap scan on ICS ports: $port_list"
        nmap -sV -sC -p "$port_list" --open -T4 "$domain" -oN "$phase_dir/nmap_ics.txt" 2>>"$LOGS_DIR/ics_scada.log" || true
    fi

    # --- Parse results for open ICS services ---
    if [[ -f "$phase_dir/nmap_ics.txt" ]]; then
        while IFS= read -r line; do
            for port_entry in "${ics_ports[@]}"; do
                local port_num="${port_entry%%:*}"
                local port_name="${port_entry##*:}"
                if echo "$line" | grep -q "${port_num}/tcp.*open"; then
                    echo "[ICS_PORT] port=$port_num service=$port_name domain=$domain" >> "$ics_file"
                    echo "port=$port_num service=$port_name domain=$domain" >> "$scada_file"
                    ((count++)) || true
                    log "WARN" "ICS service found: $port_name on port $port_num"
                fi
            done
        done < "$phase_dir/nmap_ics.txt"
    fi

    # --- Modbus enumeration ---
    log "INFO" "Testing Modbus protocol (port 502)..."
    if tool_available "mbtget" || command -v mbtget >/dev/null 2>&1; then
        mbtget -u -a "$domain" -r 1 2>/dev/null | head -5 >> "$ics_file" || true
        ((count++)) || true
    elif python3 -c "import pymodbus" 2>/dev/null; then
        python3 -c "
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient('$domain', port=502)
try:
    client.connect()
    result = client.read_holding_registers(0, 10)
    print(f'MODBUS_READ|address=0|registers={result.registers}')
    client.close()
except Exception as e:
    print(f'MODBUS_ERROR|{e}')
" 2>/dev/null >> "$ics_file" || true
        ((count++)) || true
    fi

    # --- BACnet discovery ---
    log "INFO" "Testing BACnet protocol (port 47808)..."
    if python3 -c "import BAC0" 2>/dev/null; then
        python3 -c "
import BAC0
try:
    b = BAC0.lite(ip='$domain')
    devs = b.whois()
    for d in devs:
        print(f'BACNET_DEVICE|{d}')
    b.shutdown()
except Exception as e:
    print(f'BACNET_ERROR|{e}')
" 2>/dev/null >> "$ics_file" || true
        ((count++)) || true
    fi

    # --- Check for SCADA web interfaces ---
    log "INFO" "Checking for SCADA web interfaces..."
    local scada_paths=(
        "/cgi-bin/scada"
        "/scada"
        "/hmi"
        "/panel"
        "/monitor"
        "/dashboard"
        "/gateway"
        "/plc"
        "/controller"
    )

    for path in "${scada_paths[@]}"; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$code" == "200" || "$code" == "401" ]]; then
            echo "[SCADA_WEB] https://$domain$path (HTTP $code)" >> "$ics_file"
            ((count++)) || true
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$ics_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "ics_scada_vuln" "" "" "" || true
        done < "$ics_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "iot_ics_scada_phase" "domain=$domain findings=$count"
    log "INFO" "iot_ics_scada_phase complete: $count findings"
    return 0
}

iot_ics_scada_phase "$@"
