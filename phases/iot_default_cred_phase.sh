#!/bin/bash
# Track 17 - Wireless/IoT | Phase 252: Default Credential Testing
# Manufacturer default passwords, credential databases

iot_default_cred_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "iot_default_cred_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/iot_default_cred"
    mkdir -p "$phase_dir"

    log "INFO" "Starting iot_default_cred_phase for $domain"

    local vuln_file="$phase_dir/default_cred_vulns.txt"
    local test_file="$phase_dir/credential_tests.txt"
    local count=0

    # --- Default credential pairs by manufacturer ---
    log "INFO" "Testing default credentials against IoT services..."
    declare -A DEFAULT_CREDS=(
        ["admin:admin"]="Generic"
        ["admin:password"]="Generic"
        ["admin:1234"]="Generic"
        ["admin: "]="Generic (blank password)"
        ["root:root"]="Generic"
        ["root:toor"]="Generic"
        ["root:password"]="Generic"
        ["admin:admin123"]="Generic"
        ["user:user"]="Generic"
        ["guest:guest"]="Generic"
        ["admin:hikvision"]="Hikvision"
        ["admin:888888"]="Hikvision/Dahua"
        ["admin:12345"]="Dahua"
        ["admin:7ujMko0admin"]="Dahua"
        ["admin:admin"]="Dahua"
        ["admin:pass"]="Netgear"
        ["admin:password"]="Netgear/TP-Link"
        ["admin:1234"]="TP-Link"
        ["admin:tplink"]="TP-Link"
        ["admin:public"]="Ubiquiti"
        ["ubnt:ubnt"]="Ubiquiti"
        ["admin:mikrotik"]="MikroTik"
        ["admin:admin"]="MikroTik"
        ["admin:avtech"]="AVTech"
        ["root:Vitek-2011"]="Vitek"
        ["admin:X10Wdmin"]="Axis"
        ["admin:password"]="D-Link"
        ["admin:"]="D-Link (blank)"
        ["admin:123456"]="Cameras"
        ["root:calvin"]="iDRAC (Dell)"
        ["admin:password"]="iLO (HP)"
        ["USERID:PASSW0RD"]="IMM (IBM)"
        ["admin:super"]="Cisco IOS"
        ["cisco:cisco"]="Cisco"
        ["admin:admin"]="Fortinet"
        ["admin: """]="SonicWall"
        ["admin:netscreen"]="Juniper"
        ["root:admin"]="Palo Alto"
    )

    # --- HTTP Basic Auth testing ---
    log "INFO" "Testing HTTP Basic Auth endpoints..."
    local basic_auth_paths=(
        "/"
        "/admin"
        "/login"
        "/cgi-bin/login"
        "/webcgi/login"
        "/boaform/admin"
        "/index.html"
        "/device"
        "/status"
    )

    for path in "${basic_auth_paths[@]}"; do
        # First check if auth is required
        local initial_code
        initial_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$initial_code" != "401" && "$initial_code" != "403" ]]; then
            continue
        fi

        for cred_pair in "${!DEFAULT_CREDS[@]}"; do
            local user="${cred_pair%%:*}"
            local pass="${cred_pair#*:}"
            local manufacturer="${DEFAULT_CREDS[$cred_pair]}"

            local http_code
            http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -u "$user:$pass" "https://$domain$path" 2>/dev/null) || true

            echo "path=$path user=$user pass=$pass http_code=$http_code manufacturer=$manufacturer" >> "$test_file"

            if [[ "$http_code" == "200" || "$http_code" == "302" ]]; then
                echo "[DEFAULT_CRED] https://$domain$path user=$user pass=$pass manufacturer=$manufacturer (HTTP $http_code)" >> "$vuln_file"
                ((count++)) || true
                log "WARN" "Default credential found: $user:$pass at $domain$path"
            fi
        done
    done

    # --- SNMP default community strings ---
    log "INFO" "Testing SNMP default community strings..."
    if tool_available "snmpwalk" || command -v snmpwalk >/dev/null 2>&1; then
        local snmp_strings=("public" "private" "manager" "admin" "secret" "community")
        for community in "${snmp_strings[@]}"; do
            snmpwalk -v2c -c "$community" -t 3 "$domain" 1.3.6.1.2.1.1 2>/dev/null | head -1 >> "$test_file" || true
            if snmpwalk -v2c -c "$community" -t 3 "$domain" 1.3.6.1.2.1.1 2>/dev/null | grep -q 'SNMPv2-MIB'; then
                echo "[SNMP_DEFAULT] domain=$domain community=$community (SNMP accessible with default string)" >> "$vuln_file"
                ((count++)) || true
                log "WARN" "SNMP default community string found: $community"
            fi
        done
    fi

    # --- Telnet default credentials ---
    log "INFO" "Testing Telnet default credentials..."
    if tool_available "nmap"; then
        local telnet_check
        telnet_check=$(nmap -p 23 --open -T4 "$domain" 2>/dev/null) || true
        if echo "$telnet_check" | grep -q "23/tcp.*open"; then
            echo "[TELNET_OPEN] domain=$domain port=23 (Telnet open - test default creds manually)" >> "$vuln_file"
            ((count++)) || true
        fi
    fi

    # --- Write structured findings ---
    if [[ -f "$vuln_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "default_credential" "" "" "" || true
        done < "$vuln_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "iot_default_cred_phase" "domain=$domain findings=$count"
    log "INFO" "iot_default_cred_phase complete: $count findings"
    return 0
}

iot_default_cred_phase "$@"
