#!/bin/bash
# Track 17 - Wireless/IoT | Phase 256: MQTT Broker Testing
# Topic enumeration, authentication bypass

iot_mqtt_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "iot_mqtt_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/iot_mqtt"
    mkdir -p "$phase_dir"

    log "INFO" "Starting iot_mqtt_phase for $domain"

    local mqtt_file="$phase_dir/mqtt_vulns.txt"
    local topics_file="$phase_dir/mqtt_topics.txt"
    local count=0

    # --- Scan for MQTT broker ports ---
    log "INFO" "Scanning for MQTT brokers..."
    if tool_available "nmap"; then
        nmap -sV -p 1883,8883,8083,8084,9001 --open -T4 "$domain" -oN "$phase_dir/nmap_mqtt.txt" 2>>"$LOGS_DIR/mqtt.log" || true
    fi

    local mqtt_detected=false
    if [[ -f "$phase_dir/nmap_mqtt.txt" ]] && grep -q 'open' "$phase_dir/nmap_mqtt.txt" 2>/dev/null; then
        mqtt_detected=true
        echo "[MQTT_PORT] domain=$domain MQTT ports open" >> "$mqtt_file"
        ((count++)) || true
    fi

    # --- MQTT connection and topic enumeration ---
    if tool_available "mosquitto_sub" || command -v mosquitto_sub >/dev/null 2>&1; then
        log "INFO" "Enumerating MQTT topics via mosquitto_sub..."

        # Subscribe to wildcard topic to capture all published messages
        timeout 10 mosquitto_sub -h "$domain" -p 1883 -t '#' -v -C 20 2>>"$LOGS_DIR/mqtt_enum.log" >> "$topics_file" || true

        # Test common IoT topics
        local common_topics=(
            "/#"
            "home/#"
            "device/#"
            "sensor/#"
            "iot/#"
            "devices/#"
            "sensors/#"
            "home/+/status"
            "home/+/temperature"
            "home/+/humidity"
            "home/+/light"
            "home/+/switch"
            "$domain/#"
        )

        for topic in "${common_topics[@]}"; do
            timeout 5 mosquitto_sub -h "$domain" -p 1883 -t "$topic" -v -C 5 2>>"$LOGS_DIR/mqtt_topics.log" >> "$topics_file" || true
        done
    fi

    # --- Test MQTT without authentication ---
    log "INFO" "Testing MQTT broker authentication..."
    local mqtt_test_modes=(
        "anonymous"
        "no_auth"
        "blank_user"
    )

    # Try anonymous connection
    if tool_available "mosquitto_pub" || command -v mosquitto_pub >/dev/null 2>&1; then
        timeout 5 mosquitto_pub -h "$domain" -p 1883 -t "test/probe" -m "probe_$(date +%s)" 2>>"$LOGS_DIR/mqtt_auth.log" && {
            echo "[MQTT_ANON] domain=$domain - Anonymous publish successful (no auth required)" >> "$mqtt_file"
            ((count++)) || true
        } || true

        # Try with blank credentials
        timeout 5 mosquitto_pub -h "$domain" -p 1883 -u "" -P "" -t "test/probe" -m "probe_$(date +%s)" 2>>"$LOGS_DIR/mqtt_auth.log" && {
            echo "[MQTT_BLANK_AUTH] domain=$domain - Blank credentials accepted" >> "$mqtt_file"
            ((count++)) || true
        } || true
    fi

    # --- Check for MQTT over WebSocket ---
    log "INFO" "Checking for MQTT WebSocket endpoints..."
    local ws_paths=(
        "/mqtt"
        "/ws"
        "/websocket"
        "/mqtt-websocket"
    )

    for ws_path in "${ws_paths[@]}"; do
        local ws_code
        ws_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
            -H "Upgrade: websocket" -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
            "https://$domain$ws_path" 2>/dev/null) || true
        if [[ "$ws_code" == "101" || "$ws_code" == "426" ]]; then
            echo "[MQTT_WS] domain=$domain path=$ws_path (MQTT WebSocket endpoint)" >> "$mqtt_file"
            ((count++)) || true
        fi
    done

    # --- MQTT default credentials ---
    log "INFO" "Testing MQTT default credentials..."
    local mqtt_creds=(
        "admin:admin"
        "mqtt:mqtt"
        "user:user"
        "guest:guest"
        "test:test"
        "anonymous:"
    )

    for cred in "${mqtt_creds[@]}"; do
        local mqtt_user="${cred%%:*}"
        local mqtt_pass="${cred#*:}"
        if tool_available "mosquitto_sub" || command -v mosquitto_sub >/dev/null 2>&1; then
            timeout 3 mosquitto_sub -h "$domain" -p 1883 -u "$mqtt_user" -P "$mqtt_pass" -t '#' -C 1 2>>"$LOGS_DIR/mqtt_creds.log" && {
                echo "[MQTT_DEFAULT_CREDS] domain=$domain user=$mqtt_user pass=$mqtt_pass" >> "$mqtt_file"
                ((count++)) || true
            } || true
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$mqtt_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "mqtt_vuln" "" "" "" || true
        done < "$mqtt_file"
    fi

    if [[ -f "$topics_file" ]]; then
        while IFS= read -r asset; do
            write_asset "$phase_dir" "$domain" "mqtt_topic" "$asset" "" "" || true
        done < "$topics_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "iot_mqtt_phase" "domain=$domain findings=$count"
    log "INFO" "iot_mqtt_phase complete: $count findings"
    return 0
}

iot_mqtt_phase "$@"
