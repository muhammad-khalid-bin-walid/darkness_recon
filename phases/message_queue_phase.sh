#!/usr/bin/env bash
# Message Queue Exposure Detection
# Checks for exposed RabbitMQ, Kafka, Redis, MQTT, and other queue services

message_queue_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "message_queue_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/message_queue"
    mkdir -p "$phase_dir"

    log "INFO" "Starting message_queue_phase for $domain"

    local mq_vulns="$phase_dir/mq_vulns.txt"
    local exposed_queues="$phase_dir/exposed_queues.txt"
    local count=0

    # --- Resolve IP for direct port scanning ---
    local ip_list
    ip_list=$(dig +short "$domain" A 2>/dev/null) || true

    # --- RabbitMQ Management UI (default: 15672) ---
    log "INFO" "Checking RabbitMQ management interface..."
    local mq_mgmt_ports=(15672 15673 443)
    for port in "${mq_mgmt_ports[@]}"; do
        for ip in $ip_list; do
            local mq_resp
            mq_resp=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$ip:$port/" 2>/dev/null) || true
            if [[ "$mq_resp" == "200" ]] || [[ "$mq_resp" == "401" ]]; then
                echo "[VULN] RabbitMQ management UI accessible at $ip:$port (HTTP $mq_resp)" >> "$mq_vulns"
                echo "$ip:$port:rabbitmq" >> "$exposed_queues"
                ((count++)) || true

                # Test default credentials
                if [[ "$mq_resp" == "401" ]]; then
                    local auth_resp
                    auth_resp=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -u "guest:guest" "https://$ip:$port/api/overview" 2>/dev/null) || true
                    if [[ "$auth_resp" == "200" ]]; then
                        echo "[VULN] RabbitMQ default credentials (guest:guest) work at $ip:$port" >> "$mq_vulns"
                        ((count++)) || true
                    fi
                fi
            fi
        done
    done

    # --- RabbitMQ AMQP (5672, 5671) ---
    for port in 5672 5671; do
        for ip in $ip_list; do
            (echo >/dev/tcp/"$ip"/"$port") 2>/dev/null && {
                echo "[VULN] AMQP port $port open on $ip" >> "$mq_vulns"
                echo "$ip:$port:amqp" >> "$exposed_queues"
                ((count++)) || true
            } || true
        done
    done

    # --- Kafka (9092, 9093, 9094, 9101) ---
    log "INFO" "Checking Kafka endpoints..."
    local kafka_ports=(9092 9093 9094 9101)
    for port in "${kafka_ports[@]}"; do
        for ip in $ip_list; do
            (echo >/dev/tcp/"$ip"/"$port") 2>/dev/null && {
                echo "[VULN] Kafka port $port open on $ip" >> "$mq_vulns"
                echo "$ip:$port:kafka" >> "$exposed_queues"
                ((count++)) || true
            } || true
        done
    done

    # --- Kafka Connect REST API (8083) ---
    for ip in $ip_list; do
        local kafka_resp
        kafka_resp=$(curl -s -m 5 "http://$ip:8083/connectors" 2>/dev/null) || true
        if echo "$kafka_resp" | grep -q '\['; then
            echo "[VULN] Kafka Connect REST API accessible at $ip:8083" >> "$mq_vulns"
            echo "$ip:8083:kafka-connect" >> "$exposed_queues"
            ((count++)) || true
        fi
    done

    # --- Redis (6379, 6380, 16379) ---
    log "INFO" "Checking Redis endpoints..."
    local redis_ports=(6379 6380 16379)
    for port in "${redis_ports[@]}"; do
        for ip in $ip_list; do
            local redis_resp
            redis_resp=$(timeout 3 bash -c "echo PING | nc -w 2 $ip $port" 2>/dev/null) || true
            if echo "$redis_resp" | grep -qi "PONG"; then
                echo "[VULN] Redis accessible at $ip:$port (unauthenticated)" >> "$mq_vulns"
                echo "$ip:$port:redis" >> "$exposed_queues"
                ((count++)) || true

                # Check for sensitive data
                local redis_info
                redis_info=$(timeout 3 bash -c "printf 'INFO\r\n' | nc -w 2 $ip $port" 2>/dev/null) || true
                if echo "$redis_info" | grep -qi "connected_clients"; then
                    echo "[INFO] Redis INFO accessible at $ip:$port" >> "$mq_vulns"
                fi
            fi
        done
    done

    # --- MQTT (1883, 8883) ---
    log "INFO" "Checking MQTT endpoints..."
    local mqtt_ports=(1883 8883)
    for port in "${mqtt_ports[@]}"; do
        for ip in $ip_list; do
            (echo >/dev/tcp/"$ip"/"$port") 2>/dev/null && {
                echo "[VULN] MQTT port $port open on $ip" >> "$mq_vulns"
                echo "$ip:$port:mqtt" >> "$exposed_queues"
                ((count++)) || true
            } || true
        done
    done

    # --- NATS (4222, 8222) ---
    log "INFO" "Checking NATS endpoints..."
    local nats_ports=(4222 8222)
    for port in "${nats_ports[@]}"; do
        for ip in $ip_list; do
            local nats_resp
            nats_resp=$(curl -s -m 5 "http://$ip:$port/connz" 2>/dev/null) || true
            if echo "$nats_resp" | grep -qi "connections"; then
                echo "[VULN] NATS monitoring accessible at $ip:$port" >> "$mq_vulns"
                echo "$ip:$port:nats" >> "$exposed_queues"
                ((count++)) || true
            fi
        done
    done

    # --- ActiveMQ (8161, 61616) ---
    log "INFO" "Checking ActiveMQ endpoints..."
    for port in 8161 61616; do
        for ip in $ip_list; do
            local amq_code
            amq_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "http://$ip:$port/" 2>/dev/null) || true
            if [[ "$amq_code" == "200" ]] || [[ "$amq_code" == "401" ]]; then
                echo "[VULN] ActiveMQ accessible at $ip:$port (HTTP $amq_code)" >> "$mq_vulns"
                echo "$ip:$port:activemq" >> "$exposed_queues"
                ((count++)) || true
            fi
        done
    done

    # --- Write structured findings ---
    if [[ -f "$mq_vulns" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "message_queue" "" "" ""
        done < "$mq_vulns"
    fi

    if [[ -f "$exposed_queues" ]]; then
        while IFS= read -r asset; do
            write_asset "$phase_dir" "$domain" "message_queue" "$asset" "" ""
        done < "$exposed_queues"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "message_queue_phase" "domain=$domain findings=$count"

    log "INFO" "message_queue_phase complete: $count findings"
    return 0
}

message_queue_phase "$@"
