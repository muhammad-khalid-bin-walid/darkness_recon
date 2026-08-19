#!/usr/bin/env bash
# Log & Monitoring Endpoint Exposure Detection
# Checks for exposed Elasticsearch, Kibana, Grafana, and other monitoring tools

log_exposure_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "log_exposure_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/log_exposure"
    mkdir -p "$phase_dir"

    log "INFO" "Starting log_exposure_phase for $domain"

    local log_vulns="$phase_dir/log_vulns.txt"
    local exposed_logs="$phase_dir/exposed_logs.txt"
    local count=0

    # --- Resolve IPs for direct access checks ---
    local ip_list
    ip_list=$(dig +short "$domain" A 2>/dev/null) || true

    # --- Elasticsearch (9200, 9300) ---
    log "INFO" "Checking Elasticsearch endpoints..."
    local es_ports=(9200 9300)
    for port in "${es_ports[@]}"; do
        for ip in $ip_list; do
            local es_resp
            es_resp=$(curl -s -m 5 "http://$ip:$port/" 2>/dev/null) || true
            if echo "$es_resp" | grep -qiE "cluster_name\|cluster_uuid\|tagline.*you know"; then
                echo "[VULN] Elasticsearch accessible at $ip:$port (unauthenticated)" >> "$log_vulns"
                echo "$ip:$port:elasticsearch" >> "$exposed_logs"
                ((count++)) || true

                # Check cluster info
                local cluster_name
                cluster_name=$(echo "$es_resp" | grep -o '"cluster_name":"[^"]*"' | head -1) || true
                echo "[INFO] Cluster: $cluster_name" >> "$log_vulns"
            fi
        done
    done

    # --- Kibana (5601, 443) ---
    log "INFO" "Checking Kibana endpoints..."
    local kibana_paths=("/app/kibana" "/app/discover" "/login" "/")
    for ip in $ip_list; do
        for path in "${kibana_paths[@]}"; do
            local kb_resp
            kb_resp=$(curl -sI -m 5 "https://$ip:5601$path" 2>/dev/null) || true
            if echo "$kb_resp" | grep -qiE "kibana\|x-kibana"; then
                echo "[VULN] Kibana accessible at $ip:5601$path" >> "$log_vulns"
                echo "$ip:5601:kibana" >> "$exposed_logs"
                ((count++)) || true
                break
            fi
        done
    done

    # --- Grafana (3000, 443) ---
    log "INFO" "Checking Grafana endpoints..."
    for ip in $ip_list; do
        local grafana_resp
        grafana_resp=$(curl -s -m 5 "http://$ip:3000/api/health" 2>/dev/null) || true
        if echo "$grafana_resp" | grep -qi "database.*ok\|commit\|version"; then
            echo "[VULN] Grafana accessible at $ip:3000 (unauthenticated)" >> "$log_vulns"
            echo "$ip:3000:grafana" >> "$exposed_logs"
            ((count++)) || true
        fi
    done

    # --- Prometheus (9090, 9091) ---
    log "INFO" "Checking Prometheus endpoints..."
    local prom_ports=(9090 9091)
    for port in "${prom_ports[@]}"; do
        for ip in $ip_list; do
            local prom_resp
            prom_resp=$(curl -s -m 5 "http://$ip:$port/api/v1/status/config" 2>/dev/null) || true
            if echo "$prom_resp" | grep -qi "yaml\|status.*success"; then
                echo "[VULN] Prometheus accessible at $ip:$port" >> "$log_vulns"
                echo "$ip:$port:prometheus" >> "$exposed_logs"
                ((count++)) || true
            fi
        done
    done

    # --- Jaeger (16686) ---
    log "INFO" "Checking Jaeger endpoints..."
    for ip in $ip_list; do
        local jaeger_resp
        jaeger_resp=$(curl -s -m 5 "http://$ip:16686/api/services" 2>/dev/null) || true
        if echo "$jaeger_resp" | grep -qi "data\|services"; then
            echo "[VULN] Jaeger accessible at $ip:16686" >> "$log_vulns"
            echo "$ip:16686:jaeger" >> "$exposed_logs"
            ((count++)) || true
        fi
    done

    # --- Zipkin (9411) ---
    log "INFO" "Checking Zipkin endpoints..."
    for ip in $ip_list; do
        local zipkin_resp
        zipkin_resp=$(curl -s -m 5 "http://$ip:9411/api/v2/services" 2>/dev/null) || true
        if echo "$zipkin_resp" | grep -qi "data"; then
            echo "[VULN] Zipkin accessible at $ip:9411" >> "$log_vulns"
            echo "$ip:9411:zipkin" >> "$exposed_logs"
            ((count++)) || true
        fi
    done

    # --- Fluentd / Fluent Bit (24224, 24225) ---
    for port in 24224 24225; do
        for ip in $ip_list; do
            (echo >/dev/tcp/"$ip"/"$port") 2>/dev/null && {
                echo "[VULN] Fluentd port $port open on $ip" >> "$log_vulns"
                echo "$ip:$port:fluentd" >> "$exposed_logs"
                ((count++)) || true
            } || true
        done
    done

    # --- Common monitoring paths on web ports ---
    log "INFO" "Checking web-based monitoring endpoints..."
    local monitoring_paths=(
        "/kibana"
        "/grafana"
        "/prometheus"
        "/monitoring"
        "/dashboard"
        "/logs"
        "/metrics"
        "/status"
        "/health"
        "/debug"
        "/actuator"
        "/actuator/env"
        "/actuator/health"
        "/actuator/info"
        "/actuator/metrics"
        "/actuator/trace"
        "/swagger-ui.html"
        "/swagger"
        "/api-docs"
    )

    for path in "${monitoring_paths[@]}"; do
        local mon_code
        mon_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$mon_code" == "200" ]] || [[ "$mon_code" == "302" ]]; then
            echo "[VULN] Monitoring endpoint accessible: https://$domain$path (HTTP $mon_code)" >> "$log_vulns"
            echo "$domain$path" >> "$exposed_logs"
            ((count++)) || true
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$log_vulns" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "log_exposure" "" "" ""
        done < "$log_vulns"
    fi

    if [[ -f "$exposed_logs" ]]; then
        while IFS= read -r asset; do
            write_asset "$phase_dir" "$domain" "log_exposure" "$asset" "" ""
        done < "$exposed_logs"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "log_exposure_phase" "domain=$domain findings=$count"

    log "INFO" "log_exposure_phase complete: $count findings"
    return 0
}

log_exposure_phase "$@"
