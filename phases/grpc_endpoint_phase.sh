#!/bin/bash
# gRPC/Protobuf endpoint discovery, reflection API abuse, service enumeration

grpc_endpoint_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local grpc_dir="$output_dir/grpc_endpoint"
    local crawl_file="$output_dir/crawl/endpoints.txt"
    local live_file="$output_dir/live/live_subdomains.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$grpc_dir"

    log "INFO" "Starting gRPC endpoint discovery for $domain"
    py_log "INFO" "grpc_endpoint_phase started" --phase "grpc_endpoint" --target "$domain" || true

    local grpc_endpoints="$grpc_dir/grpc_endpoints.txt"
    local grpc_services="$grpc_dir/grpc_services.txt"
    touch "$grpc_endpoints" "$grpc_services"

    # ------------------------------------------------------------------
    # 1. Discover gRPC endpoints from crawled data
    # ------------------------------------------------------------------
    if [ -f "$crawl_file" ] && command -v grep >/dev/null 2>&1; then
        log "INFO" "Discovering gRPC endpoints from crawl data..."
        grep -iE "(grpc|\.proto|grpc-web|grpcweb|proto$|protobuf)" "$crawl_file" 2>/dev/null \
            | sort -u > "$grpc_endpoints" || true
    fi

    # Probe common gRPC paths
    if [ -f "$live_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Probing common gRPC paths..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            # gRPC HTTP/2 base path
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 --http2 \
                "${host%/}/" 2>/dev/null) || true
            if echo "$code" | grep -qE "^(200|404|405)$"; then
                echo "${host%/}/" >> "$grpc_endpoints"
            fi
            # gRPC-Web endpoint
            local code2
            code2=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                -H "Content-Type: application/grpc-web" \
                "${host%/}/grpc.web.v1.Reactor/Grpc" 2>/dev/null) || true
            if echo "$code2" | grep -qE "^(200|404|405)$"; then
                echo "${host%/}/grpc.web.v1" >> "$grpc_endpoints"
            fi
        done < <(head -30 "$live_file")
        sort -u "$grpc_endpoints" -o "$grpc_endpoints" 2>/dev/null || true
    fi

    # ------------------------------------------------------------------
    # 2. gRPC server reflection abuse
    # ------------------------------------------------------------------
    if [ -f "$grpc_endpoints" ] && [ -s "$grpc_endpoints" ] && command -v grpcurl >/dev/null 2>&1; then
        log "INFO" "Testing gRPC server reflection..."
        while IFS= read -r grpc_url; do
            [ -z "$grpc_url" ] && continue
            # List services via reflection
            local services
            services=$(grpcurl -plaintext "$grpc_url" list 2>/dev/null) || true
            if [ -n "$services" ]; then
                echo "REFLECTION_ENABLED: $grpc_url" >> "$grpc_services"
                echo "$services" >> "$grpc_services"
                write_finding "{\"type\":\"grpc_reflection_enabled\",\"url\":\"$grpc_url\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$grpc_dir/findings.json" || true

                # List methods for each service
                while IFS= read -r svc; do
                    [ -z "$svc" ] && continue
                    grpcurl -plaintext "$grpc_url" list "$svc" 2>/dev/null >> "$grpc_services" || true
                done < <(echo "$services")
            fi
        done < "$grpc_endpoints"
    fi

    # ------------------------------------------------------------------
    # 3. gRPC reflection via raw HTTP/2 POST
    # ------------------------------------------------------------------
    if [ -f "$grpc_endpoints" ] && [ -s "$grpc_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing gRPC reflection via raw HTTP/2..."
        local reflection_query
        reflection_query=$(printf '\x00\x00\x00\x00\x02\x0a\x00' 2>/dev/null || echo "")

        while IFS= read -r grpc_url; do
            [ -z "$grpc_url" ] && continue
            local resp_code
            resp_code=$(curl -s -o "$grpc_dir/_grpc_resp.tmp" -w "%{http_code}" --http2 \
                -X POST -H "Content-Type: application/grpc" \
                -d "$reflection_query" \
                "${grpc_url}grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo" 2>/dev/null) || true
            if echo "$resp_code" | grep -qE "^(200|000)$"; then
                local resp_size
                resp_size=$(wc -c < "$grpc_dir/_grpc_resp.tmp" 2>/dev/null || echo 0)
                if [ "$resp_size" -gt 10 ]; then
                    echo "GRPC_RAW_REFLECTION: $grpc_url | Response size: $resp_size bytes" >> "$grpc_services"
                fi
            fi
        done < "$grpc_endpoints"
    fi

    # ------------------------------------------------------------------
    # 4. Common gRPC service enumeration
    # ------------------------------------------------------------------
    if [ -f "$grpc_endpoints" ] && [ -s "$grpc_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Enumerating common gRPC services..."
        local common_services
        common_services=$(cat << 'GRPCSERVICES'
grpc.health.v1.Health/Check
grpc.health.v1.Health/Watch
grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo
grpc.reflection.v1.ServerReflection/ServerReflectionInfo
grpc.channelz.v1.Channelz/GetTopChannels
grpc.channelz.v1.Channelz/GetServers
grpc.admin.v1.Admin/GetServerConfig
GRPCSERVICES
)

        while IFS= read -r grpc_url; do
            [ -z "$grpc_url" ] && continue
            while IFS= read -r svc; do
                [ -z "$svc" ] && continue
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --http2 \
                    -X POST -H "Content-Type: application/grpc" \
                    --max-time 10 "${grpc_url}${svc}" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|000)$"; then
                    echo "GRPC_SERVICE: $grpc_url | Service: $svc | Status: $code" >> "$grpc_services"
                fi
            done < <(echo "$common_services")
        done < "$grpc_endpoints"
    fi

    # ------------------------------------------------------------------
    # 5. gRPC-Web bypass and CORS testing
    # ------------------------------------------------------------------
    if [ -f "$grpc_endpoints" ] && [ -s "$grpc_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing gRPC-Web CORS..."
        while IFS= read -r grpc_url; do
            [ -z "$grpc_url" ] && continue
            local cors_resp
            cors_resp=$(curl -s -D - -o /dev/null --max-time 10 \
                -X OPTIONS -H "Origin: https://evil.com" \
                -H "Access-Control-Request-Method: POST" \
                "${grpc_url}grpc.web.v1" 2>/dev/null) || true
            if echo "$cors_resp" | grep -qiE "access-control-allow-origin.*evil\.com"; then
                echo "GRPC_WEB_CORS_BYPASS: $grpc_url" >> "$grpc_endpoints"
                write_finding "{\"type\":\"grpc_web_cors_bypass\",\"url\":\"$grpc_url\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$grpc_dir/findings.json" || true
            fi
        done < "$grpc_endpoints"
    fi

    # ------------------------------------------------------------------
    # 6. Summary count
    # ------------------------------------------------------------------
    local ep_count
    ep_count=$(wc -l < "$grpc_endpoints" 2>/dev/null || echo 0)
    local svc_count
    svc_count=$(wc -l < "$grpc_services" 2>/dev/null || echo 0)
    log "INFO" "gRPC discovery complete: $ep_count endpoints, $svc_count service entries"

    py_log "INFO" "grpc_endpoint_phase complete" --phase "grpc_endpoint" --target "$domain" --extra "{\"endpoints\":$ep_count,\"services\":$svc_count}" || true
    echo "$ep_count" > "$grpc_dir/count.txt"
}

export -f grpc_endpoint_phase
