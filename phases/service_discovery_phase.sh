#!/usr/bin/env bash
# service_discovery_phase.sh - Internal service discovery, microservice mapping,
# service mesh analysis.

service_discovery_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "service_discovery_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/service_discovery"

    local results=0
    local services_file="$output_dir/service_discovery/internal_services.txt"
    local map_file="$output_dir/service_discovery/service_map.txt"
    local findings_file="$output_dir/service_discovery/findings.json"

    log "INFO" "Starting service discovery phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Discover internal services via HTTP headers and responses ---
    local main_resp
    main_resp=$(curl -s -m 15 -D - "https://$domain" 2>/dev/null || true)

    if [[ -n "$main_resp" ]]; then
        # Extract server technology
        local server_header
        server_header=$(echo "$main_resp" | grep -i '^server:' 2>/dev/null | head -1 || true)
        if [[ -n "$server_header" ]]; then
            echo "[SERVER-HEADER] $domain - $server_header" >> "$services_file"
            ((results++)) || true

            write_asset "{\"type\":\"server_tech\",\"domain\":\"$domain\",\"header\":\"$(echo "$server_header" | tr -d '\r')\",\"phase\":\"service_discovery\"}" \
                "$findings_file" 2>/dev/null || true
        fi

        # Extract upstream/proxy headers
        local proxy_headers
        proxy_headers=$(echo "$main_resp" | grep -iE '(x-upstream|x-proxy|x-backend|x-real|x-forward|x-amz|via|x-envoy|x-request-id)' 2>/dev/null || true)
        if [[ -n "$proxy_headers" ]]; then
            while IFS= read -r ph; do
                echo "[PROXY-HEADER] $domain - $ph" >> "$services_file"
                ((results++)) || true
            done <<< "$proxy_headers"
        fi
    fi

    # --- Discover microservice endpoints ---
    local service_paths=(
        "/api/health"
        "/api/v1/health"
        "/api/v2/health"
        "/health"
        "/healthz"
        "/ready"
        "/readyz"
        "/live"
        "/livez"
        "/status"
        "/api/status"
        "/api/info"
        "/api/version"
        "/metrics"
        "/prometheus"
        "/actuator"
        "/actuator/health"
        "/actuator/info"
        "/actuator/env"
        "/debug"
        "/debug/vars"
        "/debug/pprof/"
        "/internal"
        "/internal/health"
        "/admin"
        "/admin/health"
        "/_internal"
        "/_service"
        "/graphql"
        "/graphql/console"
        "/graphiql"
        "/altair"
        "/playground"
    )

    for spath in "${service_paths[@]}"; do
        local s_url="https://${domain}${spath}"
        local s_status s_body
        s_body=$(curl -s -m 10 -w "\n%{http_code}" "$s_url" 2>/dev/null || true)
        s_status=$(echo "$s_body" | tail -1)

        if [[ "$s_status" != "000" && "$s_status" != "404" ]]; then
            local content
            content=$(echo "$s_body" | head -n -1)

            echo "[SERVICE-ENDPOINT] $s_url - HTTP $s_status" >> "$services_file"
            ((results++)) || true

            # Extract service info
            echo "$content" | grep -qiE '(service|app|version|build|commit|git)' 2>/dev/null && {
                echo "[SERVICE-INFO] $s_url - Service information disclosed" >> "$map_file"
            } || true
        fi
    done

    # --- Discover service mesh endpoints ---
    local mesh_paths=(
        "/istio"
        "/istio/config"
        "/istio/proxy"
        "/envoy"
        "/envoy/stats"
        "/envoy/config"
        "/linkerd"
        "/linkerd/api"
        "/consul"
        "/consul/v1/agent"
        "/consul/v1/catalog"
        "/consul/v1/health"
        "/consul/ui"
        "/vault"
        "/vault/v1/sys/health"
        "/vault/v1/auth"
        "/nats"
        "/nats/healthz"
        "/redis"
        "/rabbitmq"
        "/rabbitmq/api"
        "/kafka"
    )

    for mpath in "${mesh_paths[@]}"; do
        local m_url="https://${domain}${mpath}"
        local m_status
        m_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$m_url" 2>/dev/null || echo "000")

        if [[ "$m_status" != "000" && "$m_status" != "404" ]]; then
            echo "[MESH-ENDPOINT] $m_url - Service mesh/infra endpoint (HTTP $m_status)" >> "$services_file"
            ((results++)) || true

            write_finding "{\"type\":\"service_mesh_exposed\",\"url\":\"$m_url\",\"severity\":\"HIGH\",\"evidence\":\"Service mesh/infrastructure endpoint accessible\"}" \
                "$findings_file" 2>/dev/null || true
        fi
    done

    # --- Discover via DNS and subdomain enumeration ---
    local internal_subdomains=(
        "api"
        "internal"
        "admin"
        "dev"
        "staging"
        "stage"
        "test"
        "uat"
        "qa"
        "ci"
        "jenkins"
        "gitlab"
        "grafana"
        "prometheus"
        "kibana"
        "elasticsearch"
        "redis"
        "mysql"
        "postgres"
        "mongo"
        "rabbitmq"
        "kafka"
        "k8s"
        "kubernetes"
        "docker"
        "registry"
        "vault"
        "consul"
        "nats"
        "etcd"
        "monitoring"
        "logs"
        "metrics"
        "tracing"
    )

    for sub in "${internal_subdomains[@]}"; do
        local sub_url="https://${sub}.${domain}"
        local sub_status
        sub_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$sub_url" 2>/dev/null || echo "000")

        if [[ "$sub_status" != "000" ]]; then
            echo "[SUBDOMAIN-SERVICE] $sub_url - HTTP $sub_status" >> "$map_file"
            ((results++)) || true
        fi
    done

    # --- GraphQL introspection ---
    local graphql_urls=(
        "https://${domain}/graphql"
        "https://${domain}/api/graphql"
        "https://${domain}/v1/graphql"
        "https://api.${domain}/graphql"
    )

    local introspection_query='{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

    for gql_url in "${graphql_urls[@]}"; do
        local gql_resp gql_status
        gql_resp=$(curl -s -m 10 -w "\n%{http_code}" -X POST \
            -H "Content-Type: application/json" \
            -d "$introspection_query" \
            "$gql_url" 2>/dev/null || true)
        gql_status=$(echo "$gql_resp" | tail -1)

        if [[ "$gql_status" == "200" ]]; then
            local gql_body
            gql_body=$(echo "$gql_resp" | head -n -1)

            echo "$gql_body" | grep -q '__schema' 2>/dev/null && {
                echo "[GRAPHQL-INTROSPECTION] $gql_url - GraphQL introspection enabled" >> "$vulns_file" 2>/dev/null
                echo "[GRAPHQL-INTROSPECTION] $gql_url - GraphQL introspection enabled" >> "$services_file"
                ((results++)) || true

                write_finding "{\"type\":\"graphql_introspection\",\"url\":\"$gql_url\",\"severity\":\"MEDIUM\",\"evidence\":\"GraphQL introspection query succeeds\"}" \
                    "$findings_file" 2>/dev/null || true

                # Extract type names
                local type_names
                type_names=$(echo "$gql_body" | grep -oE '"name":"[A-Z][a-zA-Z]*"' | sed 's/"name":"//;s/"//' | head -20 || true)
                if [[ -n "$type_names" ]]; then
                    echo "[GRAPHQL-TYPES] $gql_url - Types: $(echo "$type_names" | tr '\n' ', ')" >> "$map_file"
                fi
            } || true
        fi
    done

    # --- Check for exposed service documentation ---
    local doc_paths=(
        "/swagger.json"
        "/swagger.yaml"
        "/openapi.json"
        "/openapi.yaml"
        "/api-docs"
        "/docs"
        "/redoc"
        "/swagger-ui.html"
        "/swagger-ui/"
        "/api/swagger"
        "/api/docs"
    )

    for dpath in "${doc_paths[@]}"; do
        local doc_status
        doc_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://${domain}${dpath}" 2>/dev/null || echo "000")

        if [[ "$doc_status" == "200" ]]; then
            echo "[API-DOCS] https://${domain}${dpath} - API documentation accessible" >> "$services_file"
            ((results++)) || true

            write_endpoint "{\"url\":\"https://${domain}${dpath}\",\"method\":\"GET\",\"status\":200,\"phase\":\"service_discovery\"}" \
                "$findings_file" 2>/dev/null || true
        fi
    done

    # Write count
    echo "$results" > "$output_dir/service_discovery/count.txt"

    py_log "INFO" "service_discovery_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Service discovery phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    service_discovery_phase "$@"
fi
