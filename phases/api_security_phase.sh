#!/bin/bash
# Combined Phase 9: API Security & Enumeration
# Encompasses: OpenAPI, GraphQL, gRPC enumeration, API endpoint testing
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

api_security_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local subdomains_file="$output_dir/subdomains/subdomains.txt"
    local api_dir="$output_dir/api"

    mkdir -p "$api_dir"

    log "INFO" "Starting API security & enumeration for $domain"

    # OpenAPI/Swagger discovery
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking for OpenAPI/Swagger documentation..."
        curl -s "https://$domain/swagger.json" 2>>"$LOGS_DIR/api.log" >> "$api_dir/swagger.json" || true
        curl -s "https://$domain/swagger.yaml" 2>>"$LOGS_DIR/api.log" >> "$api_dir/swagger.yaml" || true
        curl -s "https://$domain/openapi.json" 2>>"$LOGS_DIR/api.log" >> "$api_dir/openapi.json" || true
    fi

    # GraphQL introspection
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking for GraphQL introspection..."
        curl -s "https://$domain/graphql" -X POST -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name } }"}' 2>>"$LOGS_DIR/api.log" >> "$api_dir/graphql.txt" || true
    fi

    # gRPC reflection
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Checking for gRPC reflection..."
        curl -s "https://$domain:50051/reflection" 2>>"$LOGS_DIR/api.log" >> "$api_dir/grpc.txt" || true
    fi

    # API endpoint discovery from JavaScript files
    if tool_available "hakrawler"; then
        log "INFO" "Extracting API endpoints from JS files..."
        cat "$output_dir/crawl/endpoints.txt" 2>/dev/null | while read -r ep; do
            echo "$ep" | grep -iE "/api/|/rest/|/graphql/|/grpc/" >> "$api_dir/discovered_apis.txt" 2>/dev/null || true
        done
    fi

    # Deduplicate discovered APIs
    if [ -f "$api_dir/discovered_apis.txt" ]; then
        sort -u "$api_dir/discovered_apis.txt" > "$api_dir/unique_apis.txt"
    else
        touch "$api_dir/unique_apis.txt"
    fi

    local api_count
    api_count=$(wc -l < "$api_dir/unique_apis.txt" 2>/dev/null || echo 0)

    phase_log "INFO" "API security & enumeration complete: $api_count APIs discovered" "api_enumeration" "$domain"

    # Write assets
    while IFS= read -r api; do
        [ -z "$api" ] && continue
        write_asset "{\"type\":\"api_endpoint\",\"value\":\"$api\",\"source\":\"api_discovery\",\"phase\":\"api_security_enumeration\"}" \
            "$api_dir/assets.jsonl" 2>/dev/null || true
    done < "$api_dir/unique_apis.txt"

    echo "$api_count" > "$api_dir/count.txt"

    py_log "INFO" "api_security_phase" "Completed for $domain"
}