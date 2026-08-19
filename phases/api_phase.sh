#!/bin/bash
# API endpoint discovery phase

api_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local api_dir="$output_dir/api"
    local crawl_file="$output_dir/crawl/endpoints.txt"

    mkdir -p "$api_dir"

    log "INFO" "Starting API endpoint discovery for $domain"

    if [ ! -f "$crawl_file" ]; then
        log "WARN" "No endpoints file found, skipping API discovery"
        return 1
    fi

    if tool_available "apiscope"; then
        log "INFO" "Running apiscope for API discovery..."
        apiscope -i "$crawl_file" -o "$api_dir/apiscope_results.txt" 2>>"$LOGS_DIR/apiscope.log" || true
    fi

    if command -v grep >/dev/null 2>&1; then
        log "INFO" "Extracting API endpoints..."
        grep -iE "(/api/|/v[0-9]+/|graphql|openapi|swagger|/rest/|/rpc/)" "$crawl_file" 2>/dev/null | \
            sort -u > "$api_dir/api_endpoints.txt" || true
    fi

    if command -v grep >/dev/null 2>&1; then
        log "INFO" "Extracting GraphQL endpoints..."
        grep -iE "(graphql|/__graphql|/graphql/)" "$crawl_file" 2>/dev/null | \
            sort -u > "$api_dir/graphql_endpoints.txt" || true
    fi

    if command -v grep >/dev/null 2>&1; then
        log "INFO" "Extracting OpenAPI/Swagger specs..."
        grep -iE "(swagger|openapi|/swagger.json|/openapi.json|/v3/api-docs)" "$crawl_file" 2>/dev/null | \
            sort -u > "$api_dir/swagger_specs.txt" || true
    fi

    local api_count
    api_count=$(wc -l < "$api_dir/api_endpoints.txt" 2>/dev/null || echo 0)
    
    phase_log "INFO" "API endpoint discovery complete: $api_count API endpoints found" "api" "$domain"

    # Write endpoints for discovered APIs
    while IFS= read -r endpoint; do
        [ -z "$endpoint" ] && continue
        write_endpoint "{\"url\":\"$endpoint\",\"method\":\"GET\",\"phase\":\"api\"}" \
            "$api_dir/endpoints.jsonl" 2>/dev/null || true
    done < "$api_dir/api_endpoints.txt" 2>/dev/null

    # Write findings for GraphQL endpoints
    if [ -f "$api_dir/graphql_endpoints.txt" ]; then
        local graphql_count
        graphql_count=$(wc -l < "$api_dir/graphql_endpoints.txt" 2>/dev/null || echo 0)
        if [ "$graphql_count" -gt 0 ]; then
            write_finding "{\"type\":\"graphql_endpoint\",\"severity\":\"info\",\"count\":$graphql_count,\"phase\":\"api\"}" \
                "$api_dir/findings.jsonl" 2>/dev/null || true
        fi
    fi

    # Write findings for Swagger/OpenAPI specs
    if [ -f "$api_dir/swagger_specs.txt" ]; then
        local swagger_count
        swagger_count=$(wc -l < "$api_dir/swagger_specs.txt" 2>/dev/null || echo 0)
        if [ "$swagger_count" -gt 0 ]; then
            write_finding "{\"type\":\"swagger_spec\",\"severity\":\"info\",\"count\":$swagger_count,\"phase\":\"api\"}" \
                "$api_dir/findings.jsonl" 2>/dev/null || true
        fi
    fi

    echo "$api_count" > "$api_dir/count.txt"

    py_log "INFO" "api_phase" "Completed for $domain — $api_count endpoints"
}