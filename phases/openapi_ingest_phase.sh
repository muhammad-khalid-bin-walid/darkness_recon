#!/bin/bash
# OpenAPI/Swagger/GraphQL spec auto-ingestion and schema analysis phase

openapi_ingest_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local spec_dir="$output_dir/openapi_ingest"
    local crawl_file="$output_dir/crawl/endpoints.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$spec_dir"

    log "INFO" "Starting OpenAPI/Swagger spec ingestion for $domain"
    py_log "INFO" "openapi_ingest_phase started" --phase "openapi_ingest" --target "$domain" || true

    # ------------------------------------------------------------------
    # 1. Discover candidate spec URLs from crawled endpoints
    # ------------------------------------------------------------------
    local spec_candidates="$spec_dir/spec_candidates.txt"
    if [ -f "$crawl_file" ] && command -v grep >/dev/null 2>&1; then
        log "INFO" "Discovering OpenAPI/Swagger spec URLs..."
        grep -iE "(/swagger\.json|/swagger\.yaml|/openapi\.json|/openapi\.yaml|/v[0-9]+/api-docs|/api/swagger|/api/docs|/swagger-ui|/redoc|/graphql|/\$graphql|/schema\.graphql)" "$crawl_file" 2>/dev/null \
            | sort -u > "$spec_candidates" || true
    fi

    # Also probe common well-known paths
    local live_file="$output_dir/live/live_subdomains.txt"
    if [ -f "$live_file" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Probing common spec endpoints..."
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            for path in /swagger.json /openapi.json /v2/api-docs /v3/api-docs /api-docs /swagger/v1/swagger.json /graphql; do
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${host%/}${path}" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|201)$"; then
                    echo "${host%/}${path}" >> "$spec_candidates"
                fi
            done
        done < <(head -20 "$live_file")
        sort -u "$spec_candidates" -o "$spec_candidates" 2>/dev/null || true
    fi

    # ------------------------------------------------------------------
    # 2. Download and parse discovered specs
    # ------------------------------------------------------------------
    local api_specs="$spec_dir/api_specs.txt"
    local extracted_endpoints="$spec_dir/extracted_endpoints.txt"
    local api_schemas="$spec_dir/api_schemas.txt"
    touch "$api_specs" "$extracted_endpoints" "$api_schemas"

    if [ -f "$spec_candidates" ] && [ -s "$spec_candidates" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Downloading and parsing API specs..."
        while IFS= read -r spec_url; do
            [ -z "$spec_url" ] && continue
            local spec_file="$spec_dir/spec_$(echo "$spec_url" | md5sum | cut -d' ' -f1).json"
            curl -s --max-time 20 "$spec_url" -o "$spec_file" 2>/dev/null || true

            if [ -s "$spec_file" ]; then
                echo "SPEC: $spec_url" >> "$api_specs"

                # Extract endpoints using python3 or jq
                if command -v python3 >/dev/null 2>&1; then
                    python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    paths = data.get('paths', {})
    for path, methods in paths.items():
        for method in methods:
            if method.lower() in ('get','post','put','delete','patch','options','head'):
                print(f'{method.upper()} {path}')
    schemas = data.get('components', {}).get('schemas', {}) or data.get('definitions', {})
    for name in schemas:
        print(f'SCHEMA: {name}', file=sys.stderr)
except Exception:
    pass
" "$spec_file" 2>"$spec_dir/_schema_tmp.txt" >> "$extracted_endpoints" || true
                    cat "$spec_dir/_schema_tmp.txt" >> "$api_schemas" 2>/dev/null || true
                    rm -f "$spec_dir/_schema_tmp.txt" 2>/dev/null || true
                elif tool_available "jq"; then
                    jq -r '.paths // {} | to_entries[] | .key as $path | .value | keys[] | select(. != "parameters") | "\(ascii_upcase) \($path)"' "$spec_file" 2>/dev/null >> "$extracted_endpoints" || true
                    jq -r '(.components.schemas // .definitions // {}) | keys[]' "$spec_file" 2>/dev/null | sed 's/^/SCHEMA: /' >> "$api_schemas" 2>/dev/null || true
                fi
            fi
        done < "$spec_candidates"
        sort -u "$extracted_endpoints" -o "$extracted_endpoints" 2>/dev/null || true
        sort -u "$api_schemas" -o "$api_schemas" 2>/dev/null || true
    fi

    # ------------------------------------------------------------------
    # 3. Write validated findings via phase_bridge
    # ------------------------------------------------------------------
    if [ -s "$extracted_endpoints" ]; then
        while IFS= read -r ep; do
            [ -z "$ep" ] && continue
            local ep_method ep_path
            ep_method=$(echo "$ep" | awk '{print $1}')
            ep_path=$(echo "$ep" | awk '{print $2}')
            write_endpoint "{\"type\":\"api_endpoint\",\"method\":\"$ep_method\",\"path\":\"$ep_path\",\"source\":\"openapi_ingest\",\"domain\":\"$domain\"}" "$spec_dir/endpoints.json" || true
        done < "$extracted_endpoints"
    fi

    if [ -s "$api_specs" ]; then
        while IFS= read -r spec_line; do
            [ -z "$spec_line" ] && continue
            local spec_url
            spec_url=$(echo "$spec_line" | sed 's/^SPEC: //')
            write_asset "{\"type\":\"api_spec\",\"url\":\"$spec_url\",\"domain\":\"$domain\"}" "$spec_dir/assets.json" || true
        done < "$api_specs"
    fi

    # ------------------------------------------------------------------
    # 4. Summary count
    # ------------------------------------------------------------------
    local ep_count
    ep_count=$(wc -l < "$extracted_endpoints" 2>/dev/null || echo 0)
    log "INFO" "OpenAPI ingestion complete: $ep_count endpoints extracted from specs"

    write_finding "{\"type\":\"openapi_ingest\",\"severity\":\"info\",\"endpoints\":$ep_count,\"phase\":\"openapi_ingest\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "openapi_ingest_phase complete" --phase "openapi_ingest" --target "$domain" --extra "{\"endpoints\":$ep_count}" || true
    echo "$ep_count" > "$spec_dir/count.txt"
}

export -f openapi_ingest_phase
