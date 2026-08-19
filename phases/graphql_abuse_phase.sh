#!/bin/bash
# GraphQL introspection abuse, field-level authorization testing, query depth analysis, batching attacks

graphql_abuse_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local gql_dir="$output_dir/graphql_abuse"
    local crawl_file="$output_dir/crawl/endpoints.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$gql_dir"

    log "INFO" "Starting GraphQL abuse testing for $domain"
    py_log "INFO" "graphql_abuse_phase started" --phase "graphql_abuse" --target "$domain" || true

    # ------------------------------------------------------------------
    # 1. Discover GraphQL endpoints
    # ------------------------------------------------------------------
    local gql_endpoints="$gql_dir/graphql_endpoints.txt"
    if [ -f "$crawl_file" ] && command -v grep >/dev/null 2>&1; then
        log "INFO" "Discovering GraphQL endpoints..."
        grep -iE "(graphql|/__graphql|/graphql/|/gql|/\$graphql|graphiql)" "$crawl_file" 2>/dev/null \
            | sort -u > "$gql_endpoints" || true
    fi

    # Probe common paths
    local live_file="$output_dir/live/live_subdomains.txt"
    if [ -f "$live_file" ] && command -v curl >/dev/null 2>&1; then
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            for path in /graphql /v1/graphql /v2/graphql /api/graphql /graphiql /gql; do
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
                    -H "Content-Type: application/json" \
                    -d '{"query":"{ __typename }"}' \
                    --max-time 10 "${host%/}${path}" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|201|400)$"; then
                    echo "${host%/}${path}" >> "$gql_endpoints"
                fi
            done
        done < <(head -20 "$live_file")
        sort -u "$gql_endpoints" -o "$gql_endpoints" 2>/dev/null || true
    fi

    local graphql_schema="$gql_dir/graphql_schema.txt"
    local graphql_vulns="$gql_dir/graphql_vulns.txt"
    touch "$graphql_schema" "$graphql_vulns"

    # ------------------------------------------------------------------
    # 2. Introspection abuse - extract full schema
    # ------------------------------------------------------------------
    if [ -f "$gql_endpoints" ] && [ -s "$gql_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing GraphQL introspection..."
        local introspection_query='{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields { name description args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind } } } } types { name kind fields { name type { name kind ofType { name kind } } } } } }"}'

        while IFS= read -r gql_url; do
            [ -z "$gql_url" ] && continue
            local response
            response=$(curl -s --max-time 20 -X POST \
                -H "Content-Type: application/json" \
                -d "$introspection_query" \
                "$gql_url" 2>/dev/null) || true

            if echo "$response" | grep -q "__schema"; then
                echo "INTROSPECTION_ENABLED: $gql_url" >> "$graphql_vulns"
                echo "$response" >> "$graphql_schema"

                # Extract types and fields
                if command -v python3 >/dev/null 2>&1; then
                    python3 -c "
import json, sys
try:
    data = json.loads(sys.stdin.read())
    types = data.get('data', {}).get('__schema', {}).get('types', [])
    for t in types:
        if t.get('name', '').startswith('__'):
            continue
        print(f\"TYPE: {t['name']} ({t['kind']})\")
        for f in t.get('fields', []):
            type_name = f.get('type', {}).get('name') or f.get('type', {}).get('ofType', {}).get('name', '?')
            print(f\"  FIELD: {f['name']}: {type_name}\")
            for arg in f.get('args', []):
                arg_type = arg.get('type', {}).get('name') or arg.get('type', {}).get('ofType', {}).get('name', '?')
                print(f\"    ARG: {arg['name']}: {arg_type}\")
except Exception:
    pass
" <<< "$response" 2>/dev/null >> "$graphql_schema" || true
                fi

                write_finding "{\"type\":\"graphql_introspection_enabled\",\"url\":\"$gql_url\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$gql_dir/findings.json" || true
            else
                echo "INTROSPECTION_DISABLED: $gql_url" >> "$graphql_vulns"
            fi
        done < "$gql_endpoints"
    fi

    # ------------------------------------------------------------------
    # 3. Query depth analysis - detect deeply nested queries
    # ------------------------------------------------------------------
    if [ -f "$gql_endpoints" ] && [ -s "$gql_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing query depth limits..."
        local depth_payload
        depth_payload=$(python3 -c "
query = '{ user { ' * 15 + 'name' + ' }' * 15
print(json.dumps({'query': '{ __typename ' + query + ' }'}))
import json
" 2>/dev/null || echo '{"query":"{ user { posts { author { posts { author { name } } } } } }"}')

        while IFS= read -r gql_url; do
            [ -z "$gql_url" ] && continue
            local code
            code=$(curl -s -o "$gql_dir/_depth_resp.tmp" -w "%{http_code}" -X POST \
                -H "Content-Type: application/json" \
                -d "$depth_payload" \
                --max-time 15 "$gql_url" 2>/dev/null) || true

            if echo "$code" | grep -qE "^(200|201)$"; then
                if grep -q "__typename\|data" "$gql_dir/_depth_resp.tmp" 2>/dev/null; then
                    echo "NO_DEPTH_LIMIT: $gql_url | Deeply nested query accepted" >> "$graphql_vulns"
                    write_finding "{\"type\":\"graphql_no_depth_limit\",\"url\":\"$gql_url\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$gql_dir/findings.json" || true
                fi
            fi
            rm -f "$gql_dir/_depth_resp.tmp" 2>/dev/null || true
        done < "$gql_endpoints"
    fi

    # ------------------------------------------------------------------
    # 4. Batching attack testing
    # ------------------------------------------------------------------
    if [ -f "$gql_endpoints" ] && [ -s "$gql_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing GraphQL query batching..."
        local batch_payload='[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]'

        while IFS= read -r gql_url; do
            [ -z "$gql_url" ] && continue
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
                -H "Content-Type: application/json" \
                -d "$batch_payload" \
                --max-time 15 "$gql_url" 2>/dev/null) || true

            if echo "$code" | grep -qE "^(200|201)$"; then
                echo "BATCHING_ACCEPTED: $gql_url" >> "$graphql_vulns"
                write_finding "{\"type\":\"graphql_batching_accepted\",\"url\":\"$gql_url\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$gql_dir/findings.json" || true
            fi
        done < "$gql_endpoints"
    fi

    # ------------------------------------------------------------------
    # 5. Field-level authorization test with gqlmap
    # ------------------------------------------------------------------
    if [ -f "$gql_endpoints" ] && [ -s "$gql_endpoints" ] && tool_available "gqlmap"; then
        log "INFO" "Running gqlmap for field-level auth testing..."
        while IFS= read -r gql_url; do
            [ -z "$gql_url" ] && continue
            gqlmap -u "$gql_url" --introspect \
                -o "$gql_dir/gqlmap_$(echo "$gql_url" | md5sum | cut -d' ' -f1).txt" \
                2>>"$LOGS_DIR/gqlmap.log" || true
        done < "$gql_endpoints"
    fi

    # ------------------------------------------------------------------
    # 6. Summary count
    # ------------------------------------------------------------------
    local vuln_count
    vuln_count=$(wc -l < "$graphql_vulns" 2>/dev/null || echo 0)
    log "INFO" "GraphQL abuse testing complete: $vuln_count issues found"

    py_log "INFO" "graphql_abuse_phase complete" --phase "graphql_abuse" --target "$domain" --extra "{\"vulns\":$vuln_count}" || true
    echo "$vuln_count" > "$gql_dir/count.txt"
}

export -f graphql_abuse_phase
