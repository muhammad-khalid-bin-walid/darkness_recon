#!/usr/bin/env bash
# api_versioning_phase.sh - API versioning surface mapping, deprecated endpoint
# discovery, version bypass testing.

api_versioning_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "api_versioning_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/api_versioning"

    local results=0
    local versions_file="$output_dir/api_versioning/api_versions.txt"
    local deprecated_file="$output_dir/api_versioning/deprecated_endpoints.txt"

    log "INFO" "Starting API versioning analysis for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # Common API version patterns
    local version_prefixes=("/v1" "/v2" "/v3" "/v4" "/api/v1" "/api/v2" "/api/v3" "/api/v4" "/rest/v1" "/rest/v2")
    local api_base_paths=("/api" "/rest" "/graphql" "/endpoint" "/service")

    # Version header patterns
    local version_headers=(
        "Accept: application/vnd.api+json;version=1"
        "Accept: application/vnd.api+json;version=2"
        "X-API-Version: 1"
        "X-API-Version: 2"
        "Api-Version: 1"
        "Api-Version: 2"
    )

    # Test each API base path with version prefixes
    for base in "${api_base_paths[@]}"; do
        for vprefix in "${version_prefixes[@]}"; do
            local url="https://${domain}${vprefix}"
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")

            if [[ "$status" != "000" && "$status" != "404" && "$status" != "403" ]]; then
                echo "[VERSION-FOUND] $url - HTTP $status" >> "$versions_file"
                ((results++)) || true

                # Check response headers for version info
                local resp_headers
                resp_headers=$(curl -sI -m 10 "$url" 2>/dev/null || true)

                # Check for deprecated header
                local deprecated_header
                deprecated_header=$(echo "$resp_headers" | grep -iE "(deprecat|x-deprecated|x-api-deprecated)" || true)
                if [[ -n "$deprecated_header" ]]; then
                    echo "[DEPRECATED-HEADER] $url - $deprecated_header" >> "$deprecated_file"
                    ((results++)) || true
                fi

                # Check for Sunset header
                local sunset_header
                sunset_header=$(echo "$resp_headers" | grep -i "sunset" || true)
                if [[ -n "$sunset_header" ]]; then
                    echo "[SUNSET] $url - $sunset_header" >> "$deprecated_file"
                    ((results++)) || true
                fi
            fi
        done
    done

    # Test version header bypass
    log "INFO" "Testing version header bypass for $domain"
    local test_endpoints=("/api/users" "/api/health" "/api/config" "/api/me" "/api/status")

    for endpoint in "${test_endpoints[@]}"; do
        local base_url="https://${domain}${endpoint}"
        local base_status
        base_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$base_url" 2>/dev/null || echo "000")

        if [[ "$base_status" == "404" || "$base_status" == "000" ]]; then
            continue
        fi

        for header in "${version_headers[@]}"; do
            local hname
            hname=$(echo "$header" | cut -d: -f1 | xargs)
            local hval
            hval=$(echo "$header" | cut -d: -f2- | xargs)

            local bypass_status
            bypass_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -H "$header" "$base_url" 2>/dev/null || echo "000")

            if [[ "$bypass_status" != "$base_status" && "$bypass_status" != "000" && "$bypass_status" != "404" ]]; then
                echo "[VERSION-BYPASS] $endpoint via $hname: $hval -> HTTP $bypass_status (base: $base_status)" >> "$versions_file"
                ((results++)) || true
            fi
        done

        # Test path-based version override
        local path_bypasses=(
            "${endpoint}/../v1/"
            "${endpoint}?version=1"
            "${endpoint}?api_version=2"
            "${endpoint}#v1"
        )

        for pb in "${path_bypasses[@]}"; do
            local bypass_url="https://${domain}${pb}"
            local pb_status
            pb_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$bypass_url" 2>/dev/null || echo "000")

            if [[ "$pb_status" != "000" && "$pb_status" != "404" && "$pb_status" != "403" ]]; then
                echo "[VERSION-PATH-BYPASS] $pb -> HTTP $pb_status" >> "$versions_file"
                ((results++)) || true
            fi
        done
    done

    # Check for version-specific error messages
    for vprefix in "${version_prefixes[@]}"; do
        local err_url="https://${domain}${vprefix}/nonexistent-endpoint-test"
        local err_body
        err_body=$(curl -s -m 10 "$err_url" 2>/dev/null || true)
        local err_status
        err_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$err_url" 2>/dev/null || echo "000")

        if [[ -n "$err_body" && "$err_status" != "000" ]]; then
            local version_leak
            version_leak=$(echo "$err_body" | grep -ioE "(version|api.version|v[0-9]+)" || true)
            if [[ -n "$version_leak" ]]; then
                echo "[VERSION-LEAK] $vprefix - Error response leaks version info: $version_leak" >> "$versions_file"
                ((results++)) || true
            fi
        fi
    done

    # Write count
    echo "$results" > "$output_dir/api_versioning/count.txt"

    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "api_versioning" "LOW" "$line" 2>/dev/null || true
        done < "$deprecated_file" 2>/dev/null || true
    fi

    py_log "INFO" "api_versioning_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "API versioning phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    api_versioning_phase "$@"
fi
