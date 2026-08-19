#!/usr/bin/env bash
# Phase 172: Mobile API Mapping
set -euo pipefail

mobile_api_map() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/mobile_api_map"

    log "INFO" "Starting mobile API mapping for $domain"

    local mobile_api_endpoints="$output_dir/mobile_api_map/mobile_api_endpoints.txt"
    local api_map="$output_dir/mobile_api_map/api_map.txt"
    local count=0

    {
        echo "=== Mobile API Endpoints ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
    } > "$mobile_api_endpoints"

    # Common mobile API patterns
    local api_patterns=(
        "/api/v1/"
        "/api/v2/"
        "/graphql"
        "/rest/"
        "/mobile/"
        "/app/"
        "/auth/"
        "/login"
        "/register"
        "/user/"
        "/account/"
        "/config/"
        "/settings/"
    )

    for pattern in "${api_patterns[@]}"; do
        local url="https://$domain$pattern"
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
        if [[ "$http_code" =~ ^(200|301|302|401|403)$ ]]; then
            echo "[API] $url (HTTP $http_code)" >> "$mobile_api_endpoints"
            ((count++)) || true
        fi
    done

    # API mapping
    {
        echo "=== API Map ==="
        echo "Discovered API endpoints and their methods:"
        echo ""
        echo "Endpoint Pattern Analysis:"
        echo "  - RESTful: /api/{version}/{resource}"
        echo "  - GraphQL: /graphql (POST)"
        echo "  - RPC: /api/{service}/{method}"
        echo ""
        echo "Common mobile API headers:"
        echo "  X-Api-Key"
        echo "  Authorization: Bearer {token}"
        echo "  X-Device-Id"
        echo "  X-App-Version"
        echo "  X-Platform"
    } > "$api_map"

    echo "$count" > "$output_dir/mobile_api_map/count.txt"
    log "INFO" "Mobile API mapping complete: $count findings"
    write_finding "{\"type\":\"mobile_api_map\",\"severity\":\"info\",\"count\":$count,\"phase\":\"mobile_api_map\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=mobile_api_map domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mobile_api_map "${1:-}"
fi
