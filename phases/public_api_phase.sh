#!/usr/bin/env bash
# Track 8: Reporting & Integration - Public API Phase
# Public API for findings access, REST/GraphQL endpoints, authentication

public_api_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        echo "Usage: public_api_phase <domain>"
        return 1
    fi

    # Source core.sh if not already sourced
    if ! declare -F log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    # Set up output directory
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/public_api"

    log "INFO" "Starting public API phase for $domain"

    # Check for required tools
    if ! tool_available "python3"; then
        log "ERROR" "python3 is required for public API phase"
        return 1
    fi

    # Initialize outputs
    local api_config="$output_dir/public_api/api_config.json"
    local api_endpoints="$output_dir/public_api/api_endpoints.txt"

    # Create API config
    cat > "$api_config" <<EOF
{
  "domain": "$domain",
  "timestamp": "$TIMESTAMP",
  "api_version": "v1",
  "base_url": "https://api.darkrecon.local/v1",
  "authentication": {
    "type": "bearer",
    "token_header": "Authorization",
    "token_prefix": "Bearer",
    "api_key_header": "X-API-Key",
    "rate_limiting": {
      "enabled": true,
      "requests_per_minute": 60,
      "burst_limit": 10
    }
  },
  "endpoints": {
    "findings": {
      "list": "GET /findings",
      "get": "GET /findings/{id}",
      "create": "POST /findings",
      "update": "PUT /findings/{id}",
      "delete": "DELETE /findings/{id}",
      "search": "GET /findings/search?q={query}"
    },
    "assets": {
      "list": "GET /assets",
      "get": "GET /assets/{id}",
      "create": "POST /assets",
      "update": "PUT /assets/{id}",
      "delete": "DELETE /assets/{id}"
    },
    "endpoints_api": {
      "list": "GET /endpoints",
      "get": "GET /endpoints/{id}",
      "create": "POST /endpoints"
    },
    "reports": {
      "generate": "POST /reports/generate",
      "download": "GET /reports/{id}/download",
      "list": "GET /reports"
    },
    "statistics": {
      "summary": "GET /stats/summary",
      "trends": "GET /stats/trends",
      "severity": "GET /stats/severity"
    }
  },
  "graphql": {
    "enabled": true,
    "endpoint": "/graphql",
    "playground": "/graphql/playground",
    "schema_file": "schema.graphql"
  },
  "cors": {
    "enabled": false,
    "allowed_origins": [],
    "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
    "allowed_headers": ["Authorization", "Content-Type"]
  },
  "documentation": {
    "openapi": "/docs/openapi.json",
    "swagger_ui": "/docs/swagger",
    "redoc": "/docs/redoc"
  }
}
EOF

    # Create API endpoints file
    cat > "$api_endpoints" <<EOF
API Endpoints for $domain
=========================
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

Base URL: https://api.darkrecon.local/v1

REST Endpoints:
- GET    /findings              - List all findings
- GET    /findings/{id}         - Get specific finding
- POST   /findings              - Create new finding
- PUT    /findings/{id}         - Update finding
- DELETE /findings/{id}         - Delete finding
- GET    /findings/search?q=    - Search findings

- GET    /assets                - List all assets
- GET    /assets/{id}           - Get specific asset
- POST   /assets                - Create new asset
- PUT    /assets/{id}           - Update asset
- DELETE /assets/{id}           - Delete asset

- GET    /endpoints             - List all endpoints
- GET    /endpoints/{id}        - Get specific endpoint
- POST   /endpoints             - Create new endpoint

- POST   /reports/generate      - Generate report
- GET    /reports/{id}/download - Download report
- GET    /reports               - List reports

- GET    /stats/summary         - Get statistics summary
- GET    /stats/trends          - Get trend data
- GET    /stats/severity        - Get severity breakdown

GraphQL:
- POST   /graphql               - GraphQL endpoint
- GET    /graphql/playground    - GraphQL Playground
- GET    /docs/openapi.json     - OpenAPI specification

Authentication: Bearer Token or API Key
Rate Limit: 60 requests/minute
EOF

    # Validate outputs
    if [[ -f "$api_config" ]]; then
        log "INFO" "API config created successfully"
        write_finding "$domain" "PUBLIC_API" "API system configured" "info" "$output_dir/public_api"
    else
        log "ERROR" "Failed to create API config"
    fi

    if [[ -f "$api_endpoints" ]]; then
        log "INFO" "API endpoints file created"
        write_asset "$domain" "API_ENDPOINTS" "API endpoint documentation" "$output_dir/public_api"
    fi

    # Structured logging
    py_log "INFO" "public_api" "Phase completed" \
        "domain=$domain" \
        "output_dir=$output_dir/public_api" \
        "api_config=$api_config" \
        "api_endpoints=$api_endpoints"

    # Count results
    local result_count=2
    echo "$result_count" > "$output_dir/public_api/count.txt"

    log "INFO" "Public API phase completed for $domain"
    return 0
}