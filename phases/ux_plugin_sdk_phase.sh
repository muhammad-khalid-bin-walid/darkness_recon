#!/usr/bin/env bash
# Phase 288: Plugin SDK, Extension Development, API Documentation
# Track 20 - UX/CLI

ux_plugin_sdk() {
    local domain="${1:?Usage: ux_plugin_sdk <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/ux_plugin_sdk"
    mkdir -p "$phase_dir"

    log "INFO" "[PLUGIN_SDK] Generating plugin SDK documentation for $domain"

    local plugin_sdk="$phase_dir/plugin_sdk.json"
    local sdk_docs="$phase_dir/sdk_docs.txt"

    local count=0

    cat > "$plugin_sdk" <<PSEOF
{
  "domain": "$domain",
  "timestamp": "$TIMESTAMP",
  "sdk": {
    "version": "1.0.0",
    "name": "DarkRecon Plugin SDK",
    "description": "SDK for extending DarkRecon with custom phases and integrations",
    "api": {
      "phase_interface": {
        "name": "string",
        "description": "string",
        "execute": "function(domain, config) -> findings[]",
        "validate": "function(config) -> boolean"
      },
      "hooks": {
        "pre_scan": "function(domain) -> domain",
        "post_scan": "function(findings) -> findings",
        "on_error": "function(error) -> void"
      },
      "output": {
        "write_finding": "function(phase_dir, id, description, severity, status)",
        "write_asset": "function(phase_dir, key, value, type)",
        "write_endpoint": "function(phase_dir, url, method, description)"
      }
    },
    "plugin_types": [
      "phase",
      "scanner",
      "analyzer",
      "reporter",
      "integration"
    ]
  }
}
PSEOF
    count=$((count + 1))

    log "INFO" "[PLUGIN_SDK] Generating SDK documentation"
    {
        echo "=== Plugin SDK Documentation ==="
        echo "Domain: $domain"
        echo "SDK Version: 1.0.0"
        echo ""
        echo "=== Plugin Interface ==="
        echo ""
        echo "Every plugin must implement:"
        echo "  - name: Plugin name (string)"
        echo "  - description: Plugin description (string)"
        echo "  - execute(domain, config): Main execution function"
        echo "  - validate(config): Configuration validation"
        echo ""
        echo "=== Available Hooks ==="
        echo ""
        echo "  pre_scan(domain): Modify domain before scanning"
        echo "  post_scan(findings): Modify findings after scanning"
        echo "  on_error(error): Handle errors gracefully"
        echo ""
        echo "=== Output Functions ==="
        echo ""
        echo "  write_finding(phase_dir, id, description, severity, status)"
        echo "  write_asset(phase_dir, key, value, type)"
        echo "  write_endpoint(phase_dir, url, method, description)"
        echo ""
        echo "=== Plugin Types ==="
        echo ""
        echo "  phase: Custom scanning phase"
        echo "  scanner: Service-specific scanner"
        echo "  analyzer: Results analyzer"
        echo "  reporter: Report generator"
        echo "  integration: Third-party integration"
        echo ""
        echo "=== Creating a Plugin ==="
        echo ""
        echo "  1. Create a .sh file in plugins/"
        echo "  2. Implement the phase interface"
        echo "  3. Register in plugin registry"
        echo "  4. Test with --dry-run"
    } > "$sdk_docs"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "PLUGIN_SDK" "Plugin SDK documentation generated" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "plugin_sdk_complete" "Plugin SDK complete: $count items"
    log "INFO" "[PLUGIN_SDK] Completed: $count items generated"

    return 0
}
