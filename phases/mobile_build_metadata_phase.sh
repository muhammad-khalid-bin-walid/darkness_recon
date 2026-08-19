#!/usr/bin/env bash
# Phase 178: Build Metadata Analysis
set -euo pipefail

mobile_build_metadata() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/mobile_build_metadata"

    log "INFO" "Starting build metadata analysis for $domain"

    local build_metadata="$output_dir/mobile_build_metadata/build_metadata.txt"
    local debug_flags="$output_dir/mobile_build_metadata/debug_flags.txt"
    local count=0

    {
        echo "=== Build Metadata Analysis ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Build metadata to analyze:"
        echo "  1. Build version numbers"
        echo "  2. Build timestamps"
        echo "  3. Build environment (debug/release)"
        echo "  4. Compiler flags"
        echo "  5. Signing certificates"
        echo "  6. ProGuard/R8 configuration"
        echo "  7. Bundle size optimization"
        echo "  8. Asset packaging"
    } > "$build_metadata"

    {
        echo "=== Debug Flags ==="
        echo "Domain: $domain"
        echo ""
        echo "Debug-related flags to check:"
        echo "  Android:"
        echo "    - debuggable=true in AndroidManifest.xml"
        echo "    - android:debuggable attribute"
        echo "    - BuildConfig.DEBUG flag"
        echo "    - Log.d() statements in production"
        echo ""
        echo "  iOS:"
        echo "    - DEBUG preprocessor macro"
        echo "    - NSLOG statements"
        echo "    - isDebuggerAttached check"
        echo "    - Keychain accessibility settings"
        echo ""
        echo "Security implications of debug builds:"
        echo "  1. Exposed debugging interfaces"
        echo "  2. Verbose logging"
        echo "  3. Disabled optimizations"
        echo "  4. Weakened security checks"
        echo "  5. Backdoor access via ADB"
    } > "$debug_flags"

    # Check for common metadata exposure
    local metadata_paths=(
        "/app-info.json"
        "/config.json"
        "/build-info.json"
        "/version.json"
    )

    for path in "${metadata_paths[@]}"; do
        local url="https://$domain$path"
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
        if [[ "$http_code" == "200" ]]; then
            echo "[METADATA] $url exposed (HTTP $http_code)" >> "$build_metadata"
            ((count++)) || true
        fi
    done

    echo "$count" > "$output_dir/mobile_build_metadata/count.txt"
    log "INFO" "Build metadata analysis complete: $count findings"
    write_finding "{\"type\":\"mobile_build_metadata\",\"severity\":\"info\",\"count\":$count,\"phase\":\"mobile_build_metadata\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=mobile_build_metadata domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mobile_build_metadata "${1:-}"
fi
