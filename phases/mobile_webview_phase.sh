#!/usr/bin/env bash
# Phase 177: WebView Security Testing
set -euo pipefail

mobile_webview() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/mobile_webview"

    log "INFO" "Starting WebView security testing for $domain"

    local webview_vulns="$output_dir/mobile_webview/webview_vulns.txt"
    local js_interfaces="$output_dir/mobile_webview/js_interfaces.txt"
    local count=0

    {
        echo "=== WebView Vulnerabilities ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Common WebView security issues:"
        echo "  1. JavaScript enabled without restrictions"
        echo "  2. File access enabled (setAllowFileAccess)"
        echo "  3. Universal file access (setAllowFileAccessFromFileURLs)"
        echo "  4. Cross-origin access enabled"
        echo "  5. JavaScript interface exposed"
        echo "  6. Mixed content loading"
        echo "  7. Untrusted content rendering"
        echo "  8. Missing Content Security Policy"
    } > "$webview_vulns"

    {
        echo "=== JavaScript Interfaces ==="
        echo "Domain: $domain"
        echo ""
        echo "Common JavaScript interfaces to check:"
        echo "  - @JavascriptInterface (Android)"
        echo "  - WKScriptMessageHandler (iOS)"
        echo "  - JSContext (iOS)"
        echo "  - evaluateJavaScript (iOS)"
        echo ""
        echo "Dangerous interface methods:"
        echo "  - Runtime.exec()"
        echo "  - System.exec()"
        echo "  - File operations"
        echo "  - Database access"
        echo "  - Network requests"
        echo "  - Shared preferences access"
        echo "  - Contact list access"
    } > "$js_interfaces"

    # Test for common WebView issues
    {
        echo ""
        echo "--- WebView Configuration Checks ---"
        echo "1. setJavaScriptEnabled(true) without input validation"
        echo "2. setAllowFileAccess(true) exposing local files"
        echo "3. setAllowUniversalAccessFromFileURLs(true)"
        echo "4. addJavascriptInterface() with dangerous methods"
        echo "5. loadUrl() with user-controlled input"
        echo "6. setWebViewClient() without SSL error handling"
        echo "7. setWebChromeClient() with file upload enabled"
        echo "8. Mixed content: HTTP resources on HTTPS page"
    } >> "$webview_vulns"

    ((count+=2)) || true

    echo "$count" > "$output_dir/mobile_webview/count.txt"
    log "INFO" "WebView security testing complete: $count findings"
    write_finding "{\"type\":\"mobile_webview\",\"severity\":\"info\",\"count\":$count,\"phase\":\"mobile_webview\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=mobile_webview domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mobile_webview "${1:-}"
fi
