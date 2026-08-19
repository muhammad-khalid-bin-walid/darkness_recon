#!/usr/bin/env bash
# Crawl Tuning Phase - Autonomous crawl depth and scope configuration
set -euo pipefail

crawl_tuning_phase() {
    local domain="$1"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/crawl_tuning"
    mkdir -p "$phase_dir"

    log "INFO" "[crawl_tuning] Starting crawl tuning analysis for $domain"
    py_log "phase_start" "crawl_tuning" "$domain"

    local count=0

    # Discover site structure via robots.txt and sitemap
    log "INFO" "[crawl_tuning] Analyzing robots.txt"
    curl -sL "https://${domain}/robots.txt" 2>/dev/null > "$phase_dir/robots.txt" || true

    log "INFO" "[crawl_tuning] Analyzing sitemap"
    curl -sL "https://${domain}/sitemap.xml" 2>/dev/null > "$phase_dir/sitemap.xml" || true
    curl -sL "https://${domain}/sitemap_index.xml" 2>/dev/null >> "$phase_dir/sitemap.xml" || true

    # Analyze redirect chains from common paths
    log "INFO" "[crawl_tuning] Analyzing redirect chains"
    local paths=("/" "/index.html" "/index.php" "/home" "/login" "/admin" "/api" "/wp-admin" "/wp-login.php")
    for path in "${paths[@]}"; do
        local url="https://${domain}${path}"
        local redirect_chain
        redirect_chain=$(curl -sLI -o /dev/null -w '%{url_effective}\n%{http_code}\n%{redirect_url}\n' \
            "$url" 2>/dev/null || true)
        echo "Path: $path" >> "$phase_dir/redirect_chains.txt"
        echo "$redirect_chain" >> "$phase_dir/redirect_chains.txt"
        echo "---" >> "$phase_dir/redirect_chains.txt"
    done

    # Detect content types from response headers
    log "INFO" "[crawl_tuning] Detecting content types"
    for path in "/" "/api" "/feed" "/rss" "/json" "/graphql"; do
        local content_type
        content_type=$(curl -sI "https://${domain}${path}" 2>/dev/null \
            | grep -i content-type | head -1)
        if [[ -n "$content_type" ]]; then
            echo "${path}: ${content_type}" >> "$phase_dir/content_types.txt"
        fi
    done

    # Analyze JavaScript-heavy pages for SPA detection
    log "INFO" "[crawl_tuning] Detecting SPA patterns"
    local main_page
    main_page=$(curl -sL "https://${domain}" 2>/dev/null || true)

    local spa_score=0
    echo "$main_page" | grep -qiE '(react|angular|vue|__NEXT_DATA__|_app\.js|bundle\.js)' && ((spa_score++))
    echo "$main_page" | grep -qiE '(data-reactroot|ng-app|v-cloak)' && ((spa_score++))
    echo "$main_page" | grep -qiE '(history\.pushState|react-router|angular-router)' && ((spa_score++))

    if [[ $spa_score -ge 2 ]]; then
        log "INFO" "[crawl_tuning] SPA detected (score: $spa_score)"
    fi

    # Estimate optimal crawl depth
    local link_count
    link_count=$(echo "$main_page" | grep -oP 'href="[^"]*"' 2>/dev/null | wc -l || echo 0)
    local recommended_depth=3
    [[ $link_count -gt 100 ]] && recommended_depth=4
    [[ $link_count -gt 500 ]] && recommended_depth=5
    [[ $spa_score -ge 2 ]] && ((recommended_depth++))

    # Write crawl configuration
    python3 -c "
import json
config = {
    'domain': '$domain',
    'spa_detected': $spa_score >= 2,
    'spa_score': $spa_score,
    'link_count': $link_count,
    'recommended_depth': $recommended_depth,
    'respect_robots': True,
    'max_concurrency': 5,
    'delay_between_requests': 1.0,
    'content_types': ['text/html', 'application/json', 'application/xml'],
    'exclude_patterns': ['/wp-admin/*', '/login', '/logout', '/api/*'],
    'scope': {
        'same_domain': True,
        'include_subdomains': False,
        'max_redirects': 5
    }
}
print(json.dumps(config, indent=2))
" > "$phase_dir/crawl_config.json" 2>/dev/null

    # Count redirect chains discovered
    count=$(grep -c "^Path:" "$phase_dir/redirect_chains.txt" 2>/dev/null || echo 0)
    echo "$count" > "$phase_dir/count.txt"

    write_finding "$domain" "crawl_tuning" "info" \
        "Crawl config generated: depth=$recommended_depth, SPA=$([ $spa_score -ge 2 ] && echo yes || echo no)" || true

    log "INFO" "[crawl_tuning] Complete: recommended depth=$recommended_depth"
    py_log "phase_complete" "crawl_tuning" "$domain" "depth=$recommended_depth spa=$spa_score"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    crawl_tuning_phase "${1:?Usage: crawl_tuning_phase <domain>}"
fi
