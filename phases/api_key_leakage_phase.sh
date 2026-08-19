#!/usr/bin/env bash
# api_key_leakage_phase.sh - API key/token leakage detection in client-side bundles,
# JavaScript source analysis, HAR file analysis.

api_key_leakage_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "api_key_leakage_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/api_key_leakage"

    local results=0
    local leaked_file="$output_dir/api_key_leakage/leaked_keys.txt"
    local exposure_file="$output_dir/api_key_leakage/key_exposure.txt"

    log "INFO" "Starting API key leakage analysis for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # Collect JavaScript sources from main domain
    local js_urls=()
    local main_page
    main_page=$(curl -s -m 15 "https://$domain" 2>/dev/null || true)

    if [[ -n "$main_page" ]]; then
        # Extract JS file URLs
        while IFS= read -r url; do
            js_urls+=("$url")
        done < <(echo "$main_page" | grep -oE '(src|href)="[^"]*\.js[^"]*"' | \
            sed 's/.*="\(.*\)"/\1/' | head -30 2>/dev/null || true)

        # Extract inline script content
        local inline_scripts
        inline_scripts=$(echo "$main_page" | grep -oP '(?<=<script[^>]*>)[^<]+' || true)

        # Check for API keys in inline scripts
        if [[ -n "$inline_scripts" ]]; then
            # Common API key patterns
            local key_patterns=(
                'api[_-]?key\s*[:=]\s*["\x27][A-Za-z0-9_\-]{20,}["\x27]'
                'apikey\s*[:=]\s*["\x27][A-Za-z0-9_\-]{20,}["\x27]'
                'secret[_-]?key\s*[:=]\s*["\x27][A-Za-z0-9_\-]{20,}["\x27]'
                'access[_-]?token\s*[:=]\s*["\x27][A-Za-z0-9_\-]{20,}["\x27]'
                'auth[_-]?token\s*[:=]\s*["\x27][A-Za-z0-9_\-]{20,}["\x27]'
                'bearer\s+[A-Za-z0-9_\-\.]{20,}'
                'ghp_[A-Za-z0-9]{36}'
                'sk-[A-Za-z0-9]{32,}'
                'AIza[A-Za-z0-9_\-]{35}'
                'AKIA[A-Z0-9]{16}'
                'eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*'
            )

            for pattern in "${key_patterns[@]}"; do
                local matches
                matches=$(echo "$inline_scripts" | grep -oiE "$pattern" 2>/dev/null || true)
                if [[ -n "$matches" ]]; then
                    echo "[INLINE-KEY] $domain - Pattern matched:" >> "$leaked_file"
                    echo "$matches" >> "$leaked_file"
                    echo "---" >> "$leaked_file"
                    ((results++)) || true
                fi
            done
        fi

        # Check for meta tags with keys
        local meta_keys
        meta_keys=$(echo "$main_page" | grep -iE '(api[_-]?key|token|secret|auth)' || true)
        if [[ -n "$meta_keys" ]]; then
            echo "[META-KEY] $domain - Potential key in meta tags:" >> "$leaked_file"
            echo "$meta_keys" >> "$leaked_file"
            echo "---" >> "$leaked_file"
            ((results++)) || true
        fi
    fi

    # Download and analyze JS bundles
    log "INFO" "Analyzing ${#js_urls[@]} JavaScript files"
    local temp_dir
    temp_dir=$(mktemp -d)

    for js_url in "${js_urls[@]}"; do
        # Normalize relative URLs
        if [[ "$js_url" != http* ]]; then
            if [[ "$js_url" == //* ]]; then
                js_url="https:${js_url}"
            elif [[ "$js_url" == /* ]]; then
                js_url="https://${domain}${js_url}"
            else
                js_url="https://${domain}/${js_url}"
            fi
        fi

        local js_file="$temp_dir/$(echo "$js_url" | md5sum | cut -d' ' -f1).js"
        curl -s -m 15 -o "$js_file" "$js_url" 2>/dev/null || continue

        if [[ ! -s "$js_file" ]]; then
            continue
        fi

        local js_size
        js_size=$(wc -c < "$js_file" 2>/dev/null || echo "0")
        log "INFO" "Analyzing $(basename "$js_url") ($js_size bytes)"

        # Search for hardcoded API keys
        local found_keys
        found_keys=$(grep -oiE '(api[_-]?key|apikey|secret|token|password|auth|credential|private[_-]?key)\s*[:=]\s*["\x27][A-Za-z0-9_\-\.\/\:]{10,}["\x27]' "$js_file" 2>/dev/null || true)

        if [[ -n "$found_keys" ]]; then
            echo "[JS-KEY] $js_url:" >> "$leaked_file"
            echo "$found_keys" >> "$leaked_file"
            echo "---" >> "$leaked_file"
            ((results++)) || true
        fi

        # Check for AWS keys
        local aws_keys
        aws_keys=$(grep -oE 'AKIA[0-9A-Z]{16}' "$js_file" 2>/dev/null || true)
        if [[ -n "$aws_keys" ]]; then
            echo "[AWS-KEY] $js_url - AWS Access Key found:" >> "$leaked_file"
            echo "$aws_keys" >> "$leaked_file"
            echo "---" >> "$leaked_file"
            ((results++)) || true
        fi

        # Check for GCP keys
        local gcp_keys
        gcp_keys=$(grep -oE 'AIza[A-Za-z0-9_\-]{35}' "$js_file" 2>/dev/null || true)
        if [[ -n "$gcp_keys" ]]; then
            echo "[GCP-KEY] $js_url - GCP API Key found:" >> "$leaked_file"
            echo "$gcp_keys" >> "$leaked_file"
            echo "---" >> "$leaked_file"
            ((results++)) || true
        fi

        # Check for GitHub tokens
        local gh_tokens
        gh_tokens=$(grep -oE '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}' "$js_file" 2>/dev/null || true)
        if [[ -n "$gh_tokens" ]]; then
            echo "[GH-TOKEN] $js_url - GitHub token found:" >> "$leaked_file"
            echo "$gh_tokens" >> "$leaked_file"
            echo "---" >> "$leaked_file"
            ((results++)) || true
        fi

        # Check for Stripe keys
        local stripe_keys
        stripe_keys=$(grep -oE '(sk|pk)_(test|live)_[A-Za-z0-9]{24,}' "$js_file" 2>/dev/null || true)
        if [[ -n "$stripe_keys" ]]; then
            echo "[STRIPE-KEY] $js_url - Stripe key found:" >> "$leaked_file"
            echo "$stripe_keys" >> "$leaked_file"
            echo "---" >> "$leaked_file"
            ((results++)) || true
        fi

        # Check for JWT tokens in source
        local jwts
        jwts=$(grep -oE 'eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*' "$js_file" 2>/dev/null || true)
        if [[ -n "$jwts" ]]; then
            echo "[JWT-EXPOSED] $js_url - JWT token in source:" >> "$leaked_file"
            echo "$jwts" | head -5 >> "$leaked_file"
            echo "---" >> "$leaked_file"
            ((results++)) || true
        fi

        # Check for base64 encoded secrets
        local base64_secrets
        base64_secrets=$(grep -oE '[A-Za-z0-9+/]{40,}={0,2}' "$js_file" 2>/dev/null | while read -r b64; do
            local decoded
            decoded=$(echo "$b64" | base64 -d 2>/dev/null || true)
            if echo "$decoded" | grep -qiE '(key|secret|token|password|api)'; then
                echo "$b64"
            fi
        done || true)

        if [[ -n "$base64_secrets" ]]; then
            echo "[B64-SECRET] $js_url - Base64 encoded secret:" >> "$leaked_file"
            echo "$base64_secrets" | head -3 >> "$leaked_file"
            echo "---" >> "$leaked_file"
            ((results++)) || true
        fi

        # Check for exposed internal URLs/endpoints
        local internal_urls
        internal_urls=$(grep -oE 'https?://[a-z0-9._\-]+:(\d+|/[a-z0-9/_\-]+)' "$js_file" 2>/dev/null | \
            grep -v "localhost" | grep -v "127.0.0.1" | sort -u || true)
        if [[ -n "$internal_urls" ]]; then
            echo "[INTERNAL-URL] $js_url - Exposed internal URLs:" >> "$exposure_file"
            echo "$internal_urls" | head -10 >> "$exposure_file"
            echo "---" >> "$exposure_file"
            ((results++)) || true
        fi

        # Check for source maps
        local source_map_url="${js_url}.map"
        local sm_status
        sm_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$source_map_url" 2>/dev/null || echo "000")
        if [[ "$sm_status" == "200" ]]; then
            echo "[SOURCE-MAP] $source_map_url - Source map accessible" >> "$exposure_file"
            ((results++)) || true
        fi
    done

    # Check common paths for HAR files and debug endpoints
    local debug_paths=(
        "/.well-known/openid-configuration"
        "/debug/vars"
        "/debug/pprof/"
        "/actuator"
        "/actuator/env"
        "/actuator/configprops"
        "/swagger-ui.html"
        "/api/swagger"
        "/.env"
        "/config.json"
        "/.git/config"
        "/wp-config.php.bak"
        "/composer.json"
        "/package.json"
        "/.DS_Store"
    )

    for dpath in "${debug_paths[@]}"; do
        local d_status
        d_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://${domain}${dpath}" 2>/dev/null || echo "000")
        if [[ "$d_status" == "200" ]]; then
            echo "[DEBUG-ENDPOINT] https://${domain}${dpath} - Accessible (HTTP 200)" >> "$exposure_file"
            ((results++)) || true
        fi
    done

    # Cleanup
    rm -rf "$temp_dir" 2>/dev/null || true

    # Write count
    echo "$results" > "$output_dir/api_key_leakage/count.txt"

    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "api_key_leakage" "CRITICAL" "$line" 2>/dev/null || true
        done < "$leaked_file" 2>/dev/null || true
    fi

    py_log "INFO" "api_key_leakage_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "API key leakage phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    api_key_leakage_phase "$@"
fi
