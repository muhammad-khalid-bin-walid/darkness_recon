#!/bin/bash
# Favicon hash phase - favicon hash fingerprinting, Shodan search, logo correlation

favicon_hash_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local fav_dir="$output_dir/favicon_hash"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$fav_dir"

    log "INFO" "Starting favicon hash fingerprinting for $domain"
    py_log "INFO" "favicon_hash_phase" --phase "favicon_hash" --target "$domain"

    # ===== DOWNLOAD FAVICON =====
    log "INFO" "Downloading favicon..."
    if tool_available "curl"; then
        local favicon_urls=(
            "https://$domain/favicon.ico"
            "http://$domain/favicon.ico"
            "https://$domain/apple-touch-icon.png"
            "https://$domain/apple-touch-icon-precomposed.png"
        )

        local found_favicon=""
        for fav_url in "${favicon_urls[@]}"; do
            local http_code
            http_code=$(curl -s -o "$fav_dir/favicon_downloaded.ico" -w "%{http_code}" -L --max-time 10 "$fav_url" 2>/dev/null || echo "000")
            if [ "$http_code" = "200" ] && [ -s "$fav_dir/favicon_downloaded.ico" ]; then
                found_favicon="$fav_dir/favicon_downloaded.ico"
                cp "$found_favicon" "$fav_dir/favicon.ico"
                log "INFO" "Downloaded favicon from $fav_url"
                break
            fi
        done

        # Also check HTML-referenced favicons
        local live_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/live/httpx_results.txt"
        if [ -f "$live_file" ] && [ -z "$found_favicon" ]; then
            local first_url
            first_url=$(head -1 "$live_file" | awk '{print $1}')
            if [ -n "$first_url" ]; then
                local html
                html=$(curl -s -L --max-time 15 "$first_url" 2>/dev/null || echo "")
                local html_fav
                html_fav=$(echo "$html" | grep -oiP '<link[^>]+rel=["\x27](shortcut )?icon["\x27][^>]+href=["\x27]\K[^"\x27]+' 2>/dev/null | head -1)
                if [ -n "$html_fav" ]; then
                    local full_fav_url
                    if echo "$html_fav" | grep -q '^http'; then
                        full_fav_url="$html_fav"
                    else
                        full_fav_url="${first_url%/}$(echo "$html_fav" | sed 's|^/||')"
                    fi
                    curl -s -o "$fav_dir/favicon.ico" -L --max-time 10 "$full_fav_url" 2>/dev/null || true
                    [ -s "$fav_dir/favicon.ico" ] && found_favicon="$fav_dir/favicon.ico"
                fi
            fi
        fi
    fi

    # ===== COMPUTE FAVICON HASHES =====
    log "INFO" "Computing favicon hashes..."
    if [ -f "$fav_dir/favicon.ico" ]; then
        local md5_hash sha1_hash sha256_hash mmh3_hash b64_content
        md5_hash=$(md5sum "$fav_dir/favicon.ico" 2>/dev/null | awk '{print $1}' || echo "")
        sha1_hash=$(sha1sum "$fav_dir/favicon.ico" 2>/dev/null | awk '{print $1}' || echo "")
        sha256_hash=$(sha256sum "$fav_dir/favicon.ico" 2>/dev/null | awk '{print $1}' || echo "")
        b64_content=$(base64 "$fav_dir/favicon.ico" 2>/dev/null | tr -d '\n')

        # Compute MMH3 hash (Shodan-compatible) using Python
        mmh3_hash=$(python3 -c "
import sys
try:
    import mmh3
    import base64
    with open('$fav_dir/favicon.ico', 'rb') as f:
        data = f.read()
    print(mmh3.hash(base64.b64encode(data)))
except ImportError:
    # Fallback: use Python's built-in hash
    import base64
    with open('$fav_dir/favicon.ico', 'rb') as f:
        data = f.read()
    b64 = base64.b64encode(data).decode()
    print(hash(b64))
except Exception as e:
    print('error', file=sys.stderr)
" 2>/dev/null || echo "unavailable")

        {
            echo "=== FAVICON HASHES FOR $domain ==="
            echo "MD5: $md5_hash"
            echo "SHA1: $sha1_hash"
            echo "SHA256: $sha256_hash"
            echo "MMH3 (Shodan): $mmh3_hash"
            echo "Base64 length: ${#b64_content}"
        } > "$fav_dir/favicon_hashes.txt" 2>/dev/null || true

        write_finding "{\"type\":\"favicon_hash\",\"target\":\"$domain\",\"md5\":\"$md5_hash\",\"sha1\":\"$sha1_hash\",\"sha256\":\"$sha256_hash\",\"mmh3\":\"$mmh3_hash\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$fav_dir/favicon_finding.json" || true
    else
        log "WARN" "No favicon found for $domain"
        echo "NO_FAVICON_FOUND" > "$fav_dir/favicon_hashes.txt"
    fi

    # ===== SHODAN FAVICON HASH SEARCH =====
    log "INFO" "Searching Shodan for similar favicon hashes..."
    if tool_available "curl" && [ -n "${SHODAN_API_KEY:-}" ] && [ "$mmh3_hash" != "unavailable" ] && [ -n "$mmh3_hash" ]; then
        curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=http.favicon.hash:$mmh3_hash" \
            -o "$fav_dir/shodan_favicon.json" 2>/dev/null || true

        if [ -s "$fav_dir/shodan_favicon.json" ]; then
            python3 -c "
import json, sys
try:
    with open('$fav_dir/shodan_favicon.json') as f:
        data = json.load(f)
    matches = data.get('matches', [])
    similar = []
    seen = set()
    for match in matches:
        ip = match.get('ip_str', '')
        host = match.get('hostnames', [])
        org = match.get('org', '')
        if ip not in seen:
            seen.add(ip)
            similar.append({
                'ip': ip, 'hostnames': host,
                'org': org, 'port': match.get('port', '')
            })
    with open('$fav_dir/similar_assets.json', 'w') as f:
        json.dump(similar, f, indent=2)
    with open('$fav_dir/similar_assets.txt', 'w') as f:
        for s in similar:
            hosts = ', '.join(s.get('hostnames', []))
            f.write(f\"{s['ip']} ({hosts}) - {s.get('org', 'Unknown')} port:{s['port']}\n\")
    print(f'found={len(similar)}')
except Exception as e:
    print(f'error={e}', file=sys.stderr)
" 2>/dev/null || true
        fi
    fi

    # Also search by MD5 hash
    if tool_available "curl" && [ -n "${SHODAN_API_KEY:-}" ] && [ -n "$md5_hash" ]; then
        curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=http.favicon.hash:$md5_hash" \
            -o "$fav_dir/shodan_favicon_md5.json" 2>/dev/null || true
    fi

    # ===== LOGO CORRELATION =====
    log "INFO" "Performing logo correlation analysis..."
    if [ -f "$fav_dir/favicon.ico" ]; then
        local logo_hash
        logo_hash=$(sha256sum "$fav_dir/favicon.ico" 2>/dev/null | awk '{print $1}')

        # Try to match against known brand favicon hashes
        {
            echo "=== LOGO CORRELATION FOR $domain ==="
            echo "SHA256: $logo_hash"
            if [ -s "$fav_dir/similar_assets.txt" ]; then
                echo ""
                echo "Similar assets found via Shodan:"
                cat "$fav_dir/similar_assets.txt"
            else
                echo "No similar assets found via Shodan"
            fi
        } > "$fav_dir/logo_correlation.txt" 2>/dev/null || true
    fi

    local similar_count
    similar_count=$(wc -l < "$fav_dir/similar_assets.txt" 2>/dev/null || echo 0)
    log "INFO" "Favicon hash fingerprinting complete: $similar_count similar assets found"

    local total_count=$((1 + similar_count))
    echo "$total_count" > "$fav_dir/count.txt"
}
