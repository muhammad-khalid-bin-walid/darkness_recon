#!/bin/bash
# Meta harvesting phase - robots.txt, sitemap.xml, security.txt, humans.txt, .well-known/

meta_harvest_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local meta_dir="$output_dir/meta_harvest"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$meta_dir"

    log "INFO" "Starting meta harvesting for $domain"
    py_log "INFO" "meta_harvest_phase" --phase "meta_harvest" --target "$domain"

    # ===== ROBOTS.TXT =====
    log "INFO" "Fetching robots.txt..."
    if tool_available "curl"; then
        curl -s -L -o "$meta_dir/robots.txt" "https://$domain/robots.txt" 2>/dev/null || true
        curl -s -L -o "$meta_dir/robots_http.txt" "http://$domain/robots.txt" 2>/dev/null || true

        if [ -s "$meta_dir/robots.txt" ] || [ -s "$meta_dir/robots_http.txt" ]; then
            local robots_file="$meta_dir/robots.txt"
            [ ! -s "$robots_file" ] && robots_file="$meta_dir/robots_http.txt"

            write_finding "{\"type\":\"meta_robots_txt\",\"target\":\"$domain\",\"url\":\"https://$domain/robots.txt\",\"status\":\"found\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$meta_dir/robots_finding.json" || true

            log "INFO" "Parsing robots.txt for disallowed paths..."
            grep -iE '^\s*(disallow|allow|sitemap|crawl-delay|user-agent)' "$robots_file" 2>/dev/null \
                | sed 's/^[[:space:]]*//' > "$meta_dir/robots_parsed.txt" || true

            # Extract disallowed paths
            grep -i '^\s*disallow' "$robots_file" 2>/dev/null \
                | sed 's/^disallow:\s*//i; s/^[[:space:]]*//' | grep -v '^$' \
                | sort -u > "$meta_dir/disallowed_paths.txt" || true
        else
            log "WARN" "robots.txt not found for $domain"
            echo "NOT_FOUND" > "$meta_dir/disallowed_paths.txt"
        fi
    fi

    # ===== SITEMAP.XML =====
    log "INFO" "Fetching sitemap.xml..."
    if tool_available "curl"; then
        local sitemap_urls=(
            "https://$domain/sitemap.xml"
            "https://$domain/sitemap_index.xml"
            "https://$domain/sitemap-index.xml"
            "https://$domain/post-sitemap.xml"
            "https://$domain/page-sitemap.xml"
        )
        local sitemap_count=0
        for surl in "${sitemap_urls[@]}"; do
            local sitemap_file="$meta_dir/sitemap_$(echo "$surl" | md5sum | awk '{print $1}').xml"
            curl -s -L -o "$sitemap_file" "$surl" 2>/dev/null || true
            if [ -s "$sitemap_file" ] && grep -q '<urlset\|<sitemapindex' "$sitemap_file" 2>/dev/null; then
                sitemap_count=$((sitemap_count + 1))
                write_endpoint "{\"type\":\"sitemap\",\"url\":\"$surl\",\"status\":\"found\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$meta_dir/sitemap_finding_${sitemap_count}.json" || true
            else
                rm -f "$sitemap_file" 2>/dev/null || true
            fi
        done
        log "INFO" "Found $sitemap_count sitemap(s)"
    fi

    # ===== SECURITY.TXT =====
    log "INFO" "Fetching security.txt..."
    if tool_available "curl"; then
        local security_urls=(
            "https://$domain/.well-known/security.txt"
            "https://$domain/security.txt"
        )
        for securl in "${security_urls[@]}"; do
            curl -s -L -o "$meta_dir/security_candidate.txt" "$securl" 2>/dev/null || true
            if [ -s "$meta_dir/security_candidate.txt" ]; then
                cp "$meta_dir/security_candidate.txt" "$meta_dir/security_contact.txt"
                grep -iE '^(contact|expires|policy|acknowledgments|preferred-languages|canonical)' \
                    "$meta_dir/security_contact.txt" 2>/dev/null > "$meta_dir/security_parsed.txt" || true

                write_finding "{\"type\":\"security_txt\",\"target\":\"$domain\",\"url\":\"$securl\",\"status\":\"found\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$meta_dir/security_txt_finding.json" || true
                break
            fi
        done
        [ ! -f "$meta_dir/security_contact.txt" ] && echo "NOT_FOUND" > "$meta_dir/security_contact.txt"
    fi

    # ===== HUMANS.TXT =====
    log "INFO" "Fetching humans.txt..."
    if tool_available "curl"; then
        curl -s -L -o "$meta_dir/humans.txt" "https://$domain/humans.txt" 2>/dev/null || true
        curl -s -L -o "$meta_dir/humans_http.txt" "http://$domain/humans.txt" 2>/dev/null || true

        if [ -s "$meta_dir/humans.txt" ] || [ -s "$meta_dir/humans_http.txt" ]; then
            write_finding "{\"type\":\"humans_txt\",\"target\":\"$domain\",\"status\":\"found\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$meta_dir/humans_finding.json" || true
        fi
    fi

    # ===== .WELL-KNOWN/ ENUMERATION =====
    log "INFO" "Enumerating .well-known/ paths..."
    if tool_available "curl"; then
        local wellknown_paths=(
            "security.txt" "assetlinks.json" "apple-app-site-association"
            "change-password" "openid-configuration" "acme-challenge"
            "msidentity" "host-meta" "caldav" "carddav" "matomo.php"
        )
        local wellknown_found=0
        for wkpath in "${wellknown_paths[@]}"; do
            local wkurl="https://$domain/.well-known/$wkpath"
            local http_code
            http_code=$(curl -s -o /dev/null -w "%{http_code}" -L "$wkurl" 2>/dev/null || echo "000")
            if [ "$http_code" != "404" ] && [ "$http_code" != "000" ]; then
                curl -s -L -o "$meta_dir/wellknown_${wkpath}" "$wkurl" 2>/dev/null || true
                wellknown_found=$((wellknown_found + 1))
                write_endpoint "{\"type\":\"well_known\",\"url\":\"$wkurl\",\"status_code\":$http_code,\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$meta_dir/wellknown_finding_${wellknown_found}.json" || true
            fi
        done
        log "INFO" "Found $wellknown_found .well-known/ resources"
    fi

    # ===== HARVESTED META COMPILATION =====
    log "INFO" "Compiling harvested meta data..."
    {
        echo "=== META HARVEST RESULTS FOR $domain ==="
        echo "--- robots.txt ---"
        [ -s "$meta_dir/robots_parsed.txt" ] && cat "$meta_dir/robots_parsed.txt" || echo "Not found"
        echo ""
        echo "--- Disallowed Paths ---"
        [ -s "$meta_dir/disallowed_paths.txt" ] && cat "$meta_dir/disallowed_paths.txt" || echo "None"
        echo ""
        echo "--- Security.txt ---"
        [ -s "$meta_dir/security_parsed.txt" ] && cat "$meta_dir/security_parsed.txt" || echo "Not found"
        echo ""
        echo "--- Humans.txt ---"
        [ -s "$meta_dir/humans.txt" ] && head -20 "$meta_dir/humans.txt" || echo "Not found"
    } > "$meta_dir/harvested_meta.txt" 2>/dev/null || true

    local total_count
    total_count=$(find "$meta_dir" -type f \( -name "*.txt" -o -name "*.json" -o -name "*.xml" \) 2>/dev/null | wc -l)
    log "INFO" "Meta harvesting complete: $total_count results"
    echo "$total_count" > "$meta_dir/count.txt"
}
