#!/bin/bash
# Subresource inventory phase - third-party deps, SRI, CDN mapping

subresource_inventory_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local subres_dir="$output_dir/subresource_inventory"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$subres_dir"

    log "INFO" "Starting subresource inventory for $domain"
    py_log "INFO" "subresource_inventory_phase" --phase "subresource_inventory" --target "$domain"

    local live_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/live/httpx_results.txt"
    local crawl_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/crawl/crawled_urls.txt"
    local target_file=""

    if [ -f "$live_file" ]; then
        target_file="$live_file"
    elif [ -f "$crawl_file" ]; then
        target_file="$crawl_file"
    fi

    if [ -z "$target_file" ]; then
        log "WARN" "No live hosts or crawled URLs found, using domain root"
        echo "https://$domain" > "$subres_dir/seed_urls.txt"
        target_file="$subres_dir/seed_urls.txt"
    fi

    # ===== HTML FETCHING AND PARSING =====
    log "INFO" "Fetching pages and extracting subresources..."
    if tool_available "curl"; then
        > "$subres_dir/all_scripts.txt"
        > "$subres_dir/all_stylesheets.txt"
        > "$subres_dir/all_iframes.txt"
        > "$subres_dir/all_images_ext.txt"

        while IFS= read -r url; do
            [ -z "$url" ] && continue
            local html
            html=$(curl -s -L --max-time 15 "$url" 2>/dev/null || echo "")

            [ -z "$html" ] && continue

            # Extract script sources
            echo "$html" | grep -oiP '<script[^>]+src=["\x27]\K[^"\x27]+' 2>/dev/null \
                >> "$subres_dir/all_scripts.txt" || true

            # Extract stylesheet hrefs
            echo "$html" | grep -oiP '<link[^>]+href=["\x27]\K[^"\x27]+(?=["\x27][^>]*rel=["\x27]stylesheet)' 2>/dev/null \
                >> "$subres_dir/all_stylesheets.txt" || true

            # Extract iframe sources
            echo "$html" | grep -oiP '<iframe[^>]+src=["\x27]\K[^"\x27]+' 2>/dev/null \
                >> "$subres_dir/all_iframes.txt" || true

            # Extract external image domains
            echo "$html" | grep -oiP '<img[^>]+src=["\x27]\Khttps?://[^"\x27]+' 2>/dev/null \
                >> "$subres_dir/all_images_ext.txt" || true
        done < <(head -50 "$target_file")
    fi

    # ===== THIRD-PARTY DEPENDENCY CLASSIFICATION =====
    log "INFO" "Classifying third-party dependencies..."
    {
        echo "=== THIRD-PARTY DEPENDENCIES FOR $domain ==="
        echo ""
        echo "--- External Scripts ---"
        sort -u "$subres_dir/all_scripts.txt" 2>/dev/null || echo "None"
        echo ""
        echo "--- External Stylesheets ---"
        sort -u "$subres_dir/all_stylesheets.txt" 2>/dev/null || echo "None"
        echo ""
        echo "--- External Iframes ---"
        sort -u "$subres_dir/all_iframes.txt" 2>/dev/null || echo "None"
        echo ""
        echo "--- External Image Hosts ---"
        sort -u "$subres_dir/all_images_ext.txt" 2>/dev/null | sed 's|https\?://||; s|/.*||' | sort -u || echo "None"
    } > "$subres_dir/third_party_deps.txt" 2>/dev/null || true

    # ===== SRI (SUBRESOURCE INTEGRITY) ANALYSIS =====
    log "INFO" "Analyzing Subresource Integrity coverage..."
    if tool_available "curl"; then
        > "$subres_dir/sri_results.txt"
        local total_scripts=0
        local sri_protected=0

        while IFS= read -r url; do
            [ -z "$url" ] && continue
            local html
            html=$(curl -s -L --max-time 15 "$url" 2>/dev/null || echo "")
            [ -z "$html" ] && continue

            local page_scripts
            page_scripts=$(echo "$html" | grep -oiP '<script[^>]+src=["\x27][^"\x27]+["\x27][^>]*>' 2>/dev/null || echo "")
            local page_sri
            page_sri=$(echo "$html" | grep -oiP '<script[^>]+integrity=["\x27][^"\x27]+["\x27]' 2>/dev/null || echo "")

            local ps_count psri_count
            ps_count=$(echo "$page_scripts" | grep -c 'src=' 2>/dev/null || echo 0)
            psri_count=$(echo "$page_sri" | grep -c 'integrity=' 2>/dev/null || echo 0)
            total_scripts=$((total_scripts + ps_count))
            sri_protected=$((sri_protected + psri_count))
        done < <(head -30 "$target_file")

        local sri_coverage="0"
        if [ "$total_scripts" -gt 0 ]; then
            sri_coverage=$(awk "BEGIN {printf \"%.1f\", ($sri_protected / $total_scripts) * 100}")
        fi

        {
            echo "=== SRI ANALYSIS FOR $domain ==="
            echo "Total external scripts: $total_scripts"
            echo "SRI protected scripts: $sri_protected"
            echo "SRI coverage: ${sri_coverage}%"
            if [ "$sri_coverage" = "0.0" ] && [ "$total_scripts" -gt 0 ]; then
                echo "STATUS: CRITICAL - No SRI coverage on $total_scripts external scripts"
            elif (( $(awk "BEGIN {print ($sri_coverage < 50) ? 1 : 0}") )); then
                echo "STATUS: WARNING - Low SRI coverage"
            else
                echo "STATUS: OK - Adequate SRI coverage"
            fi
        } > "$subres_dir/sri_status.txt" 2>/dev/null || true

        write_finding "{\"type\":\"sri_analysis\",\"target\":\"$domain\",\"total_scripts\":$total_scripts,\"sri_protected\":$sri_protected,\"coverage\":\"${sri_coverage}%\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$subres_dir/sri_finding.json" || true
    fi

    # ===== CDN USAGE MAPPING =====
    log "INFO" "Mapping CDN and third-party hosting..."
    {
        echo "=== CDN AND HOSTING MAP FOR $domain ==="
        echo ""
        local all_deps="$subres_dir/third_party_deps.txt"
        local known_cdns="cloudflare|cloudfront|fastly|akamai|jsdelivr|unpkg|cdnjs|googleapis|gstatic|bootstrapcdn|jquery|cloudinary|vercel|netlify|azureedge|incapsula|sucuri"
        grep -iE "$known_cdns" "$all_deps" 2>/dev/null | sort -u > "$subres_dir/cdn_entries.txt" || true

        if [ -s "$subres_dir/cdn_entries.txt" ]; then
            echo "Detected CDN/Third-party hosts:"
            while IFS= read -r line; do
                local host
                host=$(echo "$line" | sed 's|https\?://||; s|/.*||')
                [ -n "$host" ] && echo "  - $host"
            done < "$subres_dir/cdn_entries.txt"
        else
            echo "No known CDN dependencies detected"
        fi
    } > "$subres_dir/cdn_map.txt" 2>/dev/null || true

    write_finding "{\"type\":\"cdn_map\",\"target\":\"$domain\",\"file\":\"cdn_map.txt\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$subres_dir/cdn_finding.json" || true

    local total_count
    total_count=$(wc -l < "$subres_dir/third_party_deps.txt" 2>/dev/null || echo 0)
    log "INFO" "Subresource inventory complete: $total_count dependency entries"
    echo "$total_count" > "$subres_dir/count.txt"
}
