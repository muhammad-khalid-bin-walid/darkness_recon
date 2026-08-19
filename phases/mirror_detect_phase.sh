#!/usr/bin/env bash
# Mirror Detect Phase - Duplicate and mirror site detection
set -euo pipefail

mirror_detect_phase() {
    local domain="$1"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/mirror_detect"
    mkdir -p "$phase_dir"

    log "INFO" "[mirror_detect] Starting mirror detection for $domain"
    py_log "phase_start" "mirror_detect" "$domain"

    local count=0

    # Download favicon for hashing
    log "INFO" "[mirror_detect] Downloading favicon for hash comparison"
    local favicon_data
    # Try common favicon paths
    for favicon_path in "/favicon.ico" "/favicon.png" "/apple-touch-icon.png"; do
        favicon_data=$(curl -sL "https://${domain}${favicon_path}" 2>/dev/null || true)
        if [[ -n "$favicon_data" && ${#favicon_data} -gt 100 ]]; then
            echo "$favicon_data" > "$phase_dir/favicon.bin"
            break
        fi
    done

    # Generate content hash of main page
    log "INFO" "[mirror_detect] Generating content fingerprints"
    local main_page_hash
    main_page_hash=$(curl -sL "https://${domain}" 2>/dev/null \
        | sed 's/[[:space:]]//g' | md5sum | awk '{print $1}')
    echo "${domain}:${main_page_hash}" > "$phase_dir/content_hashes.txt"

    # Check for CNAME-based mirrors
    log "INFO" "[mirror_detect] Checking DNS CNAME chains"
    local cname_chain
    cname_chain=$(dig +short CNAME "$domain" 2>/dev/null)
    if [[ -n "$cname_chain" ]]; then
        echo "$domain -> $cname_chain" >> "$phase_dir/cname_analysis.txt"
        dig +short A "$cname_chain" 2>/dev/null >> "$phase_dir/cname_ips.txt" || true
    fi

    # Check for www subdomain mirror
    local www_hash
    www_hash=$(curl -sL "https://www.${domain}" 2>/dev/null \
        | sed 's/[[:space:]]//g' | md5sum 2>/dev/null | awk '{print $1}')
    if [[ -n "$www_hash" && "$www_hash" == "$main_page_hash" ]]; then
        echo "www.${domain}: SAME CONTENT (mirror)" >> "$phase_dir/mirror_sites.txt"
    elif [[ -n "$www_hash" ]]; then
        echo "www.${domain}: DIFFERENT CONTENT" >> "$phase_dir/mirror_sites.txt"
        echo "www.${domain}:${www_hash}" >> "$phase_dir/content_hashes.txt"
    fi

    # Check common mirror/CDN hostnames
    log "INFO" "[mirror_detect] Checking common mirror patterns"
    local mirror_prefixes=("www" "mirror" "backup" "archive" "old" "new" "staging" "dev" "test" "beta")
    for prefix in "${mirror_prefixes[@]}"; do
        local mirror_hash
        mirror_hash=$(curl -sL "https://${prefix}.${domain}" 2>/dev/null \
            | sed 's/[[:space:]]//g' | md5sum 2>/dev/null | awk '{print $1}')
        if [[ -n "$mirror_hash" ]]; then
            echo "${prefix}.${domain}:${mirror_hash}" >> "$phase_dir/content_hashes.txt"
            if [[ "$mirror_hash" == "$main_page_hash" ]]; then
                echo "${prefix}.${domain}: SAME CONTENT (mirror)" >> "$phase_dir/mirror_sites.txt"
            fi
        fi
    done

    # Check for IP-based vhosts
    local target_ip
    target_ip=$(dig +short "$domain" A 2>/dev/null | head -1)
    if [[ -n "$target_ip" ]]; then
        log "INFO" "[mirror_detect] Checking IP-based vhost responses"
        local ip_hash
        ip_hash=$(curl -sL -H "Host: ${domain}" "https://${target_ip}" -k 2>/dev/null \
            | sed 's/[[:space:]]//g' | md5sum 2>/dev/null | awk '{print $1}')
        if [[ -n "$ip_hash" && "$ip_hash" != "$main_page_hash" && ${#ip_hash} -eq 32 ]]; then
            echo "${target_ip} (direct IP): DIFFERENT RESPONSE" >> "$phase_dir/mirror_sites.txt"
        fi
    fi

    # Check Wayback Machine for historical mirrors
    log "INFO" "[mirror_detect] Checking Wayback Machine"
    curl -s "https://web.archive.org/web/timemap/json?url=${domain}&output=json&limit=10" \
        2>/dev/null > "$phase_dir/wayback_raw.json" || true

    # Favicon hash comparison with known mirrors via Shodan
    if [[ -n "${SHODAN_API_KEY:-}" && -f "$phase_dir/favicon.bin" ]]; then
        log "INFO" "[mirror_detect] Querying Shodan for favicon hash matches"
        local favicon_hash
        favicon_hash=$(xxd -p "$phase_dir/favicon.bin" 2>/dev/null | tr -d '\n' || true)
        if [[ -n "$favicon_hash" ]]; then
            curl -s "https://api.shodan.io/labs/shodan-http/hashed_favicon/${favicon_hash}?key=${SHODAN_API_KEY}" \
                2>/dev/null > "$phase_dir/shodan_favicon.json" || true
        fi
    fi

    # Compile mirror sites list
    sort -u "$phase_dir/mirror_sites.txt" 2>/dev/null > "$phase_dir/mirror_sites_final.txt" || true
    mv "$phase_dir/mirror_sites_final.txt" "$phase_dir/mirror_sites.txt" 2>/dev/null || true

    count=$(grep -c "SAME CONTENT" "$phase_dir/mirror_sites.txt" 2>/dev/null || echo 0)
    echo "$count" > "$phase_dir/count.txt"

    write_finding "$domain" "mirror_detect" "info" \
        "Detected $count mirror sites with matching content" || true

    log "INFO" "[mirror_detect] Complete: $count mirrors found"
    py_log "phase_complete" "mirror_detect" "$domain" "count=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mirror_detect_phase "${1:?Usage: mirror_detect_phase <domain>}"
fi
