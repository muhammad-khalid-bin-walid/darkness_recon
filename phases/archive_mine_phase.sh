#!/bin/bash
# Archive mining phase - Wayback Machine, Common Crawl, GitHub Archive, cached pages

archive_mine_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local archive_dir="$output_dir/archive_mine"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$archive_dir"

    log "INFO" "Starting archive mining for $domain"
    py_log "INFO" "archive_mine_phase" --phase "archive_mine" --target "$domain"

    # ===== WAYBACK MACHINE CDX API =====
    log "INFO" "Querying Wayback Machine CDX API..."
    if tool_available "curl"; then
        curl -s "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=json&limit=5000&fl=timestamp,original,statuscode,mimetype&collapse=urlkey" \
            -o "$archive_dir/wayback_cdx.json" 2>/dev/null || true

        if [ -s "$archive_dir/wayback_cdx.json" ]; then
            python3 -c "
import json, sys
try:
    with open('$archive_dir/wayback_cdx.json') as f:
        data = json.load(f)
    urls = set()
    endpoints = set()
    if isinstance(data, list) and len(data) > 1:
        for row in data[1:]:
            if len(row) >= 4:
                original = row[1]
                status = row[2]
                mime = row[3]
                urls.add(original)
                if status in ('200', '301', '302', '301', '403', '500'):
                    endpoint = original.split('?')[0].split('#')[0]
                    if endpoint:
                        endpoints.add(endpoint)
    with open('$archive_dir/wayback_urls.txt', 'w') as f:
        for u in sorted(urls):
            f.write(u + '\n')
    with open('$archive_dir/historical_endpoints.txt', 'w') as f:
        for e in sorted(endpoints):
            f.write(e + '\n')
    print(f'wayback_urls={len(urls)},endpoints={len(endpoints)}')
except Exception as e:
    print(f'error={e}', file=sys.stderr)
" 2>/dev/null || true
        fi

        # Deep mining - individual domain searches
        local subdomains_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/subdomains/all_subdomains.txt"
        if [ -f "$subdomains_file" ]; then
            log "INFO" "Deep mining Wayback for subdomains..."
            while IFS= read -r sub; do
                [ -z "$sub" ] && continue
                curl -s "https://web.archive.org/cdx/search/cdx?url=${sub}/*&output=json&limit=2000&fl=timestamp,original,statuscode&collapse=urlkey" \
                    -o "$archive_dir/wayback_${sub}.json" 2>/dev/null || true
            done < <(head -30 "$subdomains_file")
        fi
    fi

    # ===== COMMON CRAWL INDEX =====
    log "INFO" "Querying Common Crawl index..."
    if tool_available "curl"; then
        local cc_index
        cc_index=$(curl -s "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.${domain}/*&output=json&limit=1000" 2>/dev/null || echo "")
        if [ -n "$cc_index" ]; then
            echo "$cc_index" > "$archive_dir/commoncrawl_results.json"
            python3 -c "
import json, sys
try:
    with open('$archive_dir/commoncrawl_results.json') as f:
        lines = f.readlines()
    urls = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            url = entry.get('url', '')
            if url:
                urls.add(url)
        except json.JSONDecodeError:
            pass
    with open('$archive_dir/commoncrawl_urls.txt', 'w') as f:
        for u in sorted(urls):
            f.write(u + '\n')
except Exception as e:
    pass
" 2>/dev/null || true
        fi
    fi

    # ===== GITHUB ARCHIVE =====
    log "INFO" "Querying GitHub for domain references..."
    if tool_available "curl"; then
        curl -s "https://api.github.com/search/code?q=$domain+in:file" \
            -H "Accept: application/vnd.github.v3+json" 2>/dev/null \
            | jq -r '.items[]? | "\(.repository.full_name) \(.path) \(.html_url)"' 2>/dev/null \
            > "$archive_dir/github_refs.txt" || true
    fi

    # ===== CACHED PAGE ANALYSIS =====
    log "INFO" "Analyzing cached page snapshots..."
    if tool_available "curl" && [ -f "$archive_dir/wayback_urls.txt" ]; then
        local cached_count=0
        while IFS= read -r wb_url; do
            [ -z "$wb_url" ] && continue
            local timestamp
            timestamp=$(echo "$wb_url" | grep -oP '/web/\K\d+' | head -1)
            [ -z "$timestamp" ] && continue
            cached_count=$((cached_count + 1))
            [ "$cached_count" -gt 50 ] && break
            curl -s -L -o "$archive_dir/cached_${cached_count}.html" \
                "https://web.archive.org/web/${timestamp}id_/${wb_url}" 2>/dev/null || true
        done < <(head -50 "$archive_dir/wayback_urls.txt")
        log "INFO" "Downloaded $cached_count cached snapshots"
    fi

    # ===== COMBINED ARCHIVED URLS =====
    log "INFO" "Compiling archived URLs..."
    {
        cat "$archive_dir/wayback_urls.txt" 2>/dev/null
        cat "$archive_dir/commoncrawl_urls.txt" 2>/dev/null
    } | sort -u > "$archive_dir/archived_urls.txt" 2>/dev/null || true

    # ===== FINDINGS =====
    local archived_count
    archived_count=$(wc -l < "$archive_dir/archived_urls.txt" 2>/dev/null || echo 0)
    local endpoint_count
    endpoint_count=$(wc -l < "$archive_dir/historical_endpoints.txt" 2>/dev/null || echo 0)

    if [ "$archived_count" -gt 0 ]; then
        write_finding "{\"type\":\"archived_urls\",\"target\":\"$domain\",\"count\":$archived_count,\"source\":\"wayback+commoncrawl\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$archive_dir/archive_finding.json" || true
    fi

    if [ "$endpoint_count" -gt 0 ]; then
        write_endpoint "{\"type\":\"historical_endpoints\",\"target\":\"$domain\",\"count\":$endpoint_count,\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$archive_dir/endpoint_finding.json" || true
    fi

    log "INFO" "Archive mining complete: $archived_count archived URLs, $endpoint_count historical endpoints"
    local total_count=$((archived_count + endpoint_count))
    echo "$total_count" > "$archive_dir/count.txt"
}
