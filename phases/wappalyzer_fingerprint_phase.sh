#!/bin/bash
# Technology fingerprinting phase - Wappalyzer, whatweb, builtwith

wappalyzer_fingerprint_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local tech_dir="$output_dir/wappalyzer_fingerprint"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$tech_dir"

    log "INFO" "Starting technology fingerprinting for $domain"
    py_log "INFO" "wappalyzer_fingerprint_phase" --phase "wappalyzer_fingerprint" --target "$domain"

    local live_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/live/httpx_results.txt"
    local crawl_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/crawl/crawled_urls.txt"
    local target_urls=()

    if [ -f "$live_file" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local url
            url=$(echo "$line" | awk '{print $1}')
            [ -n "$url" ] && target_urls+=("$url")
        done < <(head -30 "$live_file")
    elif [ -f "$crawl_file" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            target_urls+=("$line")
        done < <(head -30 "$crawl_file")
    else
        target_urls+=("https://$domain")
        target_urls+=("http://$domain")
    fi

    # ===== WHATWEB =====
    log "INFO" "Running WhatWeb for technology detection..."
    if tool_available "whatweb"; then
        > "$tech_dir/whatweb_raw.txt"
        for url in "${target_urls[@]}"; do
            [ -z "$url" ] && continue
            whatweb --color=never "$url" 2>>"$LOGS_DIR/whatweb.log" >> "$tech_dir/whatweb_raw.txt" || true
        done

        python3 -c "
import re, json, sys
technologies = set()
tech_details = []
try:
    with open('$tech_dir/whatweb_raw.txt') as f:
        for line in f:
            # Extract technology names from WhatWeb output
            matches = re.findall(r'\[(.*?)\]', line)
            for m in matches:
                parts = m.split(',')
                for part in parts:
                    part = part.strip().split(':')[0].strip()
                    if part and part not in ('status', 'IP', 'Country', 'UncommonHeaders'):
                        technologies.add(part)
                        tech_details.append({'name': part, 'source': 'whatweb'})
except Exception as e:
    pass
with open('$tech_dir/whatweb_tech.txt', 'w') as f:
    for t in sorted(technologies):
        f.write(t + '\n')
" 2>/dev/null || true
    fi

    # ===== WAPPALYZER CLI =====
    log "INFO" "Running Wappalyzer..."
    if tool_available "wappalyzer"; then
        > "$tech_dir/wappalyzer_raw.txt"
        for url in "${target_urls[@]}"; do
            [ -z "$url" ] && continue
            wappalyzer "$url" 2>>"$LOGS_DIR/wappalyzer.log" >> "$tech_dir/wappalyzer_raw.txt" || true
        done
    elif tool_available "npx"; then
        log "INFO" "Attempting Wappalyzer via npx..."
        for url in "${target_urls[@]}"; do
            [ -z "$url" ] && continue
            npx -y wappalyzer "$url" 2>>"$LOGS_DIR/wappalyzer.log" >> "$tech_dir/wappalyzer_raw.json" || true
        done

        python3 -c "
import json, sys
technologies = set()
try:
    with open('$tech_dir/wappalyzer_raw.json') as f:
        data = json.load(f)
    for tech in data.get('technologies', []):
        name = tech.get('name', '')
        version = tech.get('version', '')
        if name:
            technologies.add(f'{name} {version}'.strip())
except Exception as e:
    pass
with open('$tech_dir/wappalyzer_tech.txt', 'w') as f:
    for t in sorted(technologies):
        f.write(t + '\n')
" 2>/dev/null || true
    fi

    # ===== BUILTWITH API =====
    log "INFO" "Querying BuiltWith for technology data..."
    if tool_available "curl" && [ -n "${BUILTWITH_API_KEY:-}" ]; then
        curl -s "https://api.builtwith.com/free1/api.json?KEY=$BUILTWITH_API_KEY&LOOKUP=$domain" \
            -o "$tech_dir/builtwith_raw.json" 2>/dev/null || true

        python3 -c "
import json, sys
technologies = []
try:
    with open('$tech_dir/builtwith_raw.json') as f:
        data = json.load(f)
    for group in data.get('Results', {}).get('Result', {}).get('Lookup', {}).get('Result', []):
        for item in group.get('Categories', []):
            for cat in item.get('Items', []):
                tech_name = cat.get('Tag', {}).get('Name', '')
                if tech_name:
                    technologies.append({'name': tech_name, 'category': group.get('Categories', [{}])[0].get('Group', '')})
except Exception as e:
    pass
with open('$tech_dir/builtwith_tech.json', 'w') as f:
    json.dump(technologies, f, indent=2)
with open('$tech_dir/builtwith_tech.txt', 'w') as f:
    for t in technologies:
        f.write(t.get('name', '') + '\n')
" 2>/dev/null || true
    fi

    # ===== HTML ANALYSIS FOR TECHNOLOGY HINTS =====
    log "INFO" "Analyzing HTML source for technology signatures..."
    if tool_available "curl"; then
        for url in "${target_urls[@]:0:5}"; do
            [ -z "$url" ] && continue
            local html
            html=$(curl -s -L --max-time 15 "$url" 2>/dev/null || echo "")
            [ -z "$html" ] && continue

            # Extract generator meta
            echo "$html" | grep -oiP '<meta[^>]+name=["\x27]generator["\x27][^>]+content=["\x27]\K[^"\x27]+' 2>/dev/null \
                >> "$tech_dir/meta_generators.txt" || true

            # Extract CDN/power-by headers
            echo "$html" | grep -oiP '(?:x-powered-by|x-aspnet|x-runtime|x-generator|x-cache|x-cdn)[^:]*:\s*\K.*' 2>/dev/null \
                >> "$tech_dir/tech_headers.txt" || true

            # Extract JS/CSS framework signatures
            echo "$html" | grep -oiP '(react|vue|angular|jquery|bootstrap|tailwind|nextjs|nuxt|svelte|ember|backbone)[/.]' 2>/dev/null \
                >> "$tech_dir/framework_hints.txt" || true
        done
    fi

    # ===== CONSOLIDATE TECHNOLOGY STACK =====
    log "INFO" "Compiling technology stack..."
    {
        echo "=== TECHNOLOGY STACK FOR $domain ==="
        echo ""
        echo "--- WhatWeb ---"
        cat "$tech_dir/whatweb_tech.txt" 2>/dev/null || echo "Not available"
        echo ""
        echo "--- Wappalyzer ---"
        cat "$tech_dir/wappalyzer_tech.txt" 2>/dev/null || echo "Not available"
        echo ""
        echo "--- BuiltWith ---"
        cat "$tech_dir/builtwith_tech.txt" 2>/dev/null || echo "Not available"
        echo ""
        echo "--- Meta Generators ---"
        sort -u "$tech_dir/meta_generators.txt" 2>/dev/null || echo "None"
        echo ""
        echo "--- Framework Hints ---"
        sort -u "$tech_dir/framework_hints.txt" 2>/dev/null || echo "None"
    } > "$tech_dir/tech_stack.txt" 2>/dev/null || true

    # ===== TECHNOLOGY VERSIONS =====
    python3 -c "
import re, os, sys

tech_dir = '$tech_dir'
versions = []

# Parse WhatWeb output for versions
ww_file = os.path.join(tech_dir, 'whatweb_raw.txt')
if os.path.exists(ww_file):
    with open(ww_file) as f:
        for line in f:
            matches = re.findall(r'(\w+)[\s:]+v?(\d[\d.]+)', line)
            for name, ver in matches:
                versions.append({'name': name, 'version': ver, 'source': 'whatweb'})

# Parse HTML for version patterns
html_versions = [
    (r'jQuery[/.]v?(\d[\d.]+)', 'jQuery'),
    (r'bootstrap[/.]v?(\d[\d.]+)', 'Bootstrap'),
    (r'react[/.]v?(\d[\d.]+)', 'React'),
    (r'vue[/.]v?(\d[\d.]+)', 'Vue.js'),
    (r'angular[/.]v?(\d[\d.]+)', 'Angular'),
    (r'tailwindcss[/.]v?(\d[\d.]+)', 'Tailwind CSS'),
]
for f in os.listdir(tech_dir):
    if f.startswith('cached_') and f.endswith('.html'):
        with open(os.path.join(tech_dir, f)) as fh:
            content = fh.read()
            for pattern, name in html_versions:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for m in matches:
                    versions.append({'name': name, 'version': m, 'source': 'html'})

import json
with open(os.path.join(tech_dir, 'technology_versions.json'), 'w') as f:
    json.dump(versions, f, indent=2)
with open(os.path.join(tech_dir, 'technology_versions.txt'), 'w') as f:
    for v in versions:
        f.write(f\"{v['name']} {v['version']} ({v['source']})\n\")
" 2>/dev/null || true

    # ===== FINDINGS =====
    local tech_count
    tech_count=$(cat "$tech_dir/whatweb_tech.txt" "$tech_dir/wappalyzer_tech.txt" "$tech_dir/builtwith_tech.txt" 2>/dev/null | sort -u | wc -l)
    log "INFO" "Technology fingerprinting complete: $tech_count technologies identified"

    write_finding "{\"type\":\"tech_fingerprint\",\"target\":\"$domain\",\"count\":$tech_count,\"sources\":\"whatweb,wappalyzer,builtwith\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$tech_dir/tech_finding.json" || true

    echo "$tech_count" > "$tech_dir/count.txt"
}
