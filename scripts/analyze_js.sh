#!/bin/bash
# JS File Analysis & Validation Script
# Analyzes JavaScript files for secrets, endpoints, vulnerabilities, and library versions

analyze_js_files() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local js_analysis_dir="$output_dir/js_analysis"
    local js_files_list="$output_dir/crawl/js_files.txt"

    mkdir -p "$js_analysis_dir"

    log "INFO" "Starting JavaScript file analysis for $domain"

    if [ ! -f "$js_files_list" ]; then
        log "WARN" "No JS files list found, skipping JS analysis"
        return 1
    fi

    local js_count=0
    while IFS= read -r js_url; do
        [ -z "$js_url" ] && continue
        js_count=$((js_count + 1))
        
        if [ $js_count -gt 100 ]; then
            log "INFO" "Reached JS file limit (100), stopping"
            break
        fi

        log "DEBUG" "Analyzing JS file: $js_url"

        # Download JS file
        local js_filename=$(echo "$js_url" | sed 's|https\?://||g' | sed 's|[/?&=]|_|g' | cut -c1-100)
        local js_path="$js_analysis_dir/${js_filename}.js"
        
        curl -s -L --max-time 30 "$js_url" -o "$js_path" 2>>"$LOGS_DIR/js_download.log" || continue
        
        if [ ! -s "$js_path" ]; then
            rm -f "$js_path"
            continue
        fi

        # ========================================================================
        # 1. SECRET DETECTION
        # ========================================================================
        log "DEBUG" "Scanning for secrets in: $js_url"
        
        # API Keys & Tokens
        grep -iE "(api[_-]?key|apikey|api_key|access[_-]?token|accesstoken|access_token|secret[_-]?key|secretkey|secret_key|private[_-]?key|privatekey|private_key)" "$js_path" \
            > "$js_analysis_dir/secrets_${js_filename}.txt" 2>/dev/null || true
        
        # AWS
        grep -iE "(AKIA[0-9A-Z]{16}|aws[_-]?access[_-]?key|aws[_-]?secret[_-]?key)" "$js_path" \
            >> "$js_analysis_dir/secrets_${js_filename}.txt" 2>/dev/null || true
        
        # Generic secrets patterns
        grep -E "(['\"][a-zA-Z0-9_\-]{20,}['\"])" "$js_path" \
            >> "$js_analysis_dir/secrets_${js_filename}.txt" 2>/dev/null || true
        
        # JWT tokens
        grep -E "eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+" "$js_path" \
            >> "$js_analysis_dir/secrets_${js_filename}.txt" 2>/dev/null || true

        # ========================================================================
        # 2. ENDPOINT EXTRACTION
        # ========================================================================
        log "DEBUG" "Extracting endpoints from: $js_url"
        
        # API endpoints
        grep -oE "(https?://[a-zA-Z0-9./?=_-]+)" "$js_path" | sort -u \
            > "$js_analysis_dir/endpoints_${js_filename}.txt" 2>/dev/null || true
        
        # Relative paths
        grep -oE "(/[a-zA-Z0-9./?=_-]+)" "$js_path" | grep -E "^/(api|v[0-9]|graphql|rest)" | sort -u \
            >> "$js_analysis_dir/endpoints_${js_filename}.txt" 2>/dev/null || true
        
        # WebSocket endpoints
        grep -oE "(wss?://[a-zA-Z0-9./?=_-]+)" "$js_path" | sort -u \
            >> "$js_analysis_dir/endpoints_${js_filename}.txt" 2>/dev/null || true

        # ========================================================================
        # 3. LIBRARY & FRAMEWORK DETECTION
        # ========================================================================
        log "DEBUG" "Detecting libraries in: $js_url"
        
        # Known library signatures
        cat > "$js_analysis_dir/lib_signatures.txt" << 'LIBSIGS'
jQuery:jquery
React:react
Vue:vue
Angular:angular
Bootstrap:bootstrap
Lodash:lodash
Moment:moment
Axios:axios
Underscore:underscore
Backbone:backbone
D3:d3
Three:three
Pixi:pixi
GSAP:gsap
Anime:anime
Popper:popper
Tether:tether
Slick:slick
Swiper:swiper
Flickity:flickity
Isotope:isotope
Masonry:masonry
Packery:packery
ImagesLoaded:imagesloaded
LazyLoad:lazyload
Lazysizes:lazysizes
IntersectionObserver:intersection-observer
LIBSIGS
        
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            lib_name="${line%%:*}"
            lib_pattern="${line#*:}"
            if grep -qi "$lib_pattern" "$js_path"; then
                # Try to extract version
                version=$(grep -oE "$lib_pattern[.\-_]?v?[0-9]+\.[0-9]+\.[0-9]+" "$js_path" | head -1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" || echo "unknown")
                echo "$lib_name:$version:$js_url" >> "$js_analysis_dir/libraries_found.txt"
            fi
        done < "$js_analysis_dir/lib_signatures.txt"

        # ========================================================================
        # 4. VULNERABILITY PATTERNS
        # ========================================================================
        log "DEBUG" "Scanning for vulnerability patterns in: $js_url"
        
        # Dangerous functions
        grep -nE "(eval\(|Function\(|setTimeout\(|setInterval\(|execScript\()" "$js_path" \
            > "$js_analysis_dir/dangerous_${js_filename}.txt" 2>/dev/null || true
        
        # DOM XSS sinks
        grep -nE "(innerHTML|outerHTML|document\.write|document\.writeln|\.html\(|\.append\(|\.prepend\(|\.after\(|\.before\()" "$js_path" \
            >> "$js_analysis_dir/dangerous_${js_filename}.txt" 2>/dev/null || true
        
        # Prototype pollution
        grep -nE "(__proto__|constructor\.prototype|Object\.prototype)" "$js_path" \
            >> "$js_analysis_dir/dangerous_${js_filename}.txt" 2>/dev/null || true
        
        # PostMessage without origin check
        grep -nE "(postMessage\(|addEventListener\(['\"]message['\"])" "$js_path" \
            >> "$js_analysis_dir/dangerous_${js_filename}.txt" 2>/dev/null || true
        
        # Crypto weaknesses
        grep -nE "(MD5|SHA1|RC4|DES|ECB|Math\.random\(\))" "$js_path" \
            >> "$js_analysis_dir/dangerous_${js_filename}.txt" 2>/dev/null || true

        # ========================================================================
        # 5. SOURCE MAP DETECTION
        # ========================================================================
        if grep -q "sourceMappingURL" "$js_path"; then
            map_url=$(grep -oE "sourceMappingURL=([^\"'\s]+)" "$js_path" | cut -d'=' -f2 | head -1)
            if [ -n "$map_url" ]; then
                # Try to download source map
                if [[ "$map_url" == http* ]]; then
                    curl -s -L --max-time 30 "$map_url" -o "$js_analysis_dir/${js_filename}.map" 2>/dev/null || true
                else
                    # Relative path
                    base_url=$(echo "$js_url" | sed 's|/[^/]*$|/|')
                    curl -s -L --max-time 30 "${base_url}${map_url}" -o "$js_analysis_dir/${js_filename}.map" 2>/dev/null || true
                fi
                echo "SOURCE_MAP: $map_url" >> "$js_analysis_dir/sourcemaps_${js_filename}.txt"
            fi
        fi

        # ========================================================================
        # 6. MINIFICATION DETECTION
        # ========================================================================
        line_count=$(wc -l < "$js_path")
        char_count=$(wc -c < "$js_path")
        avg_line_len=$((char_count / (line_count + 1)))
        
        if [ $line_count -lt 10 ] && [ $avg_line_len -gt 500 ]; then
            echo "MINIFIED: $js_url (lines: $line_count, avg_len: $avg_line_len)" >> "$js_analysis_dir/minified_files.txt"
        fi

    done < "$js_files_list"

    # ========================================================================
    # AGGREGATE RESULTS
    # ========================================================================
    log "INFO" "Aggregating JS analysis results..."
    
    # Secrets summary
    cat "$js_analysis_dir"/secrets_*.txt 2>/dev/null | sort -u > "$js_analysis_dir/all_secrets.txt" 2>/dev/null || true
    
    # Endpoints summary
    cat "$js_analysis_dir"/endpoints_*.txt 2>/dev/null | sort -u > "$js_analysis_dir/all_endpoints.txt" 2>/dev/null || true
    
    # Libraries summary
    if [ -f "$js_analysis_dir/libraries_found.txt" ]; then
        sort -u "$js_analysis_dir/libraries_found.txt" > "$js_analysis_dir/libraries_summary.txt"
    fi
    
    # Dangerous patterns summary
    cat "$js_analysis_dir"/dangerous_*.txt 2>/dev/null | sort -u > "$js_analysis_dir/all_dangerous.txt" 2>/dev/null || true
    
    # Source maps summary
    cat "$js_analysis_dir"/sourcemaps_*.txt 2>/dev/null | sort -u > "$js_analysis_dir/all_sourcemaps.txt" 2>/dev/null || true
    
    # Minified files
    cat "$js_analysis_dir/minified_files.txt" 2>/dev/null | sort -u > "$js_analysis_dir/minified_summary.txt" 2>/dev/null || true

    # Create JSON report
    python3 << 'PYEOF' "$domain" "$output_dir" "$js_analysis_dir" 2>/dev/null || true
import json, os, sys, re
from datetime import datetime

domain = sys.argv[1]
output_dir = sys.argv[2]
js_dir = sys.argv[3]

report = {
    'domain': domain,
    'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
    'js_files_analyzed': 0,
    'secrets_found': [],
    'endpoints_found': [],
    'libraries_detected': [],
    'dangerous_patterns': [],
    'source_maps': [],
    'minified_files': []
}

# Count JS files analyzed
js_files = [f for f in os.listdir(js_dir) if f.endswith('.js') and not f.endswith('.map')]
report['js_files_analyzed'] = len(js_files)

# Parse secrets
secrets_file = os.path.join(js_dir, 'all_secrets.txt')
if os.path.exists(secrets_file):
    with open(secrets_file) as f:
        for line in f:
            line = line.strip()
            if line:
                report['secrets_found'].append({'pattern': line, 'source': 'js_analysis'})

# Parse endpoints
endpoints_file = os.path.join(js_dir, 'all_endpoints.txt')
if os.path.exists(endpoints_file):
    with open(endpoints_file) as f:
        for line in f:
            line = line.strip()
            if line:
                report['endpoints_found'].append(line)

# Parse libraries
libs_file = os.path.join(js_dir, 'libraries_summary.txt')
if os.path.exists(libs_file):
    with open(libs_file) as f:
        for line in f:
            line = line.strip()
            if line:
                parts = line.split(':')
                if len(parts) >= 3:
                    report['libraries_detected'].append({
                        'name': parts[0],
                        'version': parts[1],
                        'source_url': parts[2]
                    })

# Parse dangerous patterns
dangerous_file = os.path.join(js_dir, 'all_dangerous.txt')
if os.path.exists(dangerous_file):
    with open(dangerous_file) as f:
        for line in f:
            line = line.strip()
            if line:
                report['dangerous_patterns'].append(line)

# Parse source maps
sourcemaps_file = os.path.join(js_dir, 'all_sourcemaps.txt')
if os.path.exists(sourcemaps_file):
    with open(sourcemaps_file) as f:
        for line in f:
            line = line.strip()
            if line:
                report['source_maps'].append(line)

# Parse minified files
minified_file = os.path.join(js_dir, 'minified_summary.txt')
if os.path.exists(minified_file):
    with open(minified_file) as f:
        for line in f:
            line = line.strip()
            if line:
                report['minified_files'].append(line)

# Write report
with open(os.path.join(js_dir, 'js_analysis_report.json'), 'w') as f:
    json.dump(report, f, indent=2)

print(f"JS Analysis complete: {report['js_files_analyzed']} files, {len(report['secrets_found'])} secrets, {len(report['endpoints_found'])} endpoints, {len(report['libraries_detected'])} libraries")
PYEOF

    log "INFO" "JavaScript file analysis complete for $domain"
}

export -f analyze_js_files