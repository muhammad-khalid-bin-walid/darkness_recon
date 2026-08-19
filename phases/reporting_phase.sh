#!/bin/bash
# Advanced reporting phase - HTML, Markdown, CSV, DB, webhooks

reporting_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local report_dir="$output_dir/reports"
    
    mkdir -p "$report_dir"
    
    log "INFO" "Generating advanced reports for $domain"
    
    local final_output="$output_dir/final_output.txt"
    local json_report="$output_dir/final_output.json"
    
    # ===== BASIC TEXT REPORT =====
    {
        echo -e "\033[1;35m"
        echo "===================================================================="
        echo "          Dark Recon Framework v4 - Made by DarkLegende                     "
        echo "===================================================================="
        echo -e "\033[0m"
        echo "[*] Reconnaissance Results for $domain"
        echo "Timestamp: $TIMESTAMP"
        echo "Total Subdomains: $(wc -l < "$output_dir/subdomains/subdomains.txt" 2>/dev/null || echo 0)"
        echo "Live Subdomains: $(wc -l < "$output_dir/live/live_subdomains.txt" 2>/dev/null || echo 0)"
        echo "JavaScript Files: $(wc -l < "$output_dir/crawl/js_files.txt" 2>/dev/null || echo 0)"
        echo "URLs with Parameters: $(wc -l < "$output_dir/crawl/urls_with_params.txt" 2>/dev/null || echo 0)"
        echo "Endpoints: $(wc -l < "$output_dir/crawl/endpoints.txt" 2>/dev/null || echo 0)"
        echo "Fuzzing Results: $(wc -l < "$output_dir/fuzz/fuzz_results.txt" 2>/dev/null || echo 0)"
        [ "${DIRSEARCH:-false}" = true ] && echo "Dirsearch Results: $(wc -l < "$output_dir/dirsearch/dirsearch_results.txt" 2>/dev/null || echo 0)"
        [ "${API_SCAN:-false}" = true ] && echo "API Endpoints: $(wc -l < "$output_dir/api/apiscope_results.txt" 2>/dev/null || echo 0)"
        echo "DNS Records: $(wc -l < "$output_dir/dns/dns_records.txt" 2>/dev/null || echo 0)"
        echo "Potential Takeovers: $(wc -l < "$output_dir/takeovers/potential_takeovers.txt" 2>/dev/null || echo 0)"
        [ "${GIT_SCAN:-false}" = true ] && echo "Git Repositories: $(wc -l < "$output_dir/git/gitrob_results.txt" 2>/dev/null || echo 0)"
        [ "${SECRETS_SCAN:-false}" = true ] && echo "Secrets Found: $(wc -l < "$output_dir/secrets/trufflehog_results.txt" 2>/dev/null || echo 0)"
        [ "${PORT_SCAN:-false}" = true ] && echo "Port Scan Results: $(wc -l < "$output_dir/ports/portscan_results.txt" 2>/dev/null || echo 0)"
        [ "${WAF_CHECK:-false}" = true ] && echo "WAF Detection Results: $(wc -l < "$output_dir/waf/waf_results.txt" 2>/dev/null || echo 0)"
        [ "${NUCLEI_CHECK:-false}" = true ] && echo "Nuclei Scan Results: $(wc -l < "$output_dir/nuclei/nuclei_results.txt" 2>/dev/null || echo 0)"
        [ "${SSL_CHECK:-false}" = true ] && echo "SSL/TLS Results: $(wc -l < "$output_dir/ssl/sslyze_results.txt" 2>/dev/null || echo 0)"
        [ "${VULN_SCAN:-false}" = true ] && echo "Vulnerabilities Found: $(wc -l < "$output_dir/vuln/all_vulnerabilities.txt" 2>/dev/null || echo 0)"
        [ "${CLOUD_SCAN:-false}" = true ] && echo "Cloud Assets: $(wc -l < "$output_dir/cloud/all_cloud_assets.txt" 2>/dev/null || echo 0)"
        [ "${SERVICE_SCAN:-false}" = true ] && echo "Services Enumerated: $(wc -l < "$output_dir/service/all_services.txt" 2>/dev/null || echo 0)"
        [ "${DNS_SSL_WHOIS_SCAN:-false}" = true ] && echo "DNS/SSL/WHOIS Records: $(wc -l < "$output_dir/dns_ssl_whois/all_dns_ssl_whois.txt" 2>/dev/null || echo 0)"
        
        echo -e "\n[*] Live Subdomains:"
        cat "$output_dir/live/live_subdomains.txt" 2>/dev/null
        
        echo -e "\n[*] Technology Fingerprinting:"
        cat "$output_dir/live/whatweb.txt" 2>/dev/null
        
        echo -e "\n[*] DNS Records:"
        cat "$output_dir/dns/dns_records.txt" 2>/dev/null
        
        echo -e "\n[*] JavaScript Files:"
        cat "$output_dir/crawl/js_files.txt" 2>/dev/null
        
        echo -e "\n[*] URLs with Parameters:"
        cat "$output_dir/crawl/urls_with_params.txt" 2>/dev/null
        
        echo -e "\n[*] Parameter Keys:"
        cat "$output_dir/crawl/param_keys.txt" 2>/dev/null
        
        echo -e "\n[*] Endpoints:"
        cat "$output_dir/crawl/endpoints.txt" 2>/dev/null
        
        [ "${API_SCAN:-false}" = true ] && { echo -e "\n[*] API Endpoints:"; cat "$output_dir/api/apiscope_results.txt" 2>/dev/null; }
        
        echo -e "\n[*] Fuzzing Results:"
        cat "$output_dir/fuzz/fuzz_results.txt" 2>/dev/null
        
        [ "${WAF_CHECK:-false}" = true ] && { echo -e "\n[*] WAF Detection Results:"; cat "$output_dir/waf/waf_results.txt" 2>/dev/null; }

         [ "${NUCLEI_CHECK:-false}" = true ] && { echo -e "\n[*] Nuclei Scan Results:"; cat "$output_dir/nuclei/nuclei_results.txt" 2>/dev/null; }
        
        echo -e "\n[*] Potential Takeovers:"
        cat "$output_dir/takeovers/potential_takeovers.txt" 2>/dev/null
        
        [ "${GIT_SCAN:-false}" = true ] && { echo -e "\n[*] Git Repositories:"; cat "$output_dir/git/gitrob_results.txt" 2>/dev/null; }
        
        [ "${SECRETS_SCAN:-false}" = true ] && { echo -e "\n[*] Secrets Found:"; cat "$output_dir/secrets/trufflehog_results.txt" 2>/dev/null; }
        
        [ "${PORT_SCAN:-false}" = true ] && { echo -e "\n[*] Port Scan Results:"; cat "$output_dir/ports/portscan_results.txt" 2>/dev/null; }
        
        [ -d "$output_dir/patterns" ] && {
            echo -e "\n[*] GF Pattern Matches:"
            for pattern in "$output_dir/patterns/"*.txt; do
                [ -f "$pattern" ] && {
                    echo -e "\n[*] $(basename "$pattern" .txt):"
                    cat "$pattern"
                }
            done
        }
        
        [ "${WAF_CHECK:-false}" = true ] && { echo -e "\n[*] WAF Detection Results:"; cat "$output_dir/waf/waf_results.txt" 2>/dev/null; }
        
        [ "${NUCLEI_CHECK:-false}" = true ] && { echo -e "\n[*] Nuclei Scan Results:"; cat "$output_dir/nuclei/nuclei_results.txt" 2>/dev/null; }
        
        [ "${SSL_CHECK:-false}" = true ] && { echo -e "\n[*] SSL/TLS Results:"; cat "$output_dir/ssl/sslyze_results.txt" 2>/dev/null; }
        
        [ "${VULN_SCAN:-false}" = true ] && { echo -e "\n[*] Vulnerabilities:"; cat "$output_dir/vuln/all_vulnerabilities.txt" 2>/dev/null; }
        
        [ "${CLOUD_SCAN:-false}" = true ] && { echo -e "\n[*] Cloud Assets:"; cat "$output_dir/cloud/all_cloud_assets.txt" 2>/dev/null; }
        
        [ "${SERVICE_SCAN:-false}" = true ] && { echo -e "\n[*] Services:"; cat "$output_dir/service/all_services.txt" 2>/dev/null; }
        
        [ "${DNS_SSL_WHOIS_SCAN:-false}" = true ] && { echo -e "\n[*] DNS/SSL/WHOIS:"; cat "$output_dir/dns_ssl_whois/all_dns_ssl_whois.txt" 2>/dev/null; }
    } > "$final_output"
    
    log "INFO" "Text report generated: $final_output"
    
    # ===== JSON REPORT =====
    {
        echo "{"
        echo "  \"domain\": \"$domain\","
        echo "  \"timestamp\": \"$TIMESTAMP\","
        echo "  \"subdomains_total\": $(wc -l < "$output_dir/subdomains/subdomains.txt" 2>/dev/null || echo 0),"
        echo "  \"live_subdomains\": $(wc -l < "$output_dir/live/live_subdomains.txt" 2>/dev/null || echo 0),"
        echo "  \"js_files\": $(wc -l < "$output_dir/crawl/js_files.txt" 2>/dev/null || echo 0),"
        echo "  \"urls_with_params\": $(wc -l < "$output_dir/crawl/urls_with_params.txt" 2>/dev/null || echo 0),"
        echo "  \"endpoints\": $(wc -l < "$output_dir/crawl/endpoints.txt" 2>/dev/null || echo 0),"
        echo "  \"fuzzing_results\": $(wc -l < "$output_dir/fuzz/fuzz_results.txt" 2>/dev/null || echo 0),"
        echo "  \"dns_records\": $(wc -l < "$output_dir/dns/dns_records.txt" 2>/dev/null || echo 0),"
        echo "  \"potential_takeovers\": $(wc -l < "$output_dir/takeovers/potential_takeovers.txt" 2>/dev/null || echo 0)"
        
        # Add optional phase counts
        [ "${VULN_SCAN:-false}" = true ] && echo "  \"vulnerabilities\": $(wc -l < "$output_dir/vuln/all_vulnerabilities.txt" 2>/dev/null || echo 0),"
        [ "${CLOUD_SCAN:-false}" = true ] && echo "  \"cloud_assets\": $(wc -l < "$output_dir/cloud/all_cloud_assets.txt" 2>/dev/null || echo 0),"
        [ "${SERVICE_SCAN:-false}" = true ] && echo "  \"services\": $(wc -l < "$output_dir/service/all_services.txt" 2>/dev/null || echo 0),"
        [ "${DNS_SSL_WHOIS_SCAN:-false}" = true ] && echo "  \"dns_ssl_whois\": $(wc -l < "$output_dir/dns_ssl_whois/all_dns_ssl_whois.txt" 2>/dev/null || echo 0)"
        echo "}"
    } > "$json_report"
    
    log "INFO" "JSON report generated: $json_report"
    
    # ===== HTML REPORT =====
    local html_report="$report_dir/report.html"
    cat > "$html_report" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dark Recon Framework Report - DOMAIN_PLACEHOLDER</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: 'Monospace', 'Courier New', monospace; margin: 0; padding: 20px; background: #1a1a2e; color: #e8e8e8; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #c56bff; border-bottom: 2px solid #c56bff; padding-bottom: 10px; }
        h2 { color: #7fd7ff; margin-top: 30px; border-left: 4px solid #7fd7ff; padding-left: 10px; }
        h3 { color: #ff9f43; }
        .banner { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #c56bff; }
        .banner h1 { margin: 0; color: #c56bff; text-shadow: 0 0 10px #c56bff; }
        .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .meta-card { background: #16213e; padding: 15px; border-radius: 8px; border: 1px solid #2d2d5e; }
        .meta-card .label { color: #8892b0; font-size: 0.85em; text-transform: uppercase; }
        .meta-card .value { color: #c56bff; font-size: 1.5em; font-weight: bold; }
        .section { background: #16213e; margin: 20px 0; padding: 20px; border-radius: 8px; border: 1px solid #2d2d5e; }
        .section h2 { margin-top: 0; }
        pre { background: #0f0f1e; padding: 15px; border-radius: 5px; overflow-x: auto; border: 1px solid #2d2d5e; max-height: 400px; overflow-y: auto; }
        .url { color: #7fd7ff; word-break: break-all; }
        .vuln-critical { color: #ff4757; font-weight: bold; }
        .vuln-high { color: #ff9f43; font-weight: bold; }
        .vuln-medium { color: #ffdd59; }
        .vuln-low { color: #7fd7ff; }
        .vuln-info { color: #8892b0; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #2d2d5e; }
        th { color: #c56bff; }
        tr:hover { background: #1f2d5a; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: bold; }
        .badge-critical { background: #ff4757; color: white; }
        .badge-high { background: #ff9f43; color: white; }
        .badge-medium { background: #ffdd59; color: #1a1a2e; }
        .badge-low { background: #7fd7ff; color: #1a1a2e; }
        .badge-info { background: #8892b0; color: white; }
        .collapsible { cursor: pointer; }
        .collapsible-content { display: none; }
        .collapsible-content.open { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <div class="banner">
            <h1>Dark Recon Framework Report</h1>
            <p>Domain: DOMAIN_PLACEHOLDER | Timestamp: TIMESTAMP_PLACEHOLDER</p>
        </div>
        
        <div class="meta">
            <div class="meta-card"><div class="label">Total Subdomains</div><div class="value">SUBDOMAINS_TOTAL</div></div>
            <div class="meta-card"><div class="label">Live Hosts</div><div class="value">LIVE_SUBDOMAINS</div></div>
            <div class="meta-card"><div class="label">Endpoints</div><div class="value">ENDPOINTS</div></div>
            <div class="meta-card"><div class="label">Vulnerabilities</div><div class="value">VULNERABILITIES</div></div>
            <div class="meta-card"><div class="label">Cloud Assets</div><div class="value">CLOUD_ASSETS</div></div>
            <div class="meta-card"><div class="label">Secrets Found</div><div class="value">SECRETS</div></div>
        </div>
        
        CONTENT_PLACEHOLDER
    </div>
    <script>
        document.querySelectorAll('.collapsible').forEach(btn => {
            btn.addEventListener('click', () => {
                const content = btn.nextElementSibling;
                content.classList.toggle('open');
                btn.textContent = content.classList.contains('open') ? '▼ ' + btn.textContent.replace('▼ ', '').replace('► ', '') : '► ' + btn.textContent.replace('▼ ', '').replace('► ', '');
            });
        });
    </script>
</body>
</html>
EOF

    # Replace placeholders in HTML
    sed -i "s/DOMAIN_PLACEHOLDER/$domain/g" "$html_report"
    sed -i "s/TIMESTAMP_PLACEHOLDER/$TIMESTAMP/g" "$html_report"
    sed -i "s/SUBDOMAINS_TOTAL/$(wc -l < "$output_dir/subdomains/subdomains.txt" 2>/dev/null || echo 0)/g" "$html_report"
    sed -i "s/LIVE_SUBDOMAINS/$(wc -l < "$output_dir/live/live_subdomains.txt" 2>/dev/null || echo 0)/g" "$html_report"
    sed -i "s/ENDPOINTS/$(wc -l < "$output_dir/crawl/endpoints.txt" 2>/dev/null || echo 0)/g" "$html_report"
    sed -i "s/VULNERABILITIES/$(wc -l < "$output_dir/vuln/all_vulnerabilities.txt" 2>/dev/null || echo 0)/g" "$html_report"
    sed -i "s/CLOUD_ASSETS/$(wc -l < "$output_dir/cloud/all_cloud_assets.txt" 2>/dev/null || echo 0)/g" "$html_report"
    sed -i "s/SECRETS/$(wc -l < "$output_dir/secrets/all_secrets.txt" 2>/dev/null || echo 0)/g" "$html_report"
    
    # Generate content sections
    local content=""
    
    # Live subdomains
    content+="<div class=\"section\"><h2>Live Subdomains</h2><button class=\"collapsible\">► Show $(wc -l < "$output_dir/live/live_subdomains.txt" 2>/dev/null || echo 0) subdomains</button><div class=\"collapsible-content\"><pre>$(cat "$output_dir/live/live_subdomains.txt" 2>/dev/null | sed 's/&/\&/g; s/</\</g; s/>/\>/g')</pre></div></div>"
    
    # Technology fingerprinting
    content+="<div class=\"section\"><h2>Technology Fingerprinting</h2><button class=\"collapsible\">► Show tech stack</button><div class=\"collapsible-content\"><pre>$(cat "$output_dir/live/whatweb.txt" 2>/dev/null | sed 's/&/\&/g; s/</\</g; s/>/\>/g')</pre></div></div>"
    
    # DNS Records
    content+="<div class=\"section\"><h2>DNS Records</h2><button class=\"collapsible\">► Show DNS records</button><div class=\"collapsible-content\"><pre>$(cat "$output_dir/dns/dns_records.txt" 2>/dev/null | sed 's/&/\&/g; s/</\</g; s/>/\>/g')</pre></div></div>"
    
    # Endpoints
    content+="<div class=\"section\"><h2>Discovered Endpoints</h2><button class=\"collapsible\">► Show $(wc -l < "$output_dir/crawl/endpoints.txt" 2>/dev/null || echo 0) endpoints</button><div class=\"collapsible-content\"><pre>$(cat "$output_dir/crawl/endpoints.txt" 2>/dev/null | sed 's/&/\&/g; s/</\</g; s/>/\>/g')</pre></div></div>"
    
    # Vulnerabilities
    if [ "${VULN_SCAN:-false}" = true ] && [ -f "$output_dir/vuln/all_vulnerabilities.txt" ]; then
        content+="<div class=\"section\"><h2>Vulnerabilities</h2><button class=\"collapsible\">► Show $(wc -l < "$output_dir/vuln/all_vulnerabilities.txt") vulnerabilities</button><div class=\"collapsible-content\"><pre>$(cat "$output_dir/vuln/all_vulnerabilities.txt" 2>/dev/null | sed 's/&/\&/g; s/</\</g; s/>/\>/g')</pre></div></div>"
    fi
    
    # Cloud assets
    if [ "${CLOUD_SCAN:-false}" = true ] && [ -f "$output_dir/cloud/all_cloud_assets.txt" ]; then
        content+="<div class=\"section\"><h2>Cloud Assets</h2><button class=\"collapsible\">► Show $(wc -l < "$output_dir/cloud/all_cloud_assets.txt") cloud assets</button><div class=\"collapsible-content\"><pre>$(cat "$output_dir/cloud/all_cloud_assets.txt" 2>/dev/null | sed 's/&/\&/g; s/</\</g; s/>/\>/g')</pre></div></div>"
    fi
    
    # Secrets
    if [ "${SECRETS_SCAN:-false}" = true ] && [ -f "$output_dir/secrets/all_secrets.txt" ]; then
        content+="<div class=\"section\"><h2>Secrets Found</h2><button class=\"collapsible\">► Show $(wc -l < "$output_dir/secrets/all_secrets.txt") secrets</button><div class=\"collapsible-content\"><pre>$(cat "$output_dir/secrets/all_secrets.txt" 2>/dev/null | sed 's/&/\&/g; s/</\</g; s/>/\>/g')</pre></div></div>"
    fi
    
    # Services
    if [ "${SERVICE_SCAN:-false}" = true ] && [ -f "$output_dir/service/all_services.txt" ]; then
        content+="<div class=\"section\"><h2>Service Enumeration</h2><button class=\"collapsible\">► Show $(wc -l < "$output_dir/service/all_services.txt") services</button><div class=\"collapsible-content\"><pre>$(cat "$output_dir/service/all_services.txt" 2>/dev/null | sed 's/&/\&/g; s/</\</g; s/>/\>/g')</pre></div></div>"
    fi
    
    # Patterns
    if [ -d "$output_dir/patterns" ]; then
        content+="<div class=\"section\"><h2>Pattern Matches (gf)</h2>"
        for pattern in "$output_dir/patterns/"*.txt; do
            [ -f "$pattern" ] && {
                local count=$(wc -l < "$pattern")
                local name=$(basename "$pattern" .txt | tr '[:lower:]' '[:upper:]')
                content+="<h3>$name ($count matches)</h3><button class=\"collapsible\">► Show matches</button><div class=\"collapsible-content\"><pre>$(cat "$pattern" 2>/dev/null | sed 's/&/\&/g; s/</\</g; s/>/\>/g')</pre></div>"
            }
        done
        content+="</div>"
    fi
    
    # Takeovers
    content+="<div class=\"section\"><h2>Subdomain Takeovers</h2><button class=\"collapsible\">► Show $(wc -l < "$output_dir/takeovers/potential_takeovers.txt" 2>/dev/null || echo 0) potential takeovers</button><div class=\"collapsible-content\"><pre>$(cat "$output_dir/takeovers/potential_takeovers.txt" 2>/dev/null | sed 's/&/\&/g; s/</\</g; s/>/\>/g')</pre></div></div>"
    
    sed -i "s|CONTENT_PLACEHOLDER|$content|g" "$html_report"
    
    log "INFO" "HTML report generated: $html_report"
    
    # ===== MARKDOWN REPORT =====
    local md_report="$report_dir/report.md"
    cat > "$md_report" << EOF
# Dark Recon Framework Report

**Domain:** $domain  
**Timestamp:** $TIMESTAMP  

## Summary

| Metric | Count |
|--------|-------|
| Total Subdomains | $(wc -l < "$output_dir/subdomains/subdomains.txt" 2>/dev/null || echo 0) |
| Live Subdomains | $(wc -l < "$output_dir/live/live_subdomains.txt" 2>/dev/null || echo 0) |
| Endpoints | $(wc -l < "$output_dir/crawl/endpoints.txt" 2>/dev/null || echo 0) |
| JS Files | $(wc -l < "$output_dir/crawl/js_files.txt" 2>/dev/null || echo 0) |
| URLs with Params | $(wc -l < "$output_dir/crawl/urls_with_params.txt" 2>/dev/null || echo 0) |
| Fuzzing Results | $(wc -l < "$output_dir/fuzz/fuzz_results.txt" 2>/dev/null || echo 0) |
| Potential Takeovers | $(wc -l < "$output_dir/takeovers/potential_takeovers.txt" 2>/dev/null || echo 0) |

$( [ "${VULN_SCAN:-false}" = true ] && echo "| Vulnerabilities | $(wc -l < "$output_dir/vuln/all_vulnerabilities.txt" 2>/dev/null || echo 0) |" )
$( [ "${CLOUD_SCAN:-false}" = true ] && echo "| Cloud Assets | $(wc -l < "$output_dir/cloud/all_cloud_assets.txt" 2>/dev/null || echo 0) |" )
$( [ "${SECRETS_SCAN:-false}" = true ] && echo "| Secrets Found | $(wc -l < "$output_dir/secrets/all_secrets.txt" 2>/dev/null || echo 0) |" )
$( [ "${SERVICE_SCAN:-false}" = true ] && echo "| Services Enumerated | $(wc -l < "$output_dir/service/all_services.txt" 2>/dev/null || echo 0) |" )

## Live Subdomains

\`\`\`
$(cat "$output_dir/live/live_subdomains.txt" 2>/dev/null)
\`\`\`

## Technology Fingerprinting

\`\`\`
$(cat "$output_dir/live/whatweb.txt" 2>/dev/null)
\`\`\`

## DNS Records

\`\`\`
$(cat "$output_dir/dns/dns_records.txt" 2>/dev/null)
\`\`\`

## Endpoints

\`\`\`
$(cat "$output_dir/crawl/endpoints.txt" 2>/dev/null)
\`\`\`

$( [ "${VULN_SCAN:-false}" = true ] && echo "## Vulnerabilities" && echo "" && echo "\`\`\`" && cat "$output_dir/vuln/all_vulnerabilities.txt" 2>/dev/null && echo "\`\`\`" )
$( [ "${CLOUD_SCAN:-false}" = true ] && echo "## Cloud Assets" && echo "" && echo "\`\`\`" && cat "$output_dir/cloud/all_cloud_assets.txt" 2>/dev/null && echo "\`\`\`" )
$( [ "${SECRETS_SCAN:-false}" = true ] && echo "## Secrets Found" && echo "" && echo "\`\`\`" && cat "$output_dir/secrets/all_secrets.txt" 2>/dev/null && echo "\`\`\`" )
$( [ "${SERVICE_SCAN:-false}" = true ] && echo "## Services Enumerated" && echo "" && echo "\`\`\`" && cat "$output_dir/service/all_services.txt" 2>/dev/null && echo "\`\`\`" )

## Pattern Matches (gf)

$( if [ -d "$output_dir/patterns" ]; then
    for pattern in "$output_dir/patterns/"*.txt; do
        [ -f "$pattern" ] && {
            echo "### $(basename "$pattern" .txt | tr '[:lower:]' '[:upper:]') ($(wc -l < "$pattern") matches)"
            echo ""
            echo "\`\`\`"
            cat "$pattern" 2>/dev/null
            echo "\`\`\`"
            echo ""
        }
    done
fi )

## Subdomain Takeovers

\`\`\`
$(cat "$output_dir/takeovers/potential_takeovers.txt" 2>/dev/null)
\`\`\`

---
*Generated by Dark Recon Framework v4 - Made by DarkLegende*
EOF

    log "INFO" "Markdown report generated: $md_report"
    
    # ===== CSV EXPORTS =====
    # Subdomains CSV
    if [ -f "$output_dir/subdomains/subdomains.txt" ]; then
        echo "subdomain" > "$report_dir/subdomains.csv"
        cat "$output_dir/subdomains/subdomains.txt" >> "$report_dir/subdomains.csv"
    fi
    
    # Live subdomains CSV with metadata
    if [ -f "$output_dir/live/live_subdomains.txt" ]; then
        echo "url,status_code,content_length,content_type,location,title,method,server,tech,ip" > "$report_dir/live_subdomains.csv"
        cat "$output_dir/live/live_subdomains.txt" | while IFS= read -r line; do
            echo "\"$line\"" >> "$report_dir/live_subdomains.csv"
        done
    fi
    
    # Endpoints CSV
    if [ -f "$output_dir/crawl/endpoints.txt" ]; then
        echo "endpoint" > "$report_dir/endpoints.csv"
        cat "$output_dir/crawl/endpoints.txt" >> "$report_dir/endpoints.csv"
    fi
    
    # Vulnerabilities CSV
    if [ "${VULN_SCAN:-false}" = true ] && [ -f "$output_dir/vuln/all_vulnerabilities.txt" ]; then
        echo "vulnerability" > "$report_dir/vulnerabilities.csv"
        cat "$output_dir/vuln/all_vulnerabilities.txt" >> "$report_dir/vulnerabilities.csv"
    fi
    
    # Secrets CSV
    if [ "${SECRETS_SCAN:-false}" = true ] && [ -f "$output_dir/secrets/all_secrets.txt" ]; then
        echo "secret" > "$report_dir/secrets.csv"
        cat "$output_dir/secrets/all_secrets.txt" >> "$report_dir/secrets.csv"
    fi
    
    log "INFO" "CSV exports generated in $report_dir"
    
    # ===== FINDING VALIDATION & CORRELATION =====
    log "INFO" "Running finding validation and correlation..."
    source "$SCRIPT_DIR/../scripts/validate_findings.sh"
    validate_and_correlate_findings "$domain"
    
    # ===== WEBHOOK NOTIFICATION =====
    if [ -n "$WEBHOOK_URL" ]; then
        log "INFO" "Sending webhook notification..."
        curl -s -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"domain\":\"$domain\",\"timestamp\":\"$TIMESTAMP\",\"subdomains\":$(wc -l < "$output_dir/subdomains/subdomains.txt" 2>/dev/null || echo 0),\"live\":$(wc -l < "$output_dir/live/live_subdomains.txt" 2>/dev/null || echo 0),\"vulns\":$(wc -l < "$output_dir/vuln/all_vulnerabilities.txt" 2>/dev/null || echo 0),\"secrets\":$(wc -l < "$output_dir/secrets/all_secrets.txt" 2>/dev/null || echo 0),\"report_url\":\"file://$html_report\"}" \
            2>>"$LOGS_DIR/webhook.log" || log "WARN" "Webhook notification failed"
    fi
    
    # ===== DATABASE EXPORT (SQLite) =====
    if command -v sqlite3 >/dev/null 2>&1; then
        local db_file="$report_dir/recon.db"
        sqlite3 "$db_file" << SQL
CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, domain TEXT, timestamp TEXT, subdomains_total INTEGER, live_subdomains INTEGER, endpoints INTEGER, vulns INTEGER, secrets INTEGER);
INSERT INTO runs (domain, timestamp, subdomains_total, live_subdomains, endpoints, vulns, secrets) VALUES ('$domain', '$TIMESTAMP', $(wc -l < "$output_dir/subdomains/subdomains.txt" 2>/dev/null || echo 0), $(wc -l < "$output_dir/live/live_subdomains.txt" 2>/dev/null || echo 0), $(wc -l < "$output_dir/crawl/endpoints.txt" 2>/dev/null || echo 0), $(wc -l < "$output_dir/vuln/all_vulnerabilities.txt" 2>/dev/null || echo 0), $(wc -l < "$output_dir/secrets/all_secrets.txt" 2>/dev/null || echo 0));
CREATE TABLE IF NOT EXISTS subdomains (run_id INTEGER, subdomain TEXT);
$(cat "$output_dir/subdomains/subdomains.txt" 2>/dev/null | sed "s/.*/INSERT INTO subdomains (run_id, subdomain) VALUES ((SELECT MAX(id) FROM runs), '&');/" )
CREATE TABLE IF NOT EXISTS endpoints (run_id INTEGER, endpoint TEXT);
$(cat "$output_dir/crawl/endpoints.txt" 2>/dev/null | sed "s/.*/INSERT INTO endpoints (run_id, endpoint) VALUES ((SELECT MAX(id) FROM runs), '&');/" )
SQL
        log "INFO" "SQLite database generated: $db_file"
    fi
    
    log "INFO" "All reports generated in $report_dir"
    
    # Write findings for report generation
    write_finding "{\"type\":\"report_generated\",\"severity\":\"info\",\"formats\":\"html,markdown,csv,json,sqlite\",\"phase\":\"reporting\"}" \
        "$report_dir/findings.jsonl" 2>/dev/null || true
    
    phase_log "INFO" "Reporting phase complete for $domain" "reporting" "$domain"
}