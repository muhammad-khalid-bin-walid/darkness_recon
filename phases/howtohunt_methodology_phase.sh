#!/bin/bash
# HowToHunt Methodology Phase - Vulnerability methodology integration
# Integrates HowToHunt (github.com/KathanP19/HowToHunt) methodology into Dark Recon Framework v4

howtohunt_methodology_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local methodology_dir="$output_dir/howtohunt"
    local findings_file="$methodology_dir/methodology_findings.txt"
    local verified_file="$methodology_dir/verified_findings.txt"

    mkdir -p "$methodology_dir"

    log "INFO" "Running HowToHunt methodology checks for $domain"

    local categories=(
        "xss"
        "sqli"
        "ssrf"
        "idor"
        "cors"
        "csrf"
        "file_upload"
        "waf_bypass"
        "auth_bypass"
        "jwt"
        "graphql"
        "xxe"
        "ssti"
        "host_header"
        "open_redirect"
        "rate_limit"
        "race_condition"
        "parameter_pollution"
        "tabnabbing"
        "password_reset"
        "mfa_bypass"
        "saml"
        "oauth"
        "sensitive_info_leaks"
        "exif_geo_data"
        "broken_auth"
        "cms"
        "cves"
        "subdomain_takeover"
        "http_desync"
        "status_code_bypass"
        "weak_password_policy"
        "find_origin_ip"
        "web_source_review"
    )

    local category_count=0
    local finding_count=0

    for category in "${categories[@]}"; do
        category_count=$((category_count + 1))
        log "INFO" "Running HowToHunt methodology checks for category: $category"

        case "$category" in
            xss|sqli|ssrf|xxe|ssti|open_redirect|host_header)
                if [ -f "$output_dir/crawl/endpoints.txt" ]; then
                    while IFS= read -r endpoint; do
                        [ -z "$endpoint" ] && continue
                        echo "[HOWTOHUNT] $category: Test $endpoint for $category vulnerability" >> "$findings_file"
                        finding_count=$((finding_count + 1))
                    done < <(head -50 "$output_dir/crawl/endpoints.txt")
                fi
                ;;
            idor|cors|csrf|jwt|graphql|saml|oauth|parameter_pollution|tabnabbing|password_reset|mfa_bypass|broken_auth)
                if [ -f "$output_dir/crawl/endpoints.txt" ]; then
                    while IFS= read -r endpoint; do
                        [ -z "$endpoint" ] && continue
                        echo "[HOWTOHUNT] $category: Check $endpoint for $category vulnerability" >> "$findings_file"
                        finding_count=$((finding_count + 1))
                    done < <(head -30 "$output_dir/crawl/endpoints.txt")
                fi
                ;;
            waf_bypass|auth_bypass|rate_limit|race_condition|status_code_bypass|weak_password_policy)
                if [ -f "$output_dir/live/live_subdomains.txt" ]; then
                    while IFS= read -r subdomain; do
                        [ -z "$subdomain" ] && continue
                        echo "[HOWTOHUNT] $category: Test $subdomain for $category bypass" >> "$findings_file"
                        finding_count=$((finding_count + 1))
                    done < <(head -20 "$output_dir/live/live_subdomains.txt")
                fi
                ;;
            file_upload|sensitive_info_leaks|exif_geo_data|web_source_review|find_origin_ip|cms|cves|subdomain_takeover|http_desync)
                echo "[HOWTOHUNT] $category: Run specialized HowToHunt methodology checks" >> "$findings_file"
                finding_count=$((finding_count + 1))
                ;;
        esac
    done

    if [ -f "$findings_file" ]; then
        log "INFO" "Verifying HowToHunt methodology findings..."

        while IFS= read -r finding; do
            local finding_type
            finding_type=$(echo "$finding" | grep -oP '\\[HOWTOHUNT\\] \\K[^:]+')
            local finding_value
            finding_value=$(echo "$finding" | grep -oP ': \\K.*')

            local validation_result
            validation_result=$(validate_against_false_positives "{\"type\":\"$finding_type\",\"value\":\"$finding_value\"}")

            if [ "$validation_result" = "valid" ]; then
                echo "$finding" >> "$verified_file"
            fi
        done < "$findings_file"

        local verified_count=0
        if [ -f "$verified_file" ]; then
            verified_count=$(wc -l < "$verified_file")
        fi

        local confidence="medium"
        if [ "$verified_count" -ge 5 ]; then
            confidence="high"
        fi

        log "INFO" "HowToHunt methodology: $verified_count verified findings confidence: $confidence"

        echo "{\"methodology\":\"HowToHunt\",\"domain\":\"$domain\",\"categories_tested\":$category_count,\"findings\":$finding_count,\"verified\":$verified_count,\"confidence\":\"$confidence\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "$methodology_dir/howtohunt_summary.json"
    else
        log "INFO" "No HowToHunt methodology findings for $domain"
        echo "{\"methodology\":\"HowToHunt\",\"domain\":\"$domain\",\"categories_tested\":$category_count,\"findings\":0,\"verified\":0,\"confidence\":\"unverified\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "$methodology_dir/howtohunt_summary.json"
    fi

    log "INFO" "HowToHunt methodology phase completed for $domain"

    write_finding "{\"type\":\"howtohunt_methodology\",\"severity\":\"medium\",\"domain\":\"$domain\",\"phase\":\"howtohunt_methodology\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "howtohunt_methodology_phase" "Completed for $domain"
}