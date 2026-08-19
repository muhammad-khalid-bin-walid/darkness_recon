#!/usr/bin/env bash
# Multi-Cloud Asset Correlation & Cross-Cloud Identity Detection
# Correlates assets across AWS, Azure, GCP and detects cross-cloud identity issues

multi_cloud_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "multi_cloud_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/multi_cloud"
    mkdir -p "$phase_dir"

    log "INFO" "Starting multi_cloud_phase for $domain"

    local multi_cloud_assets="$phase_dir/multi_cloud_assets.txt"
    local cross_cloud_vulns="$phase_dir/cross_cloud_vulns.txt"
    local count=0

    # --- Detect cloud provider via DNS ---
    log "INFO" "Detecting cloud providers via DNS records..."

    local a_records
    a_records=$(dig +short "$domain" A 2>/dev/null) || true
    local cname_records
    cname_records=$(dig +short "$domain" CNAME 2>/dev/null) || true
    local txt_records
    txt_records=$(dig +short "$domain" TXT 2>/dev/null) || true
    local ns_records
    ns_records=$(dig +short "$domain" NS 2>/dev/null) || true
    local mx_records
    mx_records=$(dig +short "$domain" MX 2>/dev/null) || true

    # --- AWS detection ---
    local aws_detected=false
    if echo "$cname_records" | grep -qiE "amazonaws\.com|cloudfront\.net|elasticbeanstalk|elb\.amazonaws"; then
        echo "[ASSET] AWS detected via CNAME: $domain -> $cname_records" >> "$multi_cloud_assets"
        aws_detected=true
    fi
    if echo "$a_records" | grep -qiE "54\.|52\.|34\.|35\.|3\.|18\.|13\.|185\."; then
        # Check AWS IP ranges
        local aws_ip_ranges
        aws_ip_ranges=$(curl -s -m 5 "https://ip-ranges.amazonaws.com/ip-ranges.json" 2>/dev/null) || true
        if [[ -n "$aws_ip_ranges" ]]; then
            for ip in $a_records; do
                if echo "$aws_ip_ranges" | grep -q "\"$ip\"" 2>/dev/null; then
                    echo "[ASSET] AWS detected via IP: $ip" >> "$multi_cloud_assets"
                    aws_detected=true
                fi
            done
        fi
    fi
    if echo "$ns_records" | grep -qiE "awsdns"; then
        echo "[ASSET] AWS Route53 detected via NS" >> "$multi_cloud_assets"
        aws_detected=true
    fi
    if echo "$mx_records" | grep -qiE "amazonses"; then
        echo "[ASSET] AWS SES detected via MX" >> "$multi_cloud_assets"
        aws_detected=true
    fi

    # --- Azure detection ---
    local azure_detected=false
    if echo "$cname_records" | grep -qiE "azurewebsites\.net|cloudapp\.azure|blob\.core\.windows\.net|azure-api\.net|azureedge\.net|azurefd\.net|trafficmanager\.net|azurecontainer\.io"; then
        echo "[ASSET] Azure detected via CNAME: $domain -> $cname_records" >> "$multi_cloud_assets"
        azure_detected=true
    fi
    if echo "$txt_records" | grep -qiE "MS=|v=spf1.*include:.*_spf\.google"; then
        # Could be Azure or Google - check MX for confirmation
        if echo "$mx_records" | grep -qiE "protection\.outlook"; then
            echo "[ASSET] Azure detected via MX (Exchange Online)" >> "$multi_cloud_assets"
            azure_detected=true
        fi
    fi
    if echo "$ns_records" | grep -qiE "azure-dns"; then
        echo "[ASSET] Azure DNS detected via NS" >> "$multi_cloud_assets"
        azure_detected=true
    fi

    # --- GCP detection ---
    local gcp_detected=false
    if echo "$cname_records" | grep -qiE "googlehosted\.com|ghs\.google|appspot\.com|run\.app|cloud\.run|storage\.googleapis"; then
        echo "[ASSET] GCP detected via CNAME: $domain -> $cname_records" >> "$multi_cloud_assets"
        gcp_detected=true
    fi
    if echo "$ns_records" | grep -qiE "google\.com|googledomains"; then
        echo "[ASSET] GCP Cloud DNS detected via NS" >> "$multi_cloud_assets"
        gcp_detected=true
    fi
    if echo "$mx_records" | grep -qiE "google\.com|gmail"; then
        echo "[ASSET] Google Workspace detected via MX" >> "$multi_cloud_assets"
        gcp_detected=true
    fi

    # --- Multi-cloud detection ---
    local cloud_count=0
    $aws_detected && ((cloud_count++)) || true
    $azure_detected && ((cloud_count++)) || true
    $gcp_detected && ((cloud_count++)) || true

    if [[ $cloud_count -gt 1 ]]; then
        echo "[VULN] Multi-cloud deployment detected ($cloud_count providers)" >> "$cross_cloud_vulns"
        ((count++)) || true
    fi

    # --- Check for cross-cloud identity risks ---
    log "INFO" "Checking cross-cloud identity risks..."

    # Check for federated identity indicators
    local spf_record
    spf_record=$(echo "$txt_records" | grep -i "v=spf1" | head -1) || true
    if echo "$spf_record" | grep -qiE "include:.*_spf\.google.*include:.*amazonses\|include:.*amazonses.*include:.*_spf\.google"; then
        echo "[VULN] Cross-cloud email federation detected (Google + AWS)" >> "$cross_cloud_vulns"
        ((count++)) || true
    fi

    # Check for SAML/OIDC federation indicators
    local federation_paths=(
        "/.well-known/openid-configuration"
        "/adfs/.well-known/openid-configuration"
        "/oauth2/.well-known/openid-configuration"
        "/.well-known/saml-metadata"
    )

    for path in "${federation_paths[@]}"; do
        local fed_resp
        fed_resp=$(curl -s -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ -n "$fed_resp" ]] && echo "$fed_resp" | grep -qiE "issuer\|metadata\|signing"; then
            echo "[VULN] Identity provider metadata exposed: $path" >> "$cross_cloud_vulns"
            echo "$path:identity-provider" >> "$multi_cloud_assets"
            ((count++)) || true
        fi
    done

    # --- Enumerate cloud-specific subdomains ---
    log "INFO" "Enumerating cloud-specific subdomains..."

    local cloud_subdomains=(
        "s3"
        "s3.amazonaws.com"
        "blob.core.windows.net"
        "storage.googleapis.com"
        "storage.cloud.google.com"
        "console"
        "admin"
        "dashboard"
        "api"
        "staging"
        "dev"
        "test"
        "uat"
    )

    for sub in "${cloud_subdomains[@]}"; do
        local sub_cname
        sub_cname=$(dig +short "$sub.$domain" CNAME 2>/dev/null) || true
        if [[ -n "$sub_cname" ]]; then
            echo "[ASSET] Cloud subdomain: $sub.$domain -> $sub_cname" >> "$multi_cloud_assets"
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$cross_cloud_vulns" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "multi_cloud" "" "" ""
        done < "$cross_cloud_vulns"
    fi

    if [[ -f "$multi_cloud_assets" ]]; then
        while IFS= read -r asset; do
            write_asset "$phase_dir" "$domain" "multi_cloud" "$asset" "" ""
        done < "$multi_cloud_assets"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "multi_cloud_phase" "domain=$domain aws=$aws_detected azure=$azure_detected gcp=$gcp_detected findings=$count"

    log "INFO" "multi_cloud_phase complete: $count findings"
    return 0
}

multi_cloud_phase "$@"
