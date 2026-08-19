#!/usr/bin/env bash
# cloud_acl_phase.sh - Active S3/GCS/Azure Blob ACL and policy enumeration,
# public bucket detection, misconfigured policies.

cloud_acl_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "cloud_acl_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/cloud_acl"

    local results=0
    local acl_file="$output_dir/cloud_acl/cloud_acl_vulns.txt"
    local public_file="$output_dir/cloud_acl/public_buckets.txt"
    local findings_file="$output_dir/cloud_acl/findings.json"

    log "INFO" "Starting cloud ACL phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Extract possible bucket names from domain ---
    local base_name
    base_name=$(echo "$domain" | sed 's/\./-/g; s/^www-//')
    local bucket_names=(
        "$base_name"
        "$base_name-assets"
        "$base_name-static"
        "$base_name-media"
        "$base_name-uploads"
        "$base_name-backups"
        "$base_name-logs"
        "$base_name-config"
        "$base_name-public"
        "$base_name-cdn"
        "$base_name-images"
        "$base_name-docs"
        "$base_name-data"
        "$(echo "$domain" | cut -d. -f1)"
        "$(echo "$domain" | cut -d. -f1)-prod"
        "$(echo "$domain" | cut -d. -f1)-staging"
        "$(echo "$domain" | cut -d. -f1)-dev"
    )

    # --- S3 Bucket Enumeration ---
    log "INFO" "Enumerating S3 buckets"
    for bucket in "${bucket_names[@]}"; do
        # S3 URL-style access
        local s3_urls=(
            "https://${bucket}.s3.amazonaws.com"
            "https://${bucket}.s3.us-east-1.amazonaws.com"
            "https://${bucket}.s3.us-west-2.amazonaws.com"
            "https://${bucket}.s3.eu-west-1.amazonaws.com"
            "https://s3.amazonaws.com/${bucket}"
        )

        for s3_url in "${s3_urls[@]}"; do
            local s3_status s3_body
            s3_body=$(curl -s -m 10 -w "\n%{http_code}" "$s3_url" 2>/dev/null || true)
            s3_status=$(echo "$s3_body" | tail -1)

            if [[ "$s3_status" == "200" ]]; then
                log "INFO" "Public S3 bucket found: $s3_url"
                echo "[S3-PUBLIC] $s3_url - Publicly accessible (HTTP 200)" >> "$public_file"
                ((results++)) || true

                write_asset "{\"type\":\"s3_bucket\",\"url\":\"$s3_url\",\"access\":\"public\",\"phase\":\"cloud_acl\"}" \
                    "$findings_file" 2>/dev/null || true

                # Check bucket listing
                local body_content
                body_content=$(echo "$s3_body" | head -n -1)
                echo "$body_content" | grep -q '<ListBucketResult' 2>/dev/null && {
                    echo "[S3-LISTING] $s3_url - Bucket listing enabled" >> "$acl_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"s3_bucket_listing\",\"url\":\"$s3_url\",\"severity\":\"HIGH\",\"evidence\":\"S3 bucket listing is enabled\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true
            elif [[ "$s3_status" == "403" ]]; then
                echo "[S3-EXISTS] $s3_url - Bucket exists (403 Forbidden)" >> "$acl_file"
            fi

            # Check for public objects via HEAD
            local obj_url="${s3_url}/index.html"
            local obj_status
            obj_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$obj_url" 2>/dev/null || echo "000")

            if [[ "$obj_status" == "200" ]]; then
                echo "[S3-OBJECT-PUBLIC] $obj_url - Public object accessible" >> "$public_file"
                ((results++)) || true

                write_finding "{\"type\":\"s3_public_object\",\"url\":\"$obj_url\",\"severity\":\"MEDIUM\",\"evidence\":\"Public object found in S3 bucket\"}" \
                    "$findings_file" 2>/dev/null || true
            fi
        done

        # S3 API: GetBucketPolicy
        local policy_url="https://${bucket}.s3.amazonaws.com/?policy"
        local policy_status
        policy_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$policy_url" 2>/dev/null || echo "000")

        if [[ "$policy_status" == "200" ]]; then
            echo "[S3-POLICY-EXPOSED] $policy_url - Bucket policy accessible" >> "$acl_file"
            ((results++)) || true

            write_finding "{\"type\":\"s3_policy_exposed\",\"url\":\"$policy_url\",\"severity\":\"MEDIUM\",\"evidence\":\"S3 bucket policy is publicly readable\"}" \
                "$findings_file" 2>/dev/null || true
        fi

        # S3 API: GetBucketACL
        local acl_url="https://${bucket}.s3.amazonaws.com/?acl"
        local acl_status
        acl_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$acl_url" 2>/dev/null || echo "000")

        if [[ "$acl_status" == "200" ]]; then
            echo "[S3-ACL-EXPOSED] $acl_url - Bucket ACL accessible" >> "$acl_file"
            ((results++)) || true

            write_finding "{\"type\":\"s3_acl_exposed\",\"url\":\"$acl_url\",\"severity\":\"HIGH\",\"evidence\":\"S3 bucket ACL is publicly readable\"}" \
                "$findings_file" 2>/dev/null || true
        fi
    done

    # --- GCS Bucket Enumeration ---
    log "INFO" "Enumerating GCS buckets"
    for bucket in "${bucket_names[@]}"; do
        local gcs_url="https://storage.googleapis.com/${bucket}"
        local gcs_status
        gcs_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$gcs_url" 2>/dev/null || echo "000")

        if [[ "$gcs_status" == "200" ]]; then
            log "INFO" "Public GCS bucket found: $gcs_url"
            echo "[GCS-PUBLIC] $gcs_url - Publicly accessible (HTTP 200)" >> "$public_file"
            ((results++)) || true

            write_asset "{\"type\":\"gcs_bucket\",\"url\":\"$gcs_url\",\"access\":\"public\",\"phase\":\"cloud_acl\"}" \
                "$findings_file" 2>/dev/null || true

            # Check bucket listing
            local gcs_body
            gcs_body=$(curl -s -m 10 "$gcs_url" 2>/dev/null || true)
            echo "$gcs_body" | grep -q '<Contents>' 2>/dev/null && {
                echo "[GCS-LISTING] $gcs_url - Bucket listing enabled" >> "$acl_file"
                ((results++)) || true

                write_finding "{\"type\":\"gcs_bucket_listing\",\"url\":\"$gcs_url\",\"severity\":\"HIGH\",\"evidence\":\"GCS bucket listing is enabled\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true
        elif [[ "$gcs_status" == "403" ]]; then
            echo "[GCS-EXISTS] $gcs_url - Bucket exists (403)" >> "$acl_file"
        fi
    done

    # --- Azure Blob Enumeration ---
    log "INFO" "Enumerating Azure Blob containers"
    for bucket in "${bucket_names[@]}"; do
        local azure_urls=(
            "https://${bucket}.blob.core.windows.net/?comp=list"
            "https://${bucket}.blob.core.windows.net/public"
            "https://${bucket}.blob.core.windows.net/?restype=container"
        )

        for azure_url in "${azure_urls[@]}"; do
            local azure_status
            azure_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$azure_url" 2>/dev/null || echo "000")

            if [[ "$azure_status" == "200" ]]; then
                log "INFO" "Public Azure container found: $azure_url"
                echo "[AZURE-PUBLIC] $azure_url - Publicly accessible" >> "$public_file"
                ((results++)) || true

                write_asset "{\"type\":\"azure_blob\",\"url\":\"$azure_url\",\"access\":\"public\",\"phase\":\"cloud_acl\"}" \
                    "$findings_file" 2>/dev/null || true
            fi
        done
    done

    # --- Check for cloud metadata in HTML responses ---
    local main_page
    main_page=$(curl -s -m 15 "https://$domain" 2>/dev/null || true)
    if [[ -n "$main_page" ]]; then
        local cloud_urls
        cloud_urls=$(echo "$main_page" | grep -oE '(https?://[a-z0-9._\-]+\.s3[._][a-z0-9._\-]+amazonaws\.com|https?://storage\.googleapis\.com/[a-z0-9._\-]+|https?://[a-z0-9._\-]+\.blob\.core\.windows\.net)' 2>/dev/null || true)

        if [[ -n "$cloud_urls" ]]; then
            while IFS= read -r curl; do
                echo "[CLOUD-URL-IN-HTML] $domain - Cloud URL in HTML: $curl" >> "$acl_file"
                ((results++)) || true

                # Test each found URL
                local c_status
                c_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$curl" 2>/dev/null || echo "000")
                if [[ "$c_status" == "200" ]]; then
                    echo "[CLOUD-URL-PUBLIC] $curl - Accessible (HTTP 200)" >> "$public_file"
                    ((results++)) || true
                fi
            done <<< "$cloud_urls"
        fi
    fi

    # Write count
    echo "$results" > "$output_dir/cloud_acl/count.txt"

    py_log "INFO" "cloud_acl_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Cloud ACL phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    cloud_acl_phase "$@"
fi
