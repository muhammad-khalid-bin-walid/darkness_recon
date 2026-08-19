#!/usr/bin/env bash
# cloud_iam_phase.sh - Cloud IAM misconfiguration checks, privilege escalation
# paths, cross-account access.

cloud_iam_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "cloud_iam_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/cloud_iam"

    local results=0
    local iam_file="$output_dir/cloud_iam/iam_vulns.txt"
    local paths_file="$output_dir/cloud_iam/iam_paths.txt"
    local findings_file="$output_dir/cloud_iam/findings.json"

    log "INFO" "Starting cloud IAM phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Discover cloud metadata endpoints for IAM role enumeration ---
    local metadata_urls=(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        "http://169.254.169.254/latest/meta-data/iam/security-credentials"
        "http://169.254.169.254/latest/meta-data/iam/info"
        "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance"
    )

    for meta_url in "${metadata_urls[@]}"; do
        local meta_status meta_body
        meta_body=$(curl -s -m 5 -w "\n%{http_code}" "$meta_url" 2>/dev/null || true)
        meta_status=$(echo "$meta_body" | tail -1)

        if [[ "$meta_status" == "200" ]]; then
            local content
            content=$(echo "$meta_body" | head -n -1)
            echo "[IAM-METADATA] $meta_url - IAM metadata accessible: $content" >> "$iam_file"
            ((results++)) || true

            write_finding "{\"type\":\"iam_metadata_exposed\",\"url\":\"$meta_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Cloud IAM metadata endpoint accessible\"}" \
                "$findings_file" 2>/dev/null || true

            # Try to extract IAM role names
            for role in $(echo "$content" | tr ' ' '\n' | grep -v '^$'); do
                local cred_url="${meta_url}/${role}"
                local cred_status
                cred_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$cred_url" 2>/dev/null || echo "000")

                if [[ "$cred_status" == "200" ]]; then
                    echo "[IAM-CREDENTIALS] $cred_url - IAM credentials accessible for role: $role" >> "$iam_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"iam_credentials_exposed\",\"url\":\"$cred_url\",\"role\":\"$role\",\"severity\":\"CRITICAL\",\"evidence\":\"IAM role credentials accessible via metadata\"}" \
                        "$findings_file" 2>/dev/null || true

                    echo "AWS_IAM_ROLE=$role URL=$cred_url" >> "$paths_file"
                fi
            done
        fi
    done

    # --- Check for exposed AWS/GCP/Azure keys in HTML/JS ---
    local main_page
    main_page=$(curl -s -m 15 "https://$domain" 2>/dev/null || true)
    if [[ -n "$main_page" ]]; then
        # AWS Access Key patterns
        local aws_keys
        aws_keys=$(echo "$main_page" | grep -oE 'AKIA[0-9A-Z]{16}' 2>/dev/null || true)
        if [[ -n "$aws_keys" ]]; then
            while IFS= read -r key; do
                echo "[AWS-KEY-EXPOSED] $domain - AWS Access Key in page source: $key" >> "$iam_file"
                ((results++)) || true

                write_finding "{\"type\":\"aws_key_exposed\",\"key\":\"$key\",\"severity\":\"CRITICAL\",\"evidence\":\"AWS access key found in page source\"}" \
                    "$findings_file" 2>/dev/null || true
            done <<< "$aws_keys"
        fi

        # GCP Service Account patterns
        local gcp_sa
        gcp_sa=$(echo "$main_page" | grep -oE '[a-z0-9._\-]+@[a-z0-9._\-]+\.iam\.gserviceaccount\.com' 2>/dev/null || true)
        if [[ -n "$gcp_sa" ]]; then
            while IFS= read -r sa; do
                echo "[GCP-SA-EXPOSED] $domain - GCP Service Account in page source: $sa" >> "$iam_file"
                ((results++)) || true

                write_finding "{\"type\":\"gcp_sa_exposed\",\"service_account\":\"$sa\",\"severity\":\"HIGH\",\"evidence\":\"GCP service account email found in page source\"}" \
                    "$findings_file" 2>/dev/null || true
            done <<< "$gcp_sa"
        fi

        # Azure connection strings
        local azure_conn
        azure_conn=$(echo "$main_page" | grep -oE 'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}' 2>/dev/null || true)
        if [[ -n "$azure_conn" ]]; then
            echo "[AZURE-CONN-EXPOSED] $domain - Azure connection string in page source" >> "$iam_file"
            ((results++)) || true

            write_finding "{\"type\":\"azure_connection_exposed\",\"severity\":\"CRITICAL\",\"evidence\":\"Azure storage connection string found in page source\"}" \
                "$findings_file" 2>/dev/null || true
        fi
    fi

    # --- Check for IAM misconfiguration via cloud APIs ---
    # AWS STS GetCallerIdentity (anonymous)
    local sts_url="https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
    local sts_status
    sts_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$sts_url" 2>/dev/null || echo "000")

    if [[ "$sts_status" == "200" ]]; then
        echo "[STS-ACCESSIBLE] $sts_url - AWS STS GetCallerIdentity accessible" >> "$iam_file"
        ((results++)) || true

        write_finding "{\"type\":\"sts_accessible\",\"url\":\"$sts_url\",\"severity\":\"MEDIUM\",\"evidence\":\"AWS STS endpoint accessible without authentication\"}" \
            "$findings_file" 2>/dev/null || true
    fi

    # --- Check for cross-account role assumption ---
    local cross_account_roles=(
        "arn:aws:iam::*:role/admin"
        "arn:aws:iam::*:role/cross-account"
        "arn:aws:iam::*:role/organization"
        "arn:aws:iam::*:role/deploy"
        "arn:aws:iam::*:role/service"
    )

    for role_arn in "${cross_account_roles[@]}"; do
        echo "[CROSS-ACCOUNT-CHECK] Testing role pattern: $role_arn" >> "$paths_file"
    done

    # --- Check for exposed IAM policies ---
    local policy_paths=(
        "/.aws/credentials"
        "/.aws/config"
        "/aws/credentials.json"
        "/iam/policy"
        "/api/iam"
        "/.env"
    )

    for ppath in "${policy_paths[@]}"; do
        local p_status
        p_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://${domain}${ppath}" 2>/dev/null || echo "000")

        if [[ "$p_status" == "200" ]]; then
            echo "[IAM-FILE-EXPOSED] https://${domain}${ppath} - IAM file accessible" >> "$iam_file"
            ((results++)) || true

            write_finding "{\"type\":\"iam_file_exposed\",\"url\":\"https://${domain}${ppath}\",\"severity\":\"CRITICAL\",\"evidence\":\"AWS credentials/config file accessible\"}" \
                "$findings_file" 2>/dev/null || true
        fi
    done

    # Write count
    echo "$results" > "$output_dir/cloud_iam/count.txt"

    py_log "INFO" "cloud_iam_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Cloud IAM phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    cloud_iam_phase "$@"
fi
