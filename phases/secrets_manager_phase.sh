#!/usr/bin/env bash
# Secrets Manager Misconfiguration Detection
# Checks for exposed vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager

secrets_manager_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "secrets_manager_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/secrets_manager"
    mkdir -p "$phase_dir"

    log "INFO" "Starting secrets_manager_phase for $domain"

    local secrets_vulns="$phase_dir/secrets_vulns.txt"
    local secrets_config="$phase_dir/secrets_config.txt"
    local count=0

    # --- Check for exposed Vault (HashiCorp) endpoints ---
    log "INFO" "Checking HashiCorp Vault endpoints..."
    local vault_paths=(
        "/v1/sys/health"
        "/v1/sys/seal-status"
        "/ui/"
        "/v1/sys/auth"
        "/v1/secret/data"
    )

    for path in "${vault_paths[@]}"; do
        local vault_resp
        vault_resp=$(curl -s -m 5 "https://$domain$path" 2>/dev/null) || true
        local vault_code
        vault_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$vault_code" == "200" ]] || [[ "$vault_code" == "400" ]]; then
            if echo "$vault_resp" | grep -qiE "initialized\|sealed\|vault\|keys"; then
                echo "[VULN] HashiCorp Vault endpoint accessible: $path (HTTP $vault_code)" >> "$secrets_vulns"
                echo "$domain$path:vault" >> "$secrets_config"
                ((count++)) || true
            fi
        fi
    done

    # --- Check for AWS Secrets Manager metadata endpoints ---
    log "INFO" "Checking AWS Secrets Manager exposure..."
    local aws_endpoints=(
        "/latest/meta-data/iam/security-credentials/"
        "/latest/meta-data/secret/"
        "/latest/dynamic/instance-identity/document"
    )

    for path in "${aws_endpoints[@]}"; do
        local aws_resp
        aws_resp=$(curl -s -m 3 "http://169.254.169.254$path" 2>/dev/null) || true
        if [[ -n "$aws_resp" ]] && ! echo "$aws_resp" | grep -qi "not found\|error\|404"; then
            echo "[VULN] AWS metadata endpoint accessible (SSRF vector)" >> "$secrets_vulns"
            echo "$path:aws-metadata" >> "$secrets_config"
            ((count++)) || true
        fi
    done

    # --- Check for exposed API keys in common paths ---
    log "INFO" "Checking for leaked secrets in common paths..."
    local secret_paths=(
        "/.env"
        "/.env.local"
        "/.env.production"
        "/.env.staging"
        "/.env.development"
        "/.env.backup"
        "/config/secrets.json"
        "/config/credentials.json"
        "/config/secrets.yml"
        "/config/credentials.yml"
        "/config/database.yml"
        "/config/secrets.yaml"
        "/secrets.json"
        "/secrets.yml"
        "/vault.json"
        "/credentials.json"
        "/service-account.json"
        "/gcloud-service-key.json"
        "/.aws/credentials"
        "/.azure/credentials"
        "/kubeconfig"
        "/.kube/config"
        "/docker-compose.override.yml"
        "/.docker/config.json"
        "/.npmrc"
        "/.pypirc"
    )

    for path in "${secret_paths[@]}"; do
        local secret_code
        secret_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$secret_code" == "200" ]]; then
            echo "[VULN] Potential secrets file accessible: $path (HTTP $secret_code)" >> "$secrets_vulns"
            echo "$domain$path:secrets-file" >> "$secrets_config"
            ((count++)) || true
        fi
    done

    # --- Check for Azure Key Vault exposure ---
    log "INFO" "Checking Azure Key Vault exposure..."
    local azure_paths=(
        "/keys"
        "/secrets"
        "/certificates"
        "/vaultname"
    )

    for path in "${azure_paths[@]}"; do
        local azure_resp
        azure_resp=$(curl -s -m 5 "https://$domain$path" 2>/dev/null) || true
        if echo "$azure_resp" | grep -qiE "key\|secret\|certificate\|error.*unauthorized"; then
            echo "[VULN] Azure Key Vault path accessible: $path" >> "$secrets_vulns"
            echo "$domain$path:azure-keyvault" >> "$secrets_config"
            ((count++)) || true
        fi
    done

    # --- Check for GCP Secret Manager exposure ---
    local gcp_paths=(
        "/v1/projects/*/secrets"
        "/secretmanager"
    )

    for path in "${gcp_paths[@]}"; do
        local gcp_code
        gcp_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$gcp_code" != "404" ]] && [[ "$gcp_code" != "000" ]]; then
            echo "[VULN] GCP Secret Manager path accessible: $path (HTTP $gcp_code)" >> "$secrets_vulns"
            echo "$domain$path:gcp-secretmanager" >> "$secrets_config"
            ((count++)) || true
        fi
    done

    # --- Check for key rotation issues via certificate inspection ---
    log "INFO" "Checking certificate expiry (rotation indicator)..."
    local cert_expiry
    cert_expiry=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null) || true
    if [[ -n "$cert_expiry" ]]; then
        echo "[CONFIG] Certificate expiry: $cert_expiry" >> "$secrets_config"
    fi

    # --- Check for exposed SSH keys ---
    local ssh_paths=(
        "/.ssh/id_rsa"
        "/.ssh/id_ed25519"
        "/.ssh/authorized_keys"
        "/.ssh/known_hosts"
        "/id_rsa.pub"
        "/id_ed25519.pub"
    )

    for path in "${ssh_paths[@]}"; do
        local ssh_code
        ssh_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$ssh_code" == "200" ]]; then
            echo "[VULN] SSH key potentially exposed: $path" >> "$secrets_vulns"
            echo "$domain$path:ssh-key" >> "$secrets_config"
            ((count++)) || true
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$secrets_vulns" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "secrets_manager" "" "" ""
        done < "$secrets_vulns"
    fi

    if [[ -f "$secrets_config" ]]; then
        while IFS= read -r config_line; do
            write_asset "$phase_dir" "$domain" "secrets_manager" "$config_line" "" ""
        done < "$secrets_config"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "secrets_manager_phase" "domain=$domain findings=$count"

    log "INFO" "secrets_manager_phase complete: $count findings"
    return 0
}

secrets_manager_phase "$@"
