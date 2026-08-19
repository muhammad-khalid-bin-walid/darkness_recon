#!/bin/bash
# Track 16 - Secrets Deep | Phase 244: .env File Exposure & Configuration Leaks
# Configuration file leaks, backup file discovery

secrets_env_exposure_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "secrets_env_exposure_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/secrets_env_exposure"
    mkdir -p "$phase_dir"

    log "INFO" "Starting secrets_env_exposure_phase for $domain"

    local env_file="$phase_dir/env_exposures.txt"
    local config_file="$phase_dir/config_leaks.txt"
    local count=0

    # --- Exposed .env file paths ---
    log "INFO" "Scanning for exposed .env and configuration files..."
    local env_paths=(
        "/.env"
        "/.env.local"
        "/.env.development"
        "/.env.staging"
        "/.env.production"
        "/.env.backup"
        "/.env.old"
        "/.env.save"
        "/.env.bak"
        "/.env.swp"
        "/.env.sample"
        "/.env.template"
        "/env.js"
        "/config.js"
        "/config.json"
        "/config.yml"
        "/config.yaml"
        "/config.xml"
        "/settings.js"
        "/settings.json"
        "/settings.yml"
        "/application.yml"
        "/application.properties"
        "/database.yml"
        "/database.php"
        "/wp-config.php"
        "/wp-config.php.bak"
        "/wp-config.php.old"
        "/wp-config.php~"
        "/web.config"
        "/.config"
        "/.config.json"
        "/.config.yml"
        "/credentials"
        "/credentials.json"
        "/secrets.json"
        "/secrets.yml"
        "/service-account.json"
        "/keyfile.json"
        "/firebase.json"
        "/firebaseServiceAccount.json"
        "/.aws/credentials"
        "/.ssh/id_rsa"
        "/.ssh/id_ed25519"
        "/.netrc"
        "/.htpasswd"
    )

    for path in "${env_paths[@]}"; do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$http_code" == "200" ]]; then
            local content
            content=$(curl -s -m 5 "https://$domain$path" 2>/dev/null) || true
            if echo "$content" | grep -qiE '(API_KEY|SECRET|PASSWORD|TOKEN|AWS_|PRIVATE|CREDENTIAL|DATABASE_URL)'; then
                echo "[ENV_EXPOSED] https://$domain$path (contains secrets)" >> "$env_file"
                ((count++)) || true

                # Extract key names
                echo "$content" | grep -oE '[A-Z_]+=(.{1,50})' 2>/dev/null | while IFS= read -r kv; do
                    echo "[CONFIG_LEAK] $path: $kv" >> "$config_file"
                done
            elif [[ "$http_code" == "200" ]]; then
                echo "[ENV_ACCESSIBLE] https://$domain$path (status=200)" >> "$env_file"
                ((count++)) || true
            fi
        fi
    done

    # --- Check for backup config files ---
    log "INFO" "Checking for backup configuration files..."
    local backup_extensions=(".bak" ".old" ".save" ".swp" ".orig" "~" ".copy" ".tmp")
    local config_base_paths=(
        "/wp-config"
        "/config"
        "/settings"
        "/application"
        "/database"
        "/.env"
    )

    for base in "${config_base_paths[@]}"; do
        for ext in "${backup_extensions[@]}"; do
            local backup_path="${base}${ext}"
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$backup_path" 2>/dev/null) || true
            if [[ "$code" == "200" ]]; then
                echo "[BACKUP_CONFIG] https://$domain$backup_path" >> "$config_file"
                ((count++)) || true
            fi
        done
    done

    # --- Directory listing on common paths ---
    log "INFO" "Checking for directory listings on sensitive paths..."
    local listing_dirs=("/" "/assets/" "/static/" "/config/" "/backup/" "/data/")
    for dir in "${listing_dirs[@]}"; do
        local resp
        resp=$(curl -s -m 5 "https://$domain$dir" 2>/dev/null) || true
        if echo "$resp" | grep -qiE 'index of|parent directory|<pre>|listing'; then
            if echo "$resp" | grep -qiE '\.env|config|secret|credential|\.key|\.pem'; then
                echo "[DIR_LISTING_SENSITIVE] https://$domain$dir (lists sensitive files)" >> "$config_file"
                ((count++)) || true
            fi
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$env_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "env_exposure" "" "" "" || true
        done < "$env_file"
    fi

    if [[ -f "$config_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "config_leak" "" "" "" || true
        done < "$config_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "secrets_env_exposure_phase" "domain=$domain findings=$count"
    log "INFO" "secrets_env_exposure_phase complete: $count findings"
    return 0
}

secrets_env_exposure_phase "$@"
