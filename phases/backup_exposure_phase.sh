#!/usr/bin/env bash
# Backup & Snapshot Exposure Detection
# Checks for exposed database dumps, config backups, and snapshot files

backup_exposure_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "backup_exposure_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/backup_exposure"
    mkdir -p "$phase_dir"

    log "INFO" "Starting backup_exposure_phase for $domain"

    local backup_vulns="$phase_dir/backup_vulns.txt"
    local exposed_backups="$phase_dir/exposed_backups.txt"
    local count=0

    # --- Common backup file paths ---
    log "INFO" "Scanning for exposed backup files..."

    local backup_paths=(
        "/backup"
        "/backups"
        "/bak"
        "/old"
        "/dump"
        "/db"
        "/database"
        "/sql"
        "/mysql"
        "/postgres"
        "/.backup"
        "/backup.sql"
        "/dump.sql"
        "/db.sql"
        "/database.sql"
        "/www.zip"
        "/www.tar.gz"
        "/www.tar.bz2"
        "/web.zip"
        "/web.tar.gz"
        "/site.zip"
        "/site.tar.gz"
        "/public.zip"
        "/source.zip"
        "/code.zip"
        "/app.zip"
        "/archive.zip"
        "/data.zip"
        "/config.bak"
        "/config.php.bak"
        "/config.php~"
        "/config.php.swp"
        "/.config.php.swp"
        "/wp-config.php.bak"
        "/wp-config.php~"
        "/.env.bak"
        "/.env.local"
        "/.env.production"
        "/web.config.bak"
        "/application.yml.bak"
        "/settings.py.bak"
        "/docker-compose.yml.bak"
        "/.git/HEAD"
        "/.gitignore"
        "/.svn/entries"
        "/.svn/wc.db"
        "/.DS_Store"
        "/Thumbs.db"
        "/backup.tar.gz"
        "/backup.zip"
        "/snapshots"
        "/snap"
        "/snapshot"
        "/recovery"
    )

    for path in "${backup_paths[@]}"; do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$http_code" == "200" ]] || [[ "$http_code" == "403" ]]; then
            echo "[VULN] Backup artifact accessible: https://$domain$path (HTTP $http_code)" >> "$backup_vulns"
            echo "$domain$path" >> "$exposed_backups"
            ((count++)) || true

            # If 200, try to grab content type and size
            if [[ "$http_code" == "200" ]]; then
                local headers
                headers=$(curl -sI -m 5 "https://$domain$path" 2>/dev/null) || true
                local content_type
                content_type=$(echo "$headers" | grep -i "^content-type:" | head -1) || true
                local content_length
                content_length=$(echo "$headers" | grep -i "^content-length:" | head -1) || true
                echo "[INFO] $path - $content_type $content_length" >> "$backup_vulns"
            fi
        fi
        # Also try HTTP
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "http://$domain$path" 2>/dev/null) || true
        if [[ "$http_code" == "200" ]]; then
            echo "[VULN] Backup artifact accessible via HTTP: http://$domain$path (HTTP $http_code)" >> "$backup_vulns"
            echo "$domain$path" >> "$exposed_backups"
            ((count++)) || true
        fi
    done

    # --- Check for directory listing on backup directories ---
    log "INFO" "Checking for directory listing on backup directories..."
    local listing_paths=("/backup" "/backups" "/bak" "/old" "/dump" "/db" "/snapshots")
    for path in "${listing_paths[@]}"; do
        local listing_resp
        listing_resp=$(curl -s -m 5 "https://$domain$path/" 2>/dev/null) || true
        if echo "$listing_resp" | grep -qiE "index of|parent directory|<pre>|directory listing"; then
            echo "[VULN] Directory listing enabled: https://$domain$path/" >> "$backup_vulns"
            echo "$domain$path/" >> "$exposed_backups"
            ((count++)) || true
        fi
    done

    # --- Check for exposed version control ---
    log "INFO" "Checking for exposed version control systems..."
    local vcs_paths=(
        "/.git/HEAD"
        "/.git/config"
        "/.gitignore"
        "/.svn/entries"
        "/.svn/wc.db"
        "/.hg/dirstate"
        "/.bzr/README"
    )

    for path in "${vcs_paths[@]}"; do
        local vcs_resp
        vcs_resp=$(curl -s -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ -n "$vcs_resp" ]] && echo "$vcs_resp" | grep -qiE "ref:|HEAD|svn|dirstate|commit"; then
            echo "[VULN] Version control exposed: https://$domain$path" >> "$backup_vulns"
            echo "$domain$path" >> "$exposed_backups"
            ((count++)) || true
        fi
    done

    # --- Check for exposed database admin tools ---
    local db_paths=(
        "/phpmyadmin"
        "/adminer.php"
        "/adminer"
        "/dbadmin"
        "/mysql"
        "/pgadmin"
        "/rockmongo"
    )

    for path in "${db_paths[@]}"; do
        local db_code
        db_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$db_code" == "200" ]] || [[ "$db_code" == "302" ]]; then
            echo "[VULN] Database admin tool accessible: https://$domain$path (HTTP $db_code)" >> "$backup_vulns"
            echo "$domain$path" >> "$exposed_backups"
            ((count++)) || true
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$backup_vulns" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "backup_exposure" "" "" ""
        done < "$backup_vulns"
    fi

    if [[ -f "$exposed_backups" ]]; then
        while IFS= read -r asset; do
            write_asset "$phase_dir" "$domain" "backup_exposure" "$asset" "" ""
        done < "$exposed_backups"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "backup_exposure_phase" "domain=$domain findings=$count"

    log "INFO" "backup_exposure_phase complete: $count findings"
    return 0
}

backup_exposure_phase "$@"
