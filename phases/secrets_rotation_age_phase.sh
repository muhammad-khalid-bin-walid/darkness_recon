#!/bin/bash
# Track 16 - Secrets Deep | Phase 246: Secret Rotation Age Analysis
# Stale credentials, key lifecycle

secrets_rotation_age_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "secrets_rotation_age_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/secrets_rotation_age"
    mkdir -p "$phase_dir"

    log "INFO" "Starting secrets_rotation_age_phase for $domain"

    local rotation_file="$phase_dir/rotation_analysis.txt"
    local stale_file="$phase_dir/stale_credentials.txt"
    local count=0

    # --- Analyze JWT token age ---
    log "INFO" "Analyzing JWT token age and expiry..."
    local prior_secrets=("$output_dir/secrets_entropy" "$output_dir/secrets_env_exposure" "$output_dir/api_key_leakage")
    local jwt_tokens=()

    for sdir in "${prior_secrets[@]}"; do
        [[ -d "$sdir" ]] || continue
        while IFS= read -r -d '' f; do
            grep -oE 'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*' "$f" 2>/dev/null | while IFS= read -r jwt; do
                jwt_tokens+=("$jwt")
            done
        done < <(find "$sdir" -name '*.txt' -print0 2>/dev/null)
    done

    for jwt in "${jwt_tokens[@]}"; do
        [[ -z "$jwt" ]] && continue
        local payload
        payload=$(echo "$jwt" | cut -d'.' -f2)
        local decoded
        decoded=$(echo "$payload" | python3 -c "
import sys, base64, json
p = sys.stdin.read().strip()
p += '=' * (4 - len(p) % 4)
try:
    d = json.loads(base64.urlsafe_b64decode(p))
    print(json.dumps(d))
except:
    print('{}')
" 2>/dev/null) || true

        if [[ -n "$decoded" && "$decoded" != "{}" ]]; then
            local exp
            exp=$(echo "$decoded" | jq -r '.exp // empty' 2>/dev/null) || true
            local iat
            iat=$(echo "$decoded" | jq -r '.iat // empty' 2>/dev/null) || true
            local now
            now=$(date +%s)

            if [[ -n "$exp" ]]; then
                local age_days=0
                if [[ -n "$iat" ]]; then
                    age_days=$(( (now - iat) / 86400 ))
                fi
                local remaining_days=$(( (exp - now) / 86400 ))

                if (( remaining_days < 0 )); then
                    echo "[STALE] JWT expired ${remaining_days#-} days ago (age=${age_days}d)" >> "$stale_file"
                    ((count++)) || true
                elif (( remaining_days < 7 )); then
                    echo "[EXPIRING] JWT expires in ${remaining_days}d (age=${age_days}d)" >> "$rotation_file"
                    ((count++)) || true
                elif (( age_days > 90 )); then
                    echo "[AGING] JWT age=${age_days}d (threshold=90d)" >> "$rotation_file"
                    ((count++)) || true
                fi
            fi
        fi
    done

    # --- Analyze GitHub token permissions and age ---
    log "INFO" "Checking GitHub token rotation indicators..."
    local gh_tokens=()
    for sdir in "${prior_secrets[@]}"; do
        [[ -d "$sdir" ]] || continue
        while IFS= read -r -d '' f; do
            grep -oE 'ghp_[a-zA-Z0-9]{36}' "$f" 2>/dev/null | while IFS= read -r token; do
                gh_tokens+=("$token")
            done
        done < <(find "$sdir" -name '*.txt' -print0 2>/dev/null)
    done

    for token in "${gh_tokens[@]}"; do
        [[ -z "$token" ]] && continue
        local gh_resp
        gh_resp=$(curl -s -m 10 -H "Authorization: token $token" "https://api.github.com/user" 2>/dev/null) || true
        if echo "$gh_resp" | grep -q '"login"'; then
            local login
            login=$(echo "$gh_resp" | jq -r '.login // "unknown"' 2>/dev/null)
            echo "[GH_TOKEN_ACTIVE] login=$login token_prefix=${token:0:8}..." >> "$rotation_file"
            ((count++)) || true

            # Check token scopes
            local scopes
            scopes=$(curl -sI -m 10 -H "Authorization: token $token" "https://api.github.com/user" 2>/dev/null | grep -i 'x-oauth-scopes' || true)
            if echo "$scopes" | grep -qiE 'admin|delete|write'; then
                echo "[GH_TOKEN_PRIVILEGED] login=$login scopes=$scopes" >> "$stale_file"
                ((count++)) || true
            fi
        fi
    done

    # --- Check TLS certificate age (proxy for secret rotation) ---
    log "INFO" "Checking TLS certificate age..."
    local cert_info
    cert_info=$(echo | openssl s_client -servername "$domain" -connect "$domain":443 2>/dev/null | openssl x509 -noout -dates 2>/dev/null) || true
    if [[ -n "$cert_info" ]]; then
        local not_before
        not_before=$(echo "$cert_info" | grep 'notBefore=' | cut -d= -f2)
        local not_after
        not_after=$(echo "$cert_info" | grep 'notAfter=' | cut -d= -f2)
        echo "[CERT_INFO] domain=$domain valid_from=$not_before valid_to=$not_after" >> "$rotation_file"
        ((count++)) || true
    fi

    # --- Write structured findings ---
    if [[ -f "$rotation_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "rotation_analysis" "" "" "" || true
        done < "$rotation_file"
    fi

    if [[ -f "$stale_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "stale_credential" "" "" "" || true
        done < "$stale_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "secrets_rotation_age_phase" "domain=$domain findings=$count"
    log "INFO" "secrets_rotation_age_phase complete: $count findings"
    return 0
}

secrets_rotation_age_phase "$@"
