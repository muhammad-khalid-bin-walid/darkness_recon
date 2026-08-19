#!/bin/bash
# Track 16 - Secrets Deep | Phase 242: Live Credential Validation
# API key testing, token verification

secrets_live_check_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "secrets_live_check_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/secrets_live_check"
    mkdir -p "$phase_dir"

    log "INFO" "Starting secrets_live_check_phase for $domain"

    local live_file="$phase_dir/live_secrets.txt"
    local status_file="$phase_dir/credential_status.txt"
    local count=0

    # --- Load candidate secrets from prior phases ---
    local prior_secrets=()
    local secrets_dirs=(
        "$output_dir/secrets_entropy"
        "$output_dir/api_key_leakage"
        "$output_dir/git"
    )

    for sdir in "${secrets_dirs[@]}"; do
        [[ -d "$sdir" ]] || continue
        while IFS= read -r -d '' f; do
            while IFS= read -r candidate; do
                prior_secrets+=("$candidate")
            done < "$f"
        done < <(find "$sdir" -name '*.txt' -print0 2>/dev/null)
    done

    if [[ ${#prior_secrets[@]} -eq 0 ]]; then
        log "WARN" "No candidate secrets found from prior phases"
        echo "0" > "$phase_dir/count.txt"
        return 0
    fi

    # --- Live validation of candidate secrets ---
    log "INFO" "Validating ${#prior_secrets[@]} candidate secrets..."

    for secret in "${prior_secrets[@]}"; do
        [[ -z "$secret" ]] && continue

        local secret_type="unknown"
        local endpoint=""
        local status="untested"

        # AWS Key
        if echo "$secret" | grep -qE '^AKIA[0-9A-Z]{16}$'; then
            secret_type="aws_access_key"
            endpoint="https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
            local http_code
            http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -H "Authorization: AWS4-HMAC-SHA256 Credential=$secret" \
                "$endpoint" 2>/dev/null) || true
            if [[ "$http_code" != "403" && "$http_code" != "000" ]]; then
                status="validated"
            else
                status="expired_or_invalid"
            fi

        # GitHub Token
        elif echo "$secret" | grep -qE '^ghp_[a-zA-Z0-9]{36}$'; then
            secret_type="github_token"
            endpoint="https://api.github.com/user"
            local gh_resp
            gh_resp=$(curl -s -m 10 -H "Authorization: token $secret" "$endpoint" 2>/dev/null) || true
            if echo "$gh_resp" | grep -q '"login"'; then
                status="validated"
            else
                status="expired_or_invalid"
            fi

        # Slack Token
        elif echo "$secret" | grep -qE '^xox[bpsar]-'; then
            secret_type="slack_token"
            endpoint="https://slack.com/api/auth.test"
            local slack_resp
            slack_resp=$(curl -s -m 10 -X POST -H "Authorization: Bearer $secret" "$endpoint" 2>/dev/null) || true
            if echo "$slack_resp" | grep -q '"ok":true'; then
                status="validated"
            else
                status="expired_or_invalid"
            fi

        # Generic Bearer
        elif echo "$secret" | grep -qE '^eyJ'; then
            secret_type="jwt_token"
            local header_b64
            header_b64=$(echo "$secret" | cut -d'.' -f1)
            if echo "$header_b64" | python3 -c "import sys,base64; sys.stdout.buffer.write(base64.urlsafe_b64decode(sys.stdin.read().rstrip('='.encode()) + b'=='))" 2>/dev/null | grep -q '"alg"'; then
                status="valid_format"
            else
                status="invalid_format"
            fi
        fi

        if [[ "$status" == "validated" ]]; then
            echo "[LIVE] secret_type=$secret_type secret=$secret status=$status" >> "$live_file"
            echo "$secret_type|$secret|$status|$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$status_file"
            ((count++)) || true
            log "INFO" "Validated live secret: type=$secret_type"
        else
            echo "$secret_type|$secret|$status|$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$status_file"
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$live_file" ]]; then
        while IFS= read -r line; do
            write_finding "$phase_dir" "$line" "live_credential" "" "" "" || true
        done < "$live_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "secrets_live_check_phase" "domain=$domain findings=$count validated=${count}"
    log "INFO" "secrets_live_check_phase complete: $count live secrets validated"
    return 0
}

secrets_live_check_phase "$@"
