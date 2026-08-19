#!/usr/bin/env bash
# Phase: Credential Check — Read-only validation of leaked credentials
set -euo pipefail

credential_check() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/credentials"

    log "INFO" "Starting credential validation for $domain"

    local cred_findings="$output_dir/credentials/validated.txt"
    local cred_stale="$output_dir/credentials/stale.txt"
    local count=0

    # Collect leaked credentials from prior phases
    local prior_dirs=("secrets_entropy" "api_key_leakage" "git" "secrets_live_check"
                      "env_files" "hardcoded_secrets")

    for phase_dir_name in "${prior_dirs[@]}"; do
        local scan_dir="$output_dir/$phase_dir_name"
        [[ ! -d "$scan_dir" ]] && continue

        # Look for credential-like files
        find "$scan_dir" -type f \( -name "*.txt" -o -name "*.json" -o -name "*.jsonl" \) 2>/dev/null | while read -r cred_file; do
            while IFS= read -r line; do
                # Skip empty lines and comments
                [[ -z "$line" || "$line" =~ ^# ]] && continue

                # Classify credential type
                local cred_type="generic"
                local cred_value="$line"
                local validated="false"

                if echo "$line" | grep -qiE "^AKIA[0-9A-Z]{16}$"; then
                    cred_type="aws_access_key"
                    # Validate against AWS STS (read-only, no permissions needed)
                    local sts_check
                    sts_check=$(curl -s --connect-timeout 5 --max-time 10 \
                        "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15" \
                        -H "Authorization: AWS4-HMAC-SHA256 Credential=$line" 2>/dev/null || echo "")
                    if echo "$sts_check" | grep -q "InvalidClientTokenId"; then
                        validated="false"
                    elif echo "$sts_check" | grep -q "SecurityToken"; then
                        validated="true"
                    fi

                elif echo "$line" | grep -qiE "^ghp_[a-zA-Z0-9]{36}$"; then
                    cred_type="github_token"
                    local gh_check
                    gh_check=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
                        -H "Authorization: token $line" "https://api.github.com/user" 2>/dev/null || echo "000")
                    [[ "$gh_check" == "200" ]] && validated="true"

                elif echo "$line" | grep -qiE "^xox[bpsar]-[a-zA-Z0-9-]+$"; then
                    cred_type="slack_token"
                    local slack_check
                    slack_check=$(curl -s --connect-timeout 5 --max-time 10 \
                        -X POST "https://slack.com/api/auth.test" \
                        -d "token=$line" 2>/dev/null || echo "")
                    if echo "$slack_check" | grep -q '"ok":true'; then
                        validated="true"
                    fi

                elif echo "$line" | grep -qiE "^[A-Za-z0-9+/]{40,}==$"; then
                    cred_type="api_key_generic"
                    # No generic validation possible
                fi

                if [[ "$validated" == "true" ]]; then
                    echo "[VALIDATED] type=$cred_type source=$phase_dir_name" >> "$cred_findings"
                    ((count++)) || true
                fi

                # Check for stale credentials (file older than 90 days)
                local file_age
                file_age=$(( ($(date +%s) - $(stat -c %Y "$cred_file" 2>/dev/null || echo "$(date +%s)")) / 86400 ))
                if [[ "$file_age" -gt 90 ]]; then
                    echo "[STALE] type=$cred_type age=${file_age}d file=$cred_file" >> "$cred_stale"
                fi

            done < "$cred_file"
        done
    done

    sort -u "$cred_findings" > "$output_dir/credentials/validated_unique.txt" 2>/dev/null || true

    echo "$count" > "$output_dir/credentials/count.txt"
    write_finding "{\"type\":\"credential_check\",\"severity\":\"high\",\"validated\":$count,\"domain\":\"$domain\",\"phase\":\"credential_check\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    log "INFO" "Credential validation complete: $count validated credentials"
    py_log "INFO" "credential_check_phase" "Completed for $domain — $count validated"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    credential_check "${1:-}"
fi
