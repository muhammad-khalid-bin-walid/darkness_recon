#!/usr/bin/env bash
# Phase 268: Data Retention Policy Compliance, Storage Audit, Deletion Verification
# Track 18 - Compliance

compliance_data_retention() {
    local domain="${1:?Usage: compliance_data_retention <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/compliance_data_retention"
    mkdir -p "$phase_dir"

    log "INFO" "[DATA_RET] Starting data retention compliance check for $domain"

    local retention_compliance="$phase_dir/retention_compliance.txt"
    local storage_audit="$phase_dir/storage_audit.txt"

    : > "$retention_compliance"
    : > "$storage_audit"

    local count=0

    if tool_available "curl"; then
        log "INFO" "[DATA_RET] Checking privacy policy for retention statements"

        local privacy_body
        privacy_body=$(curl -sL --max-time 15 "https://$domain/privacy" 2>/dev/null || true)
        local privacy_terms_body
        privacy_terms_body=$(curl -sL --max-time 15 "https://$domain/terms" 2>/dev/null || true)
        local combined="$privacy_body $privacy_terms_body"

        if echo "$combined" | grep -qi "retain\|retention\|delet\|erasure"; then
            echo "RETENTION_POLICY: Retention language found in privacy/terms" >> "$retention_compliance"
            echo "Evidence: Privacy policy mentions data retention" >> "$storage_audit"
            write_finding "$phase_dir" "RET-POLICY" "Retention policy language present" "high" "passed"
            count=$((count + 1))
        else
            echo "RETENTION_POLICY: No retention language found" >> "$retention_compliance"
            write_finding "$phase_dir" "RET-POLICY" "No retention policy language" "high" "failed"
            count=$((count + 1))
        fi

        if echo "$combined" | grep -qi "right to deletion\|right to erasure\|data deletion"; then
            echo "RETENTION_RIGHTS: Deletion rights mentioned" >> "$retention_compliance"
            echo "Evidence: Right to deletion/erasure present" >> "$storage_audit"
            count=$((count + 1))
        else
            echo "RETENTION_RIGHTS: No deletion rights mentioned" >> "$retention_compliance"
            count=$((count + 1))
        fi

        if echo "$combined" | grep -qi "30 days\|60 days\|90 days\|1 year\|retention period"; then
            echo "RETENTION_PERIOD: Specific retention period mentioned" >> "$retention_compliance"
            count=$((count + 1))
        else
            echo "RETENTION_PERIOD: No specific retention period" >> "$retention_compliance"
            count=$((count + 1))
        fi
    fi

    if tool_available "nmap"; then
        log "INFO" "[DATA_RET] Checking storage-related services"
        nmap -p 27017,5432,3306,6379,9200 "$domain" 2>/dev/null > "$phase_dir/storage_services.txt" || true
        local storage_open
        storage_open=$(grep -c "open" "$phase_dir/storage_services.txt" 2>/dev/null || echo "0")
        echo "STORAGE_SERVICES: $storage_open database ports exposed" >> "$storage_audit"
        write_asset "$phase_dir" "storage_ports" "$storage_open" "count"
        count=$((count + 1))
    fi

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "data_retention_complete" "Data retention compliance complete: $count items checked"
    log "INFO" "[DATA_RET] Completed: $count items checked"

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_endpoint "$phase_dir" "https://$domain" "GET" "Data retention compliance target"

    return 0
}
