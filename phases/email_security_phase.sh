#!/bin/bash
# Email security phase - SPF/DKIM/DMARC analysis, MX security, reputation checks

email_security_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local email_dir="$output_dir/email_security"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$email_dir"

    log "INFO" "Starting email security analysis for $domain"
    py_log "INFO" "email_security_phase" --phase "email_security" --target "$domain"

    # ===== SPF RECORD ANALYSIS =====
    log "INFO" "Checking SPF records..."
    if command -v dig >/dev/null 2>&1; then
        dig +short TXT "$domain" 2>/dev/null | grep -i 'spf' > "$email_dir/spf_raw.txt" || true
        dig +short TXT "$domain" 2>/dev/null | grep -i 'v=spf1' > "$email_dir/spf_record.txt" || true

        if [ -s "$email_dir/spf_record.txt" ]; then
            local spf_record
            spf_record=$(head -1 "$email_dir/spf_record.txt")

            # Analyze SPF policy
            local spf_analysis="SPF Analysis for $domain:\n"
            spf_analysis+="Record: $spf_record\n"

            if echo "$spf_record" | grep -q 'all'; then
                local spf_all
                spf_all=$(echo "$spf_record" | grep -oP '[-+~?]?all$')
                case "$spf_all" in
                    *"-all") spf_analysis+="Policy: HARD FAIL (reject) - Strong\n" ;;
                    *"+all") spf_analysis+="Policy: PASS (accept all) - CRITICAL WEAKNESS\n" ;;
                    *"~all") spf_analysis+="Policy: SOFT FAIL (mark) - Moderate\n" ;;
                    *"?all") spf_analysis+="Policy: NEUTRAL - Weak\n" ;;
                    *) spf_analysis+="Policy: Unknown\n" ;;
                esac
            fi

            # Check include count
            local include_count
            include_count=$(echo "$spf_record" | grep -oP 'include:\K[^ ]+' | wc -l)
            spf_analysis+="Includes: $include_count DNS lookups\n"

            if [ "$include_count" -gt 10 ]; then
                spf_analysis+="WARNING: Exceeds 10-lookup limit - may cause softfail\n"
            fi

            echo -e "$spf_analysis" > "$email_dir/spf_analysis.txt"
            write_finding "{\"type\":\"spf_record\",\"target\":\"$domain\",\"record\":\"$spf_record\",\"includes\":$include_count,\"status\":\"found\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$email_dir/spf_finding.json" || true
        else
            echo "NO_SPF_RECORD" > "$email_dir/spf_record.txt"
            write_finding "{\"type\":\"spf_record\",\"target\":\"$domain\",\"status\":\"missing\",\"severity\":\"critical\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$email_dir/spf_finding.json" || true
        fi
    fi

    # ===== DKIM RECORD CHECK =====
    log "INFO" "Checking DKIM records..."
    local dkim_selectors=("default" "google" "selector1" "selector2" "k1" "mandrill" "s1" "s2" "protonmail" "dkim" "mail")
    local dkim_found=false

    if command -v dig >/dev/null 2>&1; then
        > "$email_dir/dkim_selectors.txt"
        for selector in "${dkim_selectors[@]}"; do
            local dkim_result
            dkim_result=$(dig +short TXT "${selector}._domainkey.${domain}" 2>/dev/null || echo "")
            if [ -n "$dkim_result" ]; then
                echo "${selector}: ${dkim_result}" >> "$email_dir/dkim_selectors.txt"
                dkim_found=true
            fi
        done

        if [ "$dkim_found" = true ]; then
            write_finding "{\"type\":\"dkim_record\",\"target\":\"$domain\",\"status\":\"found\",\"selectors_file\":\"dkim_selectors.txt\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$email_dir/dkim_finding.json" || true
        else
            write_finding "{\"type\":\"dkim_record\",\"target\":\"$domain\",\"status\":\"not_found\",\"severity\":\"high\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$email_dir/dkim_finding.json" || true
        fi
    fi

    # ===== DMARC RECORD ANALYSIS =====
    log "INFO" "Checking DMARC records..."
    if command -v dig >/dev/null 2>&1; then
        dig +short TXT "_dmarc.${domain}" 2>/dev/null > "$email_dir/dmarc_raw.txt" || true
        grep -i 'v=DMARC1' "$email_dir/dmarc_raw.txt" > "$email_dir/dmarc_status.txt" 2>/dev/null || true

        if [ -s "$email_dir/dmarc_status.txt" ]; then
            local dmarc_record
            dmarc_record=$(head -1 "$email_dir/dmarc_status.txt")

            # Analyze DMARC policy
            local dmarc_analysis="DMARC Analysis for $domain:\n"
            dmarc_analysis+="Record: $dmarc_record\n"

            if echo "$dmarc_record" | grep -qP 'p=(reject|quarantine)'; then
                dmarc_analysis+="Policy: ENFORCED\n"
            elif echo "$dmarc_record" | grep -q 'p=none'; then
                dmarc_analysis+="Policy: MONITOR ONLY (no enforcement)\n"
            fi

            if echo "$dmarc_record" | grep -q 'rua='; then
                dmarc_analysis+="Aggregate reporting: ENABLED\n"
            else
                dmarc_analysis+="Aggregate reporting: DISABLED\n"
            fi

            if echo "$dmarc_record" | grep -q 'ruf='; then
                dmarc_analysis+="Forensic reporting: ENABLED\n"
            else
                dmarc_analysis+="Forensic reporting: DISABLED\n"
            fi

            echo -e "$dmarc_analysis" > "$email_dir/dmarc_analysis.txt"
            write_finding "{\"type\":\"dmarc_record\",\"target\":\"$domain\",\"record\":\"$(echo "$dmarc_record" | tr '"' "'")\",\"status\":\"found\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$email_dir/dmarc_finding.json" || true
        else
            echo "NO_DMARC_RECORD" > "$email_dir/dmarc_status.txt"
            write_finding "{\"type\":\"dmarc_record\",\"target\":\"$domain\",\"status\":\"missing\",\"severity\":\"critical\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$email_dir/dmarc_finding.json" || true
        fi
    fi

    # ===== MX RECORD SECURITY =====
    log "INFO" "Analyzing MX record security..."
    if command -v dig >/dev/null 2>&1; then
        dig +short MX "$domain" 2>/dev/null | sort -n > "$email_dir/mx_records.txt" || true

        if [ -s "$email_dir/mx_records.txt" ]; then
            local mx_analysis="MX Records for $domain:\n"
            while IFS= read -r mx; do
                [ -z "$mx" ] && continue
                local priority host
                priority=$(echo "$mx" | awk '{print $1}')
                host=$(echo "$mx" | awk '{print $2}' | sed 's/\.$//')
                mx_analysis+="Priority $priority: $host\n"

                # Check if MX host resolves
                local mx_ip
                mx_ip=$(dig +short A "$host" 2>/dev/null | head -1)
                if [ -n "$mx_ip" ]; then
                    mx_analysis+="  IP: $mx_ip\n"
                else
                    mx_analysis+="  WARNING: Does not resolve\n"
                fi
            done < "$email_dir/mx_records.txt"

            echo -e "$mx_analysis" > "$email_dir/mx_analysis.txt"
            write_finding "{\"type\":\"mx_records\",\"target\":\"$domain\",\"count\":$(wc -l < "$email_dir/mx_records.txt"),\"status\":\"found\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$email_dir/mx_finding.json" || true
        fi
    fi

    # ===== EMAIL HEADER ANALYSIS (if sample provided) =====
    log "INFO" "Checking for email header patterns..."
    local header_patterns="^(From|To|Subject|Message-ID|X-Mailer|X-Originating-IP|Received):"
    if [ -d "$output_dir" ]; then
        find "$output_dir" -name "*.eml" -o -name "*header*" 2>/dev/null | head -5 | while read -r hf; do
            [ -z "$hf" ] && continue
            grep -iE "$header_patterns" "$hf" 2>/dev/null >> "$email_dir/email_headers.txt" || true
        done
    fi

    # ===== EMAIL REPUTATION CHECKS =====
    log "INFO" "Running email reputation checks..."
    if tool_available "curl"; then
        # Check blacklists
        local mx_ip
        mx_ip=$(head -1 "$email_dir/mx_records.txt" 2>/dev/null | awk '{print $2}' | sed 's/\.$//' | xargs dig +short A 2>/dev/null | head -1)
        if [ -n "$mx_ip" ]; then
            # DNSBL checks
            local dnsbls=("zen.spamhaus.org" "bl.spamcop.net" "b.barracudacentral.org" "dnsbl-1.uceprotect.net")
            > "$email_dir/dnsbl_results.txt"
            for dnsbl in "${dnsbls[@]}"; do
                local reversed
                reversed=$(echo "$mx_ip" | awk -F. '{print $4"."$3"."$2"."$1}')
                local dnsbl_result
                dnsbl_result=$(dig +short A "${reversed}.${dnsbl}" 2>/dev/null || echo "")
                if [ -n "$dnsbl_result" ]; then
                    echo "LISTED: $mx_ip on $dnsbl" >> "$email_dir/dnsbl_results.txt"
                fi
            done
        fi
    fi

    # ===== COMPILED REPORT =====
    log "INFO" "Compiling email security report..."
    {
        echo "=== EMAIL SECURITY REPORT FOR $domain ==="
        echo ""
        echo "--- SPF ---"
        cat "$email_dir/spf_record.txt" 2>/dev/null || echo "Not found"
        echo ""
        echo "--- DMARC ---"
        cat "$email_dir/dmarc_status.txt" 2>/dev/null || echo "Not found"
        echo ""
        echo "--- DKIM ---"
        cat "$email_dir/dkim_selectors.txt" 2>/dev/null || echo "Not found"
        echo ""
        echo "--- MX ---"
        cat "$email_dir/mx_records.txt" 2>/dev/null || echo "Not found"
        echo ""
        echo "--- DNSBL ---"
        cat "$email_dir/dnsbl_results.txt" 2>/dev/null || echo "Not listed"
    } > "$email_dir/email_security.txt" 2>/dev/null || true

    local total_count
    total_count=$(find "$email_dir" -type f 2>/dev/null | wc -l)
    log "INFO" "Email security analysis complete: $total_count result files"
    echo "$total_count" > "$email_dir/count.txt"
}
