#!/usr/bin/env bash
# SMTP Relay Misconfiguration & Email Spoofing Vector Detection
# Tests open relay, auth bypass, and email spoofing vectors

smtp_relay_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "smtp_relay_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/smtp_relay"
    mkdir -p "$phase_dir"

    log "INFO" "Starting smtp_relay_phase for $domain"

    local smtp_vulns="$phase_dir/smtp_vulns.txt"
    local relay_config="$phase_dir/relay_config.txt"
    local count=0

    # --- Discover MX records ---
    log "INFO" "Enumerating MX records for $domain..."
    local mx_file="$phase_dir/mx_records.txt"
    dig +short "$domain" MX 2>/dev/null | sort -n > "$mx_file" || true

    if [[ ! -s "$mx_file" ]]; then
        log "WARN" "No MX records found for $domain"
        echo "0" > "$phase_dir/count.txt"
        return 0
    fi

    # --- Discover SMTP ports on each MX ---
    while IFS= read -r mx_line; do
        local mx_host
        mx_host=$(echo "$mx_line" | awk '{print $2}' | sed 's/\.$//')
        [[ -z "$mx_host" ]] && continue

        log "INFO" "Testing MX: $mx_host"

        # Port scan common SMTP ports
        for port in 25 465 587 2525 487; do
            local port_open
            (echo >/dev/tcp/"$mx_host"/"$port") 2>/dev/null && port_open=true || port_open=false

            if [[ "$port_open" == "true" ]]; then
                echo "[CONFIG] $mx_host:$port open" >> "$relay_config"
                ((count++)) || true

                # Capture banner
                local banner
                banner=$(timeout 5 bash -c "echo QUIT | nc -w 3 $mx_host $port" 2>/dev/null) || true
                if [[ -n "$banner" ]]; then
                    echo "[CONFIG] $mx_host:$port banner: $(echo "$banner" | head -1)" >> "$relay_config"
                fi

                # Test EHLO
                local ehlo_resp
                ehlo_resp=$(timeout 5 bash -c "printf 'EHLO test.local\r\nQUIT\r\n' | nc -w 3 $mx_host $port" 2>/dev/null) || true
                if echo "$ehlo_resp" | grep -qiE "250.*AUTH|250.*STARTTLS"; then
                    echo "[CONFIG] $mx_host:$port supports AUTH/STARTTLS" >> "$relay_config"
                fi

                # Test open relay - MAIL FROM/RCPT TO without auth
                local relay_test
                relay_test=$(timeout 8 bash -c "printf 'EHLO test.local\r\nMAIL FROM:<test@external.com>\r\nRCPT TO:<test@$domain>\r\nQUIT\r\n' | nc -w 5 $mx_host $port" 2>/dev/null) || true
                if echo "$relay_test" | grep -qi "250.*OK\|250.*Accepted"; then
                    echo "[VULN] Potential open relay: $mx_host:$port accepts unauthenticated relay" >> "$smtp_vulns"
                    ((count++)) || true
                fi
            fi
        done
    done < "$mx_file"

    # --- Check SPF record ---
    log "INFO" "Checking SPF record..."
    local spf
    spf=$(dig +short "$domain" TXT 2>/dev/null | grep -i "v=spf1" | head -1) || true
    if [[ -z "$spf" ]]; then
        echo "[VULN] No SPF record found - email spoofing possible" >> "$smtp_vulns"
        ((count++)) || true
    elif echo "$spf" | grep -qiE "spf1.*\+all|spf1.*~all"; then
        echo "[VULN] Weak SPF policy: $spf" >> "$smtp_vulns"
        ((count++)) || true
    fi

    # --- Check DMARC record ---
    local dmarc
    dmarc=$(dig +short "_dmarc.$domain" TXT 2>/dev/null | head -1) || true
    if [[ -z "$dmarc" ]]; then
        echo "[VULN] No DMARC record found - email spoofing possible" >> "$smtp_vulns"
        ((count++)) || true
    elif echo "$dmarc" | grep -qiE "p=none"; then
        echo "[VULN] DMARC policy is 'none' (monitor only): $dmarc" >> "$smtp_vulns"
        ((count++)) || true
    fi

    # --- Check DKIM selector discovery ---
    for selector in default google dkim mail k1 selector1 selector2; do
        local dkim
        dkim=$(dig +short "${selector}._domainkey.$domain" TXT 2>/dev/null) || true
        if [[ -n "$dkim" ]]; then
            echo "[CONFIG] DKIM found for selector $selector" >> "$relay_config"
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$smtp_vulns" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "smtp_relay" "" "" ""
        done < "$smtp_vulns"
    fi

    if [[ -f "$relay_config" ]]; then
        while IFS= read -r config_line; do
            write_asset "$phase_dir" "$domain" "smtp_relay" "$config_line" "" ""
        done < "$relay_config"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "smtp_relay_phase" "domain=$domain findings=$count"

    log "INFO" "smtp_relay_phase complete: $count findings"
    return 0
}

smtp_relay_phase "$@"
